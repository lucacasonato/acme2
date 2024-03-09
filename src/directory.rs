use crate::error::*;
use crate::jws::jws;
use hyper::body::Bytes;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::debug;
use tracing::field;
use tracing::instrument;
use tracing::Level;
use tracing::Span;

/// An builder that is used create a [`Directory`].
pub struct DirectoryBuilder {
    url: String,
    http_client: Option<reqwest::Client>,
}

impl DirectoryBuilder {
    /// Creates a new builder with the specified directory root URL.
    ///
    /// Let's Encrypt: `https://acme-v02.api.letsencrypt.org/directory`
    ///
    /// Let's Encrypt Staging: `https://acme-staging-v02.api.letsencrypt.org/directory`
    pub fn new(url: String) -> Self {
        DirectoryBuilder {
            url,
            http_client: None,
        }
    }

    /// Specify a custom [`reqwest::Client`] to use for all outbound HTTP
    /// requests to the ACME server.
    pub fn http_client(&mut self, http_client: reqwest::Client) -> &mut Self {
        self.http_client = Some(http_client);
        self
    }

    /// Build a [`Directory`] using the given parameters.
    ///
    /// If no http client is specified, a default client will be created using
    /// the webpki trust roots.
    #[instrument(
    level = Level::INFO,
    name = "acme2::DirectoryBuilder::build",
    err,
    skip(self),
    fields(url = %self.url, custom_http_client = self.http_client.is_some(), dir = field::Empty)
  )]
    pub async fn build(&mut self) -> Result<Arc<Directory>, Error> {
        let http_client = self
            .http_client
            .clone()
            .unwrap_or_else(reqwest::Client::new);

        let resp = http_client.get(&self.url).send().await?;

        let res: Result<Directory, Error> = resp.json::<ServerResult<Directory>>().await?.into();
        let mut dir = res?;
        Span::current().record("dir", &field::debug(&dir));

        dir.http_client = http_client;
        dir.nonce = Mutex::new(None);

        Ok(Arc::new(dir))
    }
}

/// A directory is the resource representing how to reach an ACME server.
///
/// Must be created through a [`DirectoryBuilder`].
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct Directory {
    #[serde(skip)]
    pub(crate) http_client: reqwest::Client,
    #[serde(skip)]
    pub(crate) nonce: Mutex<Option<String>>,
    #[serde(rename = "newNonce")]
    pub(crate) new_nonce_url: String,
    #[serde(rename = "newAccount")]
    pub(crate) new_account_url: String,
    #[serde(rename = "newOrder")]
    pub(crate) new_order_url: String,
    #[serde(rename = "revokeCert")]
    pub(crate) revoke_cert_url: String,
    #[serde(rename = "keyChange")]
    pub(crate) key_change_url: Option<String>,
    #[serde(rename = "newAuthz")]
    pub(crate) new_authz_url: Option<String>,
    /// Optional metadata describing a directory.
    pub meta: Option<DirectoryMeta>,
}

/// This is some metadata about a directory.
///
/// Directories are not required to provide this information.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

fn extract_nonce_from_response(resp: &reqwest::Response) -> Result<Option<String>, Error> {
    let headers = resp.headers();
    let maybe_nonce_res = headers
        .get("replay-nonce")
        .map::<Result<String, Error>, _>(|hv| Ok(map_transport_err(hv.to_str())?.to_string()));
    match maybe_nonce_res {
        Some(Ok(n)) => Ok(Some(n)),
        Some(Err(err)) => Err(err),
        None => Ok(None),
    }
}

impl Directory {
    #[instrument(
    level = Level::DEBUG,
    name = "acme2::Directory::get_nonce",
    err,
    skip(self),
    fields(cached = field::Empty)
  )]
    pub(crate) async fn get_nonce(&self) -> Result<String, Error> {
        let maybe_nonce = {
            let mut guard = self.nonce.lock().unwrap();
            std::mem::replace(&mut *guard, None)
        };
        let span = Span::current();
        span.record("cached", &maybe_nonce.is_some());
        if let Some(nonce) = maybe_nonce {
            return Ok(nonce);
        }
        let resp = self.http_client.get(&self.new_nonce_url).send().await?;
        let maybe_nonce = extract_nonce_from_response(&resp)?;
        match maybe_nonce {
            Some(nonce) => Ok(nonce),
            None => Err(transport_err("newNonce request must return a nonce")),
        }
    }

    #[instrument(level = Level::DEBUG, name = "acme2::Directory::authenticated_request_raw", err, skip(self, payload, pkey))]
    async fn authenticated_request_raw(
        &self,
        url: &str,
        payload: &str,
        pkey: &PKey<Private>,
        account_id: &Option<String>,
    ) -> Result<reqwest::Response, Error> {
        let nonce = self.get_nonce().await?;
        let body = jws(url, Some(nonce), &payload, pkey, account_id.clone())?;
        let body = serde_json::to_vec(&body)?;
        let resp = self
            .http_client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/jose+json")
            .body(body)
            .send()
            .await?;

        if let Some(nonce) = extract_nonce_from_response(&resp)? {
            let mut guard = self.nonce.lock().unwrap();
            *guard = Some(nonce);
        }

        Ok(resp)
    }

    #[instrument(
    level = Level::DEBUG,
    name = "acme2::Directory::authenticated_request_bytes",
    err,
    skip(self, payload, pkey),
    fields()
  )]
    pub(crate) async fn authenticated_request_bytes(
        &self,
        url: &str,
        payload: &str,
        pkey: &PKey<Private>,
        account_id: &Option<String>,
    ) -> Result<(Result<Bytes, ServerError>, reqwest::header::HeaderMap), Error> {
        let mut attempt = 0;

        loop {
            attempt += 1;

            let resp = self
                .authenticated_request_raw(url, &payload, &pkey, &account_id)
                .await?;

            let headers = resp.headers().clone();

            if resp.status().is_success() {
                return Ok((Ok(resp.bytes().await?), headers));
            }

            let err: ServerError = resp.json().await?;

            if let Some(typ) = err.r#type.clone() {
                if &typ == "urn:ietf:params:acme:error:badNonce" && attempt <= 3 {
                    debug!({ attempt }, "bad nonce, retrying");
                    continue;
                }
            }

            return Ok((Err(err), headers));
        }
    }

    #[instrument(
    level = Level::DEBUG,
    name = "acme2::Directory::authenticated_request",
    err,
    skip(self, payload, pkey),
    fields()
  )]
    pub(crate) async fn authenticated_request<T, R>(
        &self,
        url: &str,
        payload: T,
        pkey: PKey<Private>,
        account_id: Option<String>,
    ) -> Result<(ServerResult<R>, reqwest::header::HeaderMap), Error>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let payload = serde_json::to_string(&payload)?;
        let payload = if payload == "\"\"" {
            "".to_string()
        } else {
            payload
        };

        let (res, headers) = self
            .authenticated_request_bytes(url, &payload, &pkey, &account_id)
            .await?;

        let bytes = match res {
            Ok(bytes) => bytes,
            Err(err) => return Ok((ServerResult::Err(err), headers)),
        };

        let val: R = serde_json::from_slice(&bytes)?;

        Ok((ServerResult::Ok(val), headers))
    }
}
