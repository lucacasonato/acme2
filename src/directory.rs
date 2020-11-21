use crate::helpers::*;
use crate::jws::jws;
use anyhow::Error;
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

pub struct DirectoryBuilder {
  url: String,
  http_client: Option<reqwest::Client>,
}

impl DirectoryBuilder {
  pub fn new(url: String) -> Self {
    DirectoryBuilder {
      url,
      http_client: None,
    }
  }

  pub fn http_client(&mut self, http_client: reqwest::Client) -> &mut Self {
    self.http_client = Some(http_client);
    self
  }

  #[instrument(
    level = Level::INFO,
    name = "acme2_slim::DirectoryBuilder::build",
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

    let res: Result<Directory, Error> =
      resp.json::<AcmeResult<Directory>>().await?.into();
    let mut dir = res?;
    Span::current().record("dir", &field::debug(&dir));

    dir.http_client = http_client;
    dir.nonce = Mutex::new(None);

    Ok(Arc::new(dir))
  }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
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
  pub(crate) key_change_url: String,
  #[serde(rename = "newAuthz")]
  pub(crate) new_authz_url: Option<String>,
  pub meta: Option<DirectoryMeta>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
  pub terms_of_service: Option<String>,
  pub website: Option<String>,
  pub caa_identities: Option<Vec<String>>,
  pub external_account_required: Option<bool>,
}

fn extract_nonce_from_response(
  resp: &reqwest::Response,
) -> Result<Option<String>, Error> {
  let headers = resp.headers();
  let maybe_nonce_res = headers
    .get("replay-nonce")
    .map::<Result<String, Error>, _>(|hv| Ok(hv.to_str()?.to_string()));
  match maybe_nonce_res {
    Some(Ok(n)) => Ok(Some(n)),
    Some(Err(err)) => Err(err),
    None => Ok(None),
  }
}

impl Directory {
  #[instrument(
    level = Level::DEBUG,
    name = "acme2_slim::Directory::get_nonce",
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
      None => Err(anyhow::anyhow!("newNonce request must return a nonce")),
    }
  }

  #[instrument(level = Level::DEBUG, name = "acme2_slim::Directory::authenticated_request_raw", err, skip(self, payload, pkey))]
  pub(crate) async fn authenticated_request_raw(
    &self,
    url: &str,
    payload: &str,
    pkey: &PKey<Private>,
    pkey_id: &Option<String>,
  ) -> Result<reqwest::Response, Error> {
    let nonce = self.get_nonce().await?;
    let body = jws(url, nonce, &payload, pkey, pkey_id.clone())?;
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
    name = "acme2_slim::Directory::authenticated_request",
    err,
    skip(self, payload, pkey),
    fields()
  )]
  pub(crate) async fn authenticated_request<T, R>(
    &self,
    url: &str,
    payload: T,
    pkey: PKey<Private>,
    pkey_id: Option<String>,
  ) -> Result<(AcmeResult<R>, reqwest::header::HeaderMap), Error>
  where
    T: Serialize,
    R: DeserializeOwned,
  {
    let mut attempt = 0;
    let payload = serde_json::to_string(&payload)?;
    let payload = if payload == "\"\"" {
      "".to_string()
    } else {
      payload
    };

    loop {
      attempt += 1;

      let resp = self
        .authenticated_request_raw(url, &payload, &pkey, &pkey_id)
        .await?;

      let headers = resp.headers().clone();

      let res: AcmeResult<R> = resp.json().await?;

      let res = match res {
        AcmeResult::Err(err) => {
          if let Some(typ) = err.typ.clone() {
            if &typ == "urn:ietf:params:acme:error:badNonce" && attempt <= 3 {
              debug!({ attempt }, "bad nonce, retrying");
              continue;
            }
          }
          AcmeResult::Err(err)
        }
        AcmeResult::Ok(ok) => AcmeResult::Ok(ok),
      };

      return Ok((res, headers));
    }
  }
}
