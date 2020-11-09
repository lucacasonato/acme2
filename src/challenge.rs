use crate::Account;
use crate::Identifier;
use crate::Path;
use crate::{jwt::Jws, CONTENT_TYPE};
use serde_json::json;
use std::time::Duration;

use crate::helper::*;
use log::debug;
use openssl::hash::{hash, MessageDigest};
use reqwest::StatusCode;
use tokio::fs;

use crate::error::{ErrorKind, Result};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
/// A verification challenge.
pub struct Challenge {
    #[serde(skip)]
    pub(crate) domain: Option<String>,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    #[serde(rename = "type")]
    pub(crate) ctype: String,
    /// URL to trigger challenge.
    pub(crate) url: String,
    /// Challenge token.
    pub(crate) token: String,
    /// Key authorization.
    pub(crate) status: String,
    #[serde(skip)]
    pub(crate) key_authorization: String,
}
#[derive(Deserialize, Debug, Clone)]
pub struct CheckResponse {
    pub(crate) status: String,
    pub(crate) expires: String,
    pub(crate) identifier: Identifier,
    pub(crate) challenges: Vec<Challenge>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ValidatePayload {
    #[serde(rename = "type")]
    pub(crate) ctype: String,
    pub(crate) token: String,
    pub(crate) resource: String,
    #[serde(rename = "keyAuthorization")]
    pub(crate) key_authorization: String,
}

impl Challenge {
    /// Saves key authorization into `{path}/.well-known/acme-challenge/{token}` for http challenge.
    pub async fn save_key_authorization<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use tokio::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        debug!("Saving validation token into: {:?}", &path);
        create_dir_all(&path).await?;

        fs::write(path.join(&self.token), self.key_authorization.as_bytes()).await?;

        Ok(())
    }

    /// Gets DNS validation signature.
    ///
    /// This value is used for verification of domain over DNS. Signature must be saved
    /// as a TXT record for `_acme_challenge.example.com`.
    pub fn signature(&self) -> Result<String> {
        Ok(b64(&hash(
            MessageDigest::sha256(),
            &self.key_authorization.clone().into_bytes(),
        )?))
    }

    pub fn domain(&self) -> Option<String> {
        self.domain.clone()
    }

    /// Returns challenge type, usually `http-01` or `dns-01` for Let's Encrypt.
    pub fn ctype(&self) -> &str {
        &self.ctype
    }

    /// Returns challenge token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns key_authorization
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// Triggers validation.
    pub async fn validate(&self, account: &Account, poll_interval: Duration) -> Result<()> {
        let payload = Jws::new(&self.url, account, json!({})).await?;

        let client = client()?;

        let resp = client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/jose+json")
            .body(payload.to_string()?)
            .send()
            .await?;

        if resp.status() != StatusCode::ACCEPTED && resp.status() != StatusCode::OK {
            return Err(
                ErrorKind::Msg("Unacceptable status when trying to validate".to_string()).into(),
            );
        }

        let mut auth: Challenge = resp.json().await?;

        auth.key_authorization = self.key_authorization().to_string();

        loop {
            let status = &auth.status;

            if status == "pending" {
                let jws = Jws::new(&auth.url, account, "").await?.to_string()?;

                let resp = client
                    .post(&auth.url)
                    .header(CONTENT_TYPE, "application/jose+json")
                    .body(jws)
                    .send()
                    .await?;

                auth = resp.json().await?;
            } else if status == "valid" {
                return Ok(());
            } else if status == "invalid" {
                return Err(ErrorKind::Msg("Invalid response.".into()).into());
            }

            tokio::time::delay_for(poll_interval).await
        }
    }
}
