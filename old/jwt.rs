use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::{helper::b64, Account};

use serde::{Deserialize, Serialize};
use serde_json::to_string;

use crate::error::Result;

/// JwsHeader that is required for ACME2
/// kid is passed after an account is created / looked up
/// jwk is passed for authorization
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct JwsHeader {
  nonce: String,
  alg: String,
  url: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  kid: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  jwk: Option<Jwk>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct Jwk {
  e: String,
  kty: String,
  n: String,
}

impl Jwk {
  pub fn new(pkey: &PKey<openssl::pkey::Private>) -> Jwk {
    Jwk {
      e: b64(&pkey.rsa().unwrap().e().to_vec()),
      kty: "RSA".to_string(),
      n: b64(&pkey.rsa().unwrap().n().to_vec()),
    }
  }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct Jws<T>
where
  T: Serialize,
{
  #[serde(skip)]
  pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
  pub(crate) url: String,
  pub(crate) header: JwsHeader,
  pub(crate) payload: T,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct EncodedJws {
  pub(crate) payload: String,
  pub(crate) protected: String,
  pub(crate) signature: String,
}

impl<T> Jws<T>
where
  T: Serialize,
{
  pub(crate) fn to_string(&self) -> Result<String> {
    let pkey = self.pkey.as_ref().unwrap();
    let payload = to_string(&self.payload)?;

    // a blank string is passed for some of the requests, which to_string turns into literally ""
    let payload64 = if payload == "\"\"" {
      "".into()
    } else {
      b64(&payload.into_bytes())
    };

    let protected64 = b64(&to_string(&self.header)?.into_bytes());

    // signature: b64 of hash of signature of {proctected64}.{payload64}
    let signature64 = {
      let mut signer = Signer::new(MessageDigest::sha256(), pkey)?;
      signer.update(&format!("{}.{}", protected64, payload64).into_bytes())?;
      b64(&signer.sign_to_vec()?)
    };

    Ok(to_string(&EncodedJws {
      payload: payload64,
      protected: protected64,
      signature: signature64,
    })?)
  }

  pub(crate) async fn new(
    url: &str,
    account: &Account,
    payload: T,
  ) -> Result<Jws<T>> {
    let mut header: JwsHeader = JwsHeader::default();
    header.nonce = account.directory.get_nonce().await?;
    header.alg = "RS256".into();
    header.url = url.into();

    if let Some(kid) = account.pkey_id.clone() {
      header.kid = kid.into();
    } else {
      header.jwk = Some(Jwk::new(&account.pkey));
    }

    Ok(Jws {
      pkey: Some(account.pkey.clone()),
      header,
      payload,
      url: url.into(),
    })
  }
}

#[cfg(test)]
pub mod tests {
  extern crate env_logger;
  use crate::error::*;
  use crate::gen_key;
  use crate::Account;
  use crate::Directory;
  use crate::Jws;

  const LETSENCRYPT_STAGING_DIRECTORY_URL: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

  pub async fn test_acc() -> Result<Account> {
    Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL)
      .await?
      .account_registration()
      .register()
      .await
  }

  #[tokio::test]
  async fn test_directory() -> Result<()> {
    Directory::lets_encrypt().await?;

    let dir = Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL)
      .await
      .unwrap();

    assert_eq!(
      dir.resources.new_account,
      "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct"
    );

    assert!(!dir.get_nonce().await.unwrap().is_empty());

    let pkey = gen_key().unwrap();
    let account = dir.account_registration().pkey(pkey).register().await?;

    assert!(
      Jws::new(&account.directory.resources.new_account, &account, "")
        .await
        .is_ok()
    );
    Ok(())
  }
}
