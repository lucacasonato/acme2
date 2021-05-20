use crate::error::*;
use crate::helpers::*;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::sign::Signer;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

#[derive(Serialize, Deserialize, Clone, Default)]
struct JwsHeader {
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
  pub fn new(pkey: &PKey<Private>) -> Jwk {
    Jwk {
      e: b64(&pkey.rsa().unwrap().e().to_vec()),
      kty: "RSA".to_string(),
      n: b64(&pkey.rsa().unwrap().n().to_vec()),
    }
  }
}

pub(crate) fn jws(
  url: &str,
  nonce: String,
  payload: &str,
  pkey: &PKey<Private>,
  account_id: Option<String>,
) -> Result<String, Error> {
  let payload_b64 = b64(&payload.as_bytes());

  let mut header = JwsHeader {
    nonce,
    alg: "RS256".into(),
    url: url.to_string(),
    ..Default::default()
  };

  if let Some(kid) = account_id {
    header.kid = kid.into();
  } else {
    header.jwk = Some(Jwk::new(&pkey));
  }

  let protected_b64 = b64(&serde_json::to_string(&header)?.into_bytes());

  let signature_b64 = {
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)?;
    signer
      .update(&format!("{}.{}", protected_b64, payload_b64).into_bytes())?;
    b64(&signer.sign_to_vec()?)
  };

  Ok(serde_json::to_string(&json!({
    "protected": protected_b64,
    "payload": payload_b64,
    "signature": signature_b64
  }))?)
}
