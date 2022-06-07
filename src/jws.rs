use crate::error::*;
use crate::helpers::*;
use openssl::hash::MessageDigest;
use openssl::pkey::Id;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::sign::Signer;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Default)]
struct JwsHeader {
  #[serde(skip_serializing_if = "Option::is_none")]
  nonce: Option<String>,
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

#[derive(Serialize, Debug, Clone)]
pub struct JwsResult {
  protected: String,
  payload: String,
  signature: String,
}

pub(crate) fn jws(
  url: &str,
  nonce: Option<String>,
  payload: &str,
  pkey: &PKey<Private>,
  account_id: Option<String>,
) -> Result<JwsResult, Error> {
  let payload_b64 = b64(&payload.as_bytes());

  let alg: String = match pkey.id() {
    Id::RSA => "RS256".into(),
    Id::HMAC => "HS256".into(),
    _ => todo!(),
  };

  let mut header = JwsHeader {
    nonce,
    alg,
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

  Ok(JwsResult {
    protected: protected_b64,
    payload: payload_b64,
    signature: signature_b64,
  })
}
