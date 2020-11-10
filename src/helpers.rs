use anyhow::Error;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
  #[serde(rename = "type")]
  /// The type of identifier.
  pub typ: String,
  /// The identifier itself.
  pub value: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeError {
  #[serde(rename = "type")]
  pub typ: Option<String>,
  pub title: Option<String>,
  pub status: Option<u16>,
  pub detail: Option<String>,
}

impl std::error::Error for AcmeError {}

impl std::fmt::Display for AcmeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "AcmeError({}): {}: {}",
      self.typ.clone().unwrap_or_default(),
      self.title.clone().unwrap_or_default(),
      self.detail.clone().unwrap_or_default()
    )
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum AcmeResult<T> {
  Ok(T),
  Err(AcmeError),
}

impl<T> Into<Result<T, Error>> for AcmeResult<T> {
  fn into(self) -> Result<T, Error> {
    match self {
      AcmeResult::Ok(t) => Ok(t),
      AcmeResult::Err(err) => Err(err.into()),
    }
  }
}

pub(crate) fn b64(data: &[u8]) -> String {
  base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
}

pub fn gen_rsa_private_key(bits: u32) -> Result<PKey<Private>, anyhow::Error> {
  let rsa = Rsa::generate(bits)?;
  let key = PKey::from_rsa(rsa)?;
  Ok(key)
}
