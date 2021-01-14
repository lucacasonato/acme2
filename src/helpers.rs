use anyhow::Error;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::Deserialize;
use serde::Serialize;

/// This is a identifier for a resource that the ACME server
/// can provision certificates for (a domain).
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
  /// The type of identifier.
  pub r#type: String,
  /// The identifier itself.
  pub value: String,
}

/// This is an error as returned by the ACME server.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeError {
  /// The type of this error.
  pub r#type: Option<String>,
  /// The human readable title of this error.
  pub title: Option<String>,
  /// The status code of this error.
  pub status: Option<u16>,
  /// The human readable extra description for this error.
  pub detail: Option<String>,
}

impl std::error::Error for AcmeError {}

impl std::fmt::Display for AcmeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "AcmeError({}): {}: {}",
      self.r#type.clone().unwrap_or_default(),
      self.title.clone().unwrap_or_default(),
      self.detail.clone().unwrap_or_default()
    )
  }
}

/// The result of an operation that can return an [`AcmeError`].
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

/// Generate a new RSA private key using the specified size,
/// using the system random.
pub fn gen_rsa_private_key(bits: u32) -> Result<PKey<Private>, anyhow::Error> {
  let rsa = Rsa::generate(bits)?;
  let key = PKey::from_rsa(rsa)?;
  Ok(key)
}
