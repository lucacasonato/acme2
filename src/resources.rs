use anyhow::Error;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// The status of this authorization. Possible values are "pending",
/// "valid", "invalid", "deactivated", "expired", and "revoked".
pub enum AuthorizationStatus {
  Pending,
  Valid,
  Invalid,
  Deactivated,
  Expired,
  Revoked,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// An ACME authorization object represents a server's authorization
/// for an account to represent an identifier.
pub struct Authorization {
  /// The identifier that the account is authorized to represent.
  pub identifier: Identifier,
  /// The status of this authorization.
  pub status: AuthorizationStatus,
  /// The timestamp after which the server will consider this
  /// authorization invalid.
  pub expires: Option<String>,
  /// For pending authorizations, the challenges that the client can
  /// fulfill in order to prove possession of the identifier. For
  /// valid authorizations, the challenge that was validated. For
  /// invalid authorizations, the challenge that was attempted and
  /// failed.
  pub challenges: Vec<Challenge>,
  pub wildcard: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// The status of this challenge. Possible values are "pending",
/// "processing", "valid", and "invalid".
pub enum ChallengeStatus {
  Pending,
  Processing,
  Valid,
  Invalid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
  #[serde(rename = "type")]
  /// The type of challenge encoded in the object.
  pub typ: String,
  /// The URL to which a response can be posted.
  pub url: String,
  /// The status of this challenge.
  pub status: ChallengeStatus,
  /// The time at which the server validated this challenge.
  pub validated: Option<String>,

  /// A random value that uniquely identifies the challenge.
  pub token: Option<String>,
}

#[derive(Deserialize, Debug)]
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
