use crate::order::Order;
use crate::resources::*;
use anyhow::Error;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// The status of this challenge. Possible values are "pending",
/// "processing", "valid", and "invalid".
pub enum ChallengeStatus {
  Pending,
  Processing,
  Valid,
  Invalid,
}

#[derive(Deserialize, Debug)]
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

impl Order {
  pub async fn authorizations(&self) -> Result<Vec<Authorization>, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let mut authorizations = vec![];

    for authorization_url in self.authorization_urls.clone() {
      println!("{}", authorization_url);

      let (res, _) = directory
        .authenticated_request::<_, AcmeResult<Authorization>>(
          &authorization_url,
          "",
          account.private_key.clone().unwrap(),
          Some(account.private_key_id.clone()),
        )
        .await?;

      let res: Result<Authorization, Error> = res.into();
      authorizations.push(res?)
    }

    Ok(authorizations)
  }
}
