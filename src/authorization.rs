use crate::account::Account;
use crate::helpers::Identifier;
use crate::helpers::*;
use crate::jws::Jwk;
use crate::order::Order;
use anyhow::Error;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use serde::Deserialize;
use serde_json::json;
use std::rc::Rc;
use std::time::Duration;

#[derive(Deserialize, Debug, Eq, PartialEq)]
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
  #[serde(skip)]
  pub(crate) account: Option<Rc<Account>>,
  #[serde(skip)]
  pub(crate) url: String,

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

#[derive(Deserialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
/// The status of this challenge. Possible values are "pending",
/// "processing", "valid", and "invalid".
pub enum ChallengeStatus {
  Pending,
  Processing,
  Valid,
  Invalid,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
  #[serde(skip)]
  pub(crate) account: Option<Rc<Account>>,

  #[serde(rename = "type")]
  /// The type of challenge encoded in the object.
  pub typ: String,
  /// The URL to which a response can be posted.
  pub(crate) url: String,
  /// The status of this challenge.
  pub status: ChallengeStatus,
  /// The time at which the server validated this challenge.
  pub validated: Option<String>,

  /// Error that occurred while the server was validating the
  /// challenge, if any.
  pub error: Option<AcmeError>,

  /// A random value that uniquely identifies the challenge.
  pub token: Option<String>,
}

impl Order {
  pub async fn authorizations(&self) -> Result<Vec<Authorization>, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let mut authorizations = vec![];

    for authorization_url in self.authorization_urls.clone() {
      let (res, _) = directory
        .authenticated_request::<_, Authorization>(
          &authorization_url,
          "",
          account.private_key.clone().unwrap(),
          Some(account.private_key_id.clone()),
        )
        .await?;

      let res: Result<Authorization, Error> = res.into();

      let mut authorization = res?;
      authorization.account = Some(account.clone());
      authorization.url = authorization_url;
      for challenge in &mut authorization.challenges {
        challenge.account = Some(account.clone())
      }
      authorizations.push(authorization)
    }

    Ok(authorizations)
  }
}

impl Authorization {
  pub fn get_challenge(&self, typ: &str) -> Option<Challenge> {
    for challenge in &self.challenges {
      if challenge.typ == typ {
        return Some(challenge.clone());
      }
    }
    None
  }

  pub async fn poll(&self) -> Result<Authorization, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Authorization>(
        &self.url,
        json!(""),
        account.private_key.clone().unwrap(),
        Some(account.private_key_id.clone()),
      )
      .await?;
    let res: Result<Authorization, Error> = res.into();
    let mut authorization = res?;
    authorization.account = Some(account.clone());
    authorization.url = self.url.clone();
    Ok(authorization)
  }

  pub async fn poll_done(
    self,
    poll_interval: Duration,
  ) -> Result<Authorization, Error> {
    let mut authorization = self;

    while authorization.status == AuthorizationStatus::Pending {
      tokio::time::delay_for(poll_interval).await;
      authorization = authorization.poll().await?;
    }

    Ok(authorization)
  }
}

impl Challenge {
  pub fn key_authorization(&self) -> Result<Option<String>, Error> {
    if let Some(token) = self.token.clone() {
      let account = self.account.clone().unwrap();

      let key_authorization = format!(
        "{}.{}",
        token,
        b64(&hash(
          MessageDigest::sha256(),
          &serde_json::to_string(&Jwk::new(
            &account.private_key.clone().unwrap()
          ))?
          .into_bytes()
        )?)
      );

      Ok(Some(key_authorization))
    } else {
      Ok(None)
    }
  }

  pub async fn validate(&self) -> Result<Challenge, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Challenge>(
        &self.url,
        json!({}),
        account.private_key.clone().unwrap(),
        Some(account.private_key_id.clone()),
      )
      .await?;
    let res: Result<Challenge, Error> = res.into();
    let mut challenge = res?;
    challenge.account = Some(account.clone());

    Ok(challenge)
  }

  pub async fn poll(&self) -> Result<Challenge, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Challenge>(
        &self.url,
        json!(""),
        account.private_key.clone().unwrap(),
        Some(account.private_key_id.clone()),
      )
      .await?;
    let res: Result<Challenge, Error> = res.into();
    let mut challenge = res?;
    challenge.account = Some(account.clone());
    Ok(challenge)
  }

  pub async fn poll_done(
    self,
    poll_interval: Duration,
  ) -> Result<Challenge, Error> {
    let mut challenge = self;

    while challenge.status == ChallengeStatus::Pending
      || challenge.status == ChallengeStatus::Processing
    {
      tokio::time::delay_for(poll_interval).await;
      challenge = challenge.poll().await?;
    }

    Ok(challenge)
  }
}
