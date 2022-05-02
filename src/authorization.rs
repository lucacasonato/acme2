use crate::account::Account;
use crate::error::*;
use crate::helpers::Identifier;
use crate::helpers::*;
use crate::jws::Jwk;
use crate::order::Order;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use tracing::field;
use tracing::instrument;
use tracing::Level;
use tracing::Span;

#[derive(Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
/// The status of this authorization.
///
/// Possible values are "pending", "valid", "invalid", "deactivated",
/// "expired", and "revoked".
pub enum AuthorizationStatus {
  Pending,
  Valid,
  Invalid,
  Deactivated,
  Expired,
  Revoked,
}

/// An autorization represents the server's authorization of a certain
/// domain being represented by an account.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
  #[serde(skip)]
  pub(crate) account: Option<Arc<Account>>,
  #[serde(skip)]
  pub(crate) url: String,

  /// The identifier (domain) that the account is authorized to represent.
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
  /// Whether this authorization was created for a wildcard identifier
  /// (domain).
  pub wildcard: Option<bool>,
}

/// The status of this challenge.
///
/// Possible values are "pending", "processing", "valid", and "invalid".
#[derive(Deserialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
  Pending,
  Processing,
  Valid,
  Invalid,
}

/// A challenge represents a means for the server to validate
/// that an account has control over an identifier (domain).
///
/// A challenge can only be acquired through an [`Authorization`].
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
  #[serde(skip)]
  pub(crate) account: Option<Arc<Account>>,

  /// The type of challenge encoded in the object.
  pub r#type: String,
  /// The URL to which a response can be posted.
  pub(crate) url: String,
  /// The status of this challenge.
  pub status: ChallengeStatus,
  /// The time at which the server validated this challenge.
  pub validated: Option<String>,

  /// Error that occurred while the server was validating the
  /// challenge, if any.
  pub error: Option<ServerError>,

  /// A random value that uniquely identifies the challenge.
  pub token: Option<String>,
}

impl Order {
  /// Retrieve all of the [`Authorization`]s needed for this order.
  ///
  /// The authorization may already be in a `Valid` state, if an
  /// authorization for this identifier was already completed through
  /// a seperate order.
  #[instrument(level = Level::INFO, name = "acme2::Order::authorizations", err, skip(self), fields(order = %self.url, authorization_urls = ?self.authorization_urls))]
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
          Some(account.id.clone()),
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
  /// Get a certain type of challenge to complete.
  ///
  /// Example: `http-01`, or `dns-01`
  pub fn get_challenge(&self, r#type: &str) -> Option<Challenge> {
    for challenge in &self.challenges {
      if challenge.r#type == r#type {
        return Some(challenge.clone());
      }
    }
    None
  }

  /// Update the authorization to match the current server state.
  ///
  /// Most users should use [`Authorization::wait_done`].
  #[instrument(level = Level::DEBUG, name = "acme2::Authorization::poll", err, skip(self), fields(url = ?self.url, status = field::Empty))]
  pub async fn poll(self) -> Result<Authorization, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Authorization>(
        &self.url,
        json!(""),
        account.private_key.clone().unwrap(),
        Some(account.id.clone()),
      )
      .await?;
    let res: Result<Authorization, Error> = res.into();
    let mut authorization = res?;
    authorization.url = self.url.clone();
    authorization.account = Some(account.clone());
    Span::current().record("status", &field::debug(&authorization.status));
    Ok(authorization)
  }

  /// Wait for the authorization to go into a state other than
  /// [`AuthorizationStatus::Pending`].
  ///
  /// This will only happen once one of the challenges in an authorization
  /// is completed. You can use [`Challenge::wait_done`] to wait until
  /// this is the case.
  ///
  /// Will complete immediately if the authorization is already in a
  /// state other than [`AuthorizationStatus::Pending`].
  ///
  /// Specify the interval at which to poll the acme server, and how often to
  /// attempt polling before timing out. Polling should not happen faster than
  /// about every 5 seconds to avoid rate limits in the acme server.
  #[instrument(level = Level::INFO, name = "acme2::Authorization::wait_done", err, skip(self), fields(url = ?self.url))]
  pub async fn wait_done(
    self,
    poll_interval: Duration,
    attempts: usize,
  ) -> Result<Authorization, Error> {
    let mut authorization = self;

    let mut i: usize = 0;

    while authorization.status == AuthorizationStatus::Pending {
      if i >= attempts {
        return Err(Error::MaxAttemptsExceeded);
      }
      debug!(
        { delay = ?poll_interval },
        "Authorization still pending. Waiting to poll."
      );
      tokio::time::sleep(poll_interval).await;
      authorization = authorization.poll().await?;
      i += 1;
    }

    Ok(authorization)
  }
}

impl Challenge {
  /// The key authorization is the token that the HTTP01 challenge
  /// should be serving for the ACME server to inspect.
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

  /// The encoded key authorization is the token that the DNS01
  /// challenge should be serving for the ACME server to inspect.
  pub fn key_authorization_encoded(&self) -> Result<Option<String>, Error> {
    let key_authorization = self.key_authorization()?;

    if let Some(key_authorization) = key_authorization {
      Ok(Some(b64(&hash(
        MessageDigest::sha256(),
        &key_authorization.into_bytes(),
      )?)))
    } else {
      Ok(None)
    }
  }

  /// Initiate validation of the challenge by the ACME server.
  ///
  /// Before calling this method, you should have set up your challenge token
  /// so it is available for the ACME server to check.
  ///
  /// In most cases this will not complete immediately. You should always
  /// call [`Challenge::wait_done`] after this operation to wait until the
  /// ACME server has finished validation.
  #[instrument(level = Level::INFO, name = "acme2::Challenge::validate", err, skip(self), fields(url = ?self.url, status = field::Empty))]
  pub async fn validate(&self) -> Result<Challenge, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Challenge>(
        &self.url,
        json!({}),
        account.private_key.clone().unwrap(),
        Some(account.id.clone()),
      )
      .await?;
    let res: Result<Challenge, Error> = res.into();
    let mut challenge = res?;
    challenge.account = Some(account.clone());
    Span::current().record("status", &field::debug(&challenge.status));

    Ok(challenge)
  }

  /// Update the challenge to match the current server state.
  ///
  /// Most users should use [`Challenge::wait_done`].
  #[instrument(level = Level::DEBUG, name = "acme2::Challenge::poll", err, skip(self), fields(url = ?self.url, status = field::Empty))]
  pub async fn poll(&self) -> Result<Challenge, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Challenge>(
        &self.url,
        json!(""),
        account.private_key.clone().unwrap(),
        Some(account.id.clone()),
      )
      .await?;
    let res: Result<Challenge, Error> = res.into();
    let mut challenge = res?;
    challenge.account = Some(account.clone());
    Span::current().record("status", &field::debug(&challenge.status));
    Ok(challenge)
  }

  /// Wait for the authorization to go into the [`AuthorizationStatus::Valid`]
  /// or [`AuthorizationStatus::Invalid`] state.
  ///
  /// Will complete immediately if the authorization is already
  /// in one of these states.
  ///
  /// Specify the interval at which to poll the acme server, and how often to
  /// attempt polling before timing out. Polling should not happen faster than
  /// about every 5 seconds to avoid rate limits in the acme server.
  #[instrument(level = Level::INFO, name = "acme2::Challenge::wait_done", err, skip(self), fields(url = ?self.url))]
  pub async fn wait_done(
    self,
    poll_interval: Duration,
    attempts: usize,
  ) -> Result<Challenge, Error> {
    let mut challenge = self;

    let mut i: usize = 0;

    while challenge.status == ChallengeStatus::Pending
      || challenge.status == ChallengeStatus::Processing
    {
      if i >= attempts {
        return Err(Error::MaxAttemptsExceeded);
      }
      debug!(
        { delay = ?poll_interval, status = ?challenge.status },
        "Challenge not done. Waiting to poll."
      );
      tokio::time::sleep(poll_interval).await;
      challenge = challenge.poll().await?;
      i += 1;
    }

    Ok(challenge)
  }
}
