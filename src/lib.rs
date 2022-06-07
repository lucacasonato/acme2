//! # acme2
//!
//! A [Tokio](https://crates.io/crates/tokio) and
//! [OpenSSL](https://crates.io/crates/openssl) based
//! [ACMEv2](https://tools.ietf.org/html/rfc8555) client.
//!
//! Features:
//!
//! - ACME v2 support, tested against Let's Encrypt and Pebble
//! - Fully async, using `reqwest` / Tokio
//! - Support for DNS01 and HTTP01 validation
//! - Fully instrumented with `tracing`
//!
//! ## Example
//!
//! This example demonstrates how to provision a certificate for the domain
//! `example.com` using `http-01` validation.
//!
//! ```no_run
//! use acme2::gen_rsa_private_key;
//! use acme2::AccountBuilder;
//! use acme2::AuthorizationStatus;
//! use acme2::ChallengeStatus;
//! use acme2::DirectoryBuilder;
//! use acme2::OrderBuilder;
//! use acme2::OrderStatus;
//! use acme2::Csr;
//! use acme2::Error;
//! use std::time::Duration;
//!
//! const LETS_ENCRYPT_URL: &'static str =
//!   "https://acme-v02.api.letsencrypt.org/directory";
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!   // Create a new ACMEv2 directory for Let's Encrypt.
//!   let dir = DirectoryBuilder::new(LETS_ENCRYPT_URL.to_string())
//!     .build()
//!     .await?;
//!
//!   // Create an ACME account to use for the order. For production
//!   // purposes, you should keep the account (and private key), so
//!   // you can renew your certificate easily.
//!   let mut builder = AccountBuilder::new(dir.clone());
//!   builder.contact(vec!["mailto:hello@lcas.dev".to_string()]);
//!   builder.terms_of_service_agreed(true);
//!   let account = builder.build().await?;
//!
//!   // Create a new order for a specific domain name.
//!   let mut builder = OrderBuilder::new(account);
//!   builder.add_dns_identifier("example.com".to_string());
//!   let order = builder.build().await?;
//!
//!   // Get the list of needed authorizations for this order.
//!   let authorizations = order.authorizations().await?;
//!   for auth in authorizations {
//!     // Get an http-01 challenge for this authorization (or panic
//!     // if it doesn't exist).
//!     let challenge = auth.get_challenge("http-01").unwrap();
//!
//!     // At this point in time, you must configure your webserver to serve
//!     // a file at `https://example.com/.well-known/${challenge.token}`
//!     // with the content of `challenge.key_authorization()??`.
//!
//!     // Start the validation of the challenge.
//!     let challenge = challenge.validate().await?;
//!
//!     // Poll the challenge every 5 seconds until it is in either the
//!     // `valid` or `invalid` state.
//!     let challenge = challenge.wait_done(Duration::from_secs(5), 3).await?;
//!
//!     assert_eq!(challenge.status, ChallengeStatus::Valid);
//!
//!     // You can now remove the challenge file hosted on your webserver.
//!
//!     // Poll the authorization every 5 seconds until it is in either the
//!     // `valid` or `invalid` state.
//!     let authorization = auth.wait_done(Duration::from_secs(5), 3).await?;
//!     assert_eq!(authorization.status, AuthorizationStatus::Valid)
//!   }
//!
//!   // Poll the order every 5 seconds until it is in either the
//!   // `ready` or `invalid` state. Ready means that it is now ready
//!   // for finalization (certificate creation).
//!   let order = order.wait_ready(Duration::from_secs(5), 3).await?;
//!
//!   assert_eq!(order.status, OrderStatus::Ready);
//!
//!   // Generate an RSA private key for the certificate.
//!   let pkey = gen_rsa_private_key(4096)?;
//!
//!   // Create a certificate signing request for the order, and request
//!   // the certificate.
//!   let order = order.finalize(Csr::Automatic(pkey)).await?;
//!
//!   // Poll the order every 5 seconds until it is in either the
//!   // `valid` or `invalid` state. Valid means that the certificate
//!   // has been provisioned, and is now ready for download.
//!   let order = order.wait_done(Duration::from_secs(5), 3).await?;
//!
//!   assert_eq!(order.status, OrderStatus::Valid);
//!
//!   // Download the certificate, and panic if it doesn't exist.
//!   let cert = order.certificate().await?.unwrap();
//!   assert!(cert.len() > 1);
//!
//!   Ok(())
//! }
//! ```
//!
mod account;
mod authorization;
mod directory;
mod error;
mod helpers;
mod jws;
mod order;

pub use account::*;
pub use authorization::*;
pub use directory::*;
pub use error::Error;
pub use error::ServerError;
pub use error::TransportError;
pub use helpers::gen_ec_p256_private_key;
pub use helpers::gen_rsa_private_key;
pub use helpers::Identifier;
pub use openssl;
pub use order::*;

#[cfg(test)]
mod tests {
  use crate::*;
  use openssl::pkey::PKey;
  use serde_json::json;
  use std::sync::Arc;
  use std::time::Duration;

  const PEBBLE_PORT: u16 = 14000;
  const PEBBLE_PORT_EAB: u16 = 14001;

  async fn pebble_http_client() -> reqwest::Client {
    let raw = tokio::fs::read("./certs/pebble.minica.pem").await.unwrap();
    let cert = reqwest::Certificate::from_pem(&raw).unwrap();
    reqwest::Client::builder()
      .add_root_certificate(cert)
      .build()
      .unwrap()
  }

  async fn pebble_directory(port: u16) -> Arc<Directory> {
    let http_client = pebble_http_client().await;

    DirectoryBuilder::new(format!("https://localhost:{}/dir", port))
      .http_client(http_client)
      .build()
      .await
      .unwrap()
  }

  async fn pebble_account() -> Arc<Account> {
    let dir = pebble_directory(PEBBLE_PORT).await;
    let mut builder = AccountBuilder::new(dir);

    let account = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert!(!account.id.is_empty());

    account
  }

  #[tokio::test]
  async fn test_client_creation_letsencrypt() {
    let dir = DirectoryBuilder::new(
      "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
    )
    .build()
    .await
    .unwrap();

    let meta = dir.meta.clone().unwrap();

    assert_eq!(
      meta.caa_identities,
      Some(vec!["letsencrypt.org".to_string()])
    );
    assert_eq!(
      meta.website,
      Some("https://letsencrypt.org/docs/staging-environment/".to_string())
    );
  }

  #[tokio::test]
  async fn test_client_creation_pebble() {
    let dir = pebble_directory(PEBBLE_PORT).await;

    let meta = dir.meta.clone().unwrap();

    assert_eq!(meta.caa_identities, None);
    assert_eq!(meta.website, None);
  }

  #[tokio::test]
  async fn test_account_creation_pebble() {
    let dir = pebble_directory(PEBBLE_PORT).await;

    let mut builder = AccountBuilder::new(dir.clone());
    let account = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert!(!account.id.is_empty());

    let mut builder = AccountBuilder::new(dir.clone());
    let account2 = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert!(!account.id.is_empty());
    assert_eq!(account.status, AccountStatus::Valid);
    assert_eq!(account2.status, AccountStatus::Valid);
  }

  #[tokio::test]
  async fn test_account_creation_pebble_eab() {
    let dir = pebble_directory(PEBBLE_PORT_EAB).await;

    let eab_key = {
      let value_b64 =
        "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W";
      let value = base64::decode(&value_b64).unwrap();
      PKey::hmac(&value).unwrap()
    };

    let mut builder = AccountBuilder::new(dir.clone());
    let account = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .external_account_binding("kid-1".to_string(), eab_key)
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert!(!account.id.is_empty());
    assert_eq!(account.status, AccountStatus::Valid);
  }

  #[tokio::test]
  async fn test_order_http01_challenge_pebble_rsa() {
    let account = pebble_account().await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
      .add_dns_identifier(
        "test-order-http01-challenge-pebble.lcas.dev".to_string(),
      )
      .build()
      .await
      .unwrap();

    let authorizations = order.authorizations().await.unwrap();

    let client = pebble_http_client().await;
    for auth in authorizations {
      let challenge = auth.get_challenge("http-01").unwrap();

      assert_eq!(challenge.status, ChallengeStatus::Pending);

      client
        .post("http://localhost:8055/add-http01")
        .json(&json!({
          "token": challenge.token,
          "content": challenge.key_authorization().unwrap().unwrap()
        }))
        .send()
        .await
        .unwrap();

      let challenge = challenge.validate().await.unwrap();
      let challenge = challenge
        .wait_done(Duration::from_secs(5), 3)
        .await
        .unwrap();

      println!("{:#?}", challenge.error);
      assert_eq!(challenge.status, ChallengeStatus::Valid);

      client
        .post("http://localhost:8055/del-http01")
        .json(&json!({ "token": challenge.token }))
        .send()
        .await
        .unwrap();

      let authorization =
        auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
      assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);

    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Ready);

    let pkey = gen_rsa_private_key(4096).unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();

    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Valid);

    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);
  }

  #[tokio::test]
  async fn test_order_http01_challenge_pebble_ec() {
    let account = pebble_account().await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
      .add_dns_identifier(
        "test-order-http01-challenge-pebble.lcas.dev".to_string(),
      )
      .build()
      .await
      .unwrap();

    let authorizations = order.authorizations().await.unwrap();

    let client = pebble_http_client().await;
    for auth in authorizations {
      let challenge = auth.get_challenge("http-01").unwrap();

      assert_eq!(challenge.status, ChallengeStatus::Pending);

      client
        .post("http://localhost:8055/add-http01")
        .json(&json!({
          "token": challenge.token,
          "content": challenge.key_authorization().unwrap().unwrap()
        }))
        .send()
        .await
        .unwrap();

      let challenge = challenge.validate().await.unwrap();
      let challenge = challenge
        .wait_done(Duration::from_secs(5), 3)
        .await
        .unwrap();

      println!("{:#?}", challenge.error);
      assert_eq!(challenge.status, ChallengeStatus::Valid);

      client
        .post("http://localhost:8055/del-http01")
        .json(&json!({ "token": challenge.token }))
        .send()
        .await
        .unwrap();

      let authorization =
        auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
      assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);

    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Ready);

    let pkey = gen_ec_p256_private_key().unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();

    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Valid);

    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);
  }

  #[tokio::test]
  async fn test_order_dns01_challenge_pebble() {
    let account = pebble_account().await;
    let mut builder = OrderBuilder::new(account);
    let order = builder
      .add_dns_identifier(
        "test-order-dns01-challenge-pebble.lcas.dev".to_string(),
      )
      .build()
      .await
      .unwrap();
    let authorizations = order.authorizations().await.unwrap();
    let client = pebble_http_client().await;

    for auth in authorizations {
      let challenge = auth.get_challenge("dns-01").unwrap();

      assert_eq!(challenge.status, ChallengeStatus::Pending);
      client
        .post("http://localhost:8055/set-txt")
        .json(&json!({
          "host": "_acme-challenge.test-order-dns01-challenge-pebble.lcas.dev.",
          "value": challenge.key_authorization_encoded().unwrap().unwrap(),
        }))
        .send()
        .await
        .unwrap();
      let challenge = challenge.validate().await.unwrap();
      let challenge = challenge
        .wait_done(Duration::from_secs(5), 3)
        .await
        .unwrap();
      println!("{:#?}", challenge.error);
      assert_eq!(challenge.status, ChallengeStatus::Valid);
      client
        .post("http://localhost:8055/clear-txt")
        .json(&json!({
          "host": "_acme-challenge.test-order-dns01-challenge-pebble.lcas.dev."
        }))
        .send()
        .await
        .unwrap();
      let authorization =
        auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
      assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);
    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();
    assert_eq!(order.status, OrderStatus::Ready);
    let pkey = gen_rsa_private_key(4096).unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();
    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();
    assert_eq!(order.status, OrderStatus::Valid);
    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);
  }
}
