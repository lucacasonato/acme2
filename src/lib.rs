mod account;
mod authorization;
mod directory;
mod jws;
mod order;
mod resources;

pub use account::*;
pub use authorization::*;
pub use directory::*;
pub use order::*;

#[cfg(test)]
mod tests {
  use crate::*;
  use serde_json::json;
  use std::rc::Rc;
  use std::time::Duration;

  async fn pebble_http_client() -> reqwest::Client {
    let raw = tokio::fs::read("./certs/pebble.minica.pem").await.unwrap();
    let cert = reqwest::Certificate::from_pem(&raw).unwrap();
    reqwest::Client::builder()
      .add_root_certificate(cert)
      .build()
      .unwrap()
  }

  async fn pebble_directory() -> Rc<Directory> {
    let http_client = pebble_http_client().await;

    DirectoryBuilder::new("https://localhost:14000/dir".to_string())
      .http_client(http_client)
      .build()
      .await
      .unwrap()
  }

  async fn pebble_account() -> Rc<Account> {
    let dir = pebble_directory().await;
    let mut builder = AccountBuilder::new(dir);

    let account = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

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
    let dir = pebble_directory().await;

    let meta = dir.meta.clone().unwrap();

    assert_eq!(meta.caa_identities, None);
    assert_eq!(meta.website, None);
  }

  #[tokio::test]
  async fn test_account_creation_pebble() {
    let dir = pebble_directory().await;

    let mut builder = AccountBuilder::new(dir.clone());
    let account = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    let mut builder = AccountBuilder::new(dir.clone());
    let account2 = builder
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert_eq!(account.status, AccountStatus::Valid);
    assert_eq!(account2.status, AccountStatus::Valid);
  }

  #[tokio::test]
  async fn test_order_http01_challenge_pebble() {
    let account = pebble_account().await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
      .add_dns_identifier("test.acme2-slim.lcas.dev".to_string())
      .build()
      .await
      .unwrap();

    let authorizations = order.authorizations().await.unwrap();

    let client = pebble_http_client().await;
    for auth in authorizations {
      for challenge in &auth.challenges {
        if challenge.typ == "http-01" {
          assert_eq!(challenge.status, ChallengeStatus::Pending);

          client
            .post("http://localhost:8055/add-a")
            .json(&json!({
              "host": "test.acme2-slim.lcas.dev",
              "addresses": ["127.0.0.1"]
            }))
            .send()
            .await
            .unwrap();

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
          let challenge =
            challenge.poll_ready(Duration::from_secs(5)).await.unwrap();

          assert_eq!(challenge.status, ChallengeStatus::Valid);
        }
      }

      let authorization =
        auth.poll_ready(Duration::from_secs(5)).await.unwrap();
      assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);
  }
}
