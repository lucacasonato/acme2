mod account;
mod directory;
mod jws;
mod order;
mod resources;

pub use account::*;
pub use directory::*;
pub use order::*;

#[cfg(test)]
mod tests {
  use crate::*;

  async fn pebble_http_client() -> reqwest::Client {
    let raw = tokio::fs::read("./certs/pebble.minica.pem").await.unwrap();
    let cert = reqwest::Certificate::from_pem(&raw).unwrap();
    reqwest::Client::builder()
      .add_root_certificate(cert)
      .build()
      .unwrap()
  }

  async fn pebble_directory() -> Directory {
    let http_client = pebble_http_client().await;

    DirectoryBuilder::new("https://localhost:14000/dir".to_string())
      .http_client(http_client)
      .build()
      .await
      .unwrap()
  }

  #[tokio::test]
  async fn test_client_creation_letsencrypt() {
    let dir = DirectoryBuilder::new(
      "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
    )
    .build()
    .await
    .unwrap();

    let meta = dir.meta.unwrap();

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

    let meta = dir.meta.unwrap();

    assert_eq!(meta.caa_identities, None);
    assert_eq!(meta.website, None);
  }

  #[tokio::test]
  async fn test_account_creation_pebble() {
    let mut dir = pebble_directory().await;

    let account = AccountBuilder::new(&mut dir)
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    let account2 = AccountBuilder::new(&mut dir)
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert_eq!(account.status, AccountStatus::Valid);
    assert_eq!(account2.status, AccountStatus::Valid);
  }
}
