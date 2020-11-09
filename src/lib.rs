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
  use crate::AccountBuilder;
  use crate::AccountStatus;
  use crate::DirectoryBuilder;

  #[tokio::test]
  async fn test_client_creation() {
    let dir = DirectoryBuilder::new(
      "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
    )
    .build()
    .await
    .unwrap();

    let dir = dir.try_borrow().unwrap();
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
  async fn test_account_creation() {
    let dir = DirectoryBuilder::new(
      "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
    )
    .build()
    .await
    .unwrap();

    let account = AccountBuilder::new(&dir)
      .contact(vec!["mailto:hello@lcas.dev".to_string()])
      .terms_of_service_agreed(true)
      .build()
      .await
      .unwrap();

    assert_eq!(account.status, AccountStatus::Valid)
  }
}
