use crate::directory::Directory;
use crate::helpers::*;
use anyhow::Error;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::field;
use tracing::instrument;
use tracing::Level;
use tracing::Span;

#[derive(Deserialize, Eq, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// The status of this account.  Possible values are "valid", "deactivated",
/// and "revoked". The value "deactivated" should be used to indicate client-
/// initiated deactivation whereas "revoked" should be used to indicate server-
/// initiated deactivation.
pub enum AccountStatus {
  Valid,
  Deactivated,
  Revoked,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// An ACME account resource represents a set of metadata associated with an
/// account.
pub struct Account {
  #[serde(skip)]
  pub(crate) directory: Option<Arc<Directory>>,

  #[serde(skip)]
  pub(crate) private_key: Option<PKey<Private>>,
  #[serde(skip)]
  pub(crate) private_key_id: String,

  /// The status of this account.
  pub status: AccountStatus,
  /// An array of URLs that the server can use to contact the client for
  /// issues related to this account.
  pub contact: Option<Vec<String>>,
  /// Including this field in a newAccount request, with a value of true,
  /// indicates the client's agreement with the terms of service.
  pub terms_of_service_agreed: Option<bool>,
  // TODO(lucacasonato): maybe add support for this
  // external_account_binding: Option<Value>
  // TODO(lucacasonato): enable this once LE supports it
  // /// A URL from which a list of orders submitted by this account can be
  // /// fetched
  // #[serde(rename = "orders")]
  // pub(crate) orders_url: Option<String>,
}

#[derive(Debug)]
pub struct AccountBuilder {
  directory: Arc<Directory>,

  private_key: Option<PKey<Private>>,

  contact: Option<Vec<String>>,
  terms_of_service_agreed: Option<bool>,
  only_return_existing: Option<bool>,
  // TODO(lucacasonato): externalAccountBinding
}

impl AccountBuilder {
  pub fn new(directory: Arc<Directory>) -> Self {
    AccountBuilder {
      directory,
      private_key: None,
      contact: None,
      terms_of_service_agreed: None,
      only_return_existing: None,
    }
  }

  pub fn private_key(&mut self, private_key: PKey<Private>) -> &mut Self {
    self.private_key = Some(private_key);
    self
  }

  pub fn contact(&mut self, contact: Vec<String>) -> &mut Self {
    self.contact = Some(contact);
    self
  }

  pub fn terms_of_service_agreed(
    &mut self,
    terms_of_service_agreed: bool,
  ) -> &mut Self {
    self.terms_of_service_agreed = Some(terms_of_service_agreed);
    self
  }

  pub fn only_return_existing(
    &mut self,
    only_return_existing: bool,
  ) -> &mut Self {
    self.only_return_existing = Some(only_return_existing);
    self
  }

  #[instrument(level = Level::INFO, name = "acme2_slim::AccountBuilder::build", err, skip(self), fields(contact = ?self.contact, terms_of_service_agreed = ?self.terms_of_service_agreed, only_return_existing = ?self.only_return_existing, private_key_id = field::Empty))]
  pub async fn build(&mut self) -> Result<Arc<Account>, Error> {
    let private_key = if let Some(private_key) = self.private_key.clone() {
      private_key
    } else {
      gen_rsa_private_key(4096)?
    };

    let url = self.directory.new_account_url.clone();

    let (res, headers) = self
      .directory
      .authenticated_request::<_, Account>(
        &url,
        json!({
          "contact": self.contact,
          "termsOfServiceAgreed": self.terms_of_service_agreed,
          "onlyReturnExisting": self.only_return_existing
        }),
        private_key.clone(),
        None,
      )
      .await?;
    let res: Result<Account, Error> = res.into();
    let mut acc = res?;

    let private_key_id = headers
      .get(reqwest::header::LOCATION)
      .ok_or_else(|| {
        anyhow::anyhow!("mandatory location header in newAccount not present")
      })?
      .to_str()?
      .to_string();
    Span::current().record("private_key_id", &field::display(&private_key_id));

    acc.directory = Some(self.directory.clone());
    acc.private_key = Some(private_key);
    acc.private_key_id = private_key_id;
    Ok(Arc::new(acc))
  }
}

impl Account {
  pub fn private_key(&self) -> PKey<Private> {
    self.private_key.clone().unwrap()
  }
}
