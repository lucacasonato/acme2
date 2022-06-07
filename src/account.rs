use crate::directory::Directory;
use crate::error::*;
use crate::helpers::*;
use crate::jws::jws;
use crate::jws::Jwk;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::field;
use tracing::instrument;
use tracing::Level;
use tracing::Span;

/// The status of an [`Account`].
///
/// Possible values are "valid", "deactivated",
/// and "revoked". The value "deactivated" should be used to indicate client-
/// initiated deactivation whereas "revoked" should be used to indicate server-
/// initiated deactivation.
#[derive(Deserialize, Eq, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
  Valid,
  Deactivated,
  Revoked,
}

#[derive(Debug, Clone)]
pub(crate) struct ExternalAccountBinding {
  /// Key identifier, in string form.
  key_id: String,

  /// HMAC private key.
  private_key: PKey<Private>,
}

/// An ACME account. This is used to identify a subscriber to an ACME server.
///
/// This resource should be created through an [`AccountBuilder`].
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account {
  #[serde(skip)]
  pub(crate) directory: Option<Arc<Directory>>,

  #[serde(skip)]
  pub(crate) private_key: Option<PKey<Private>>,

  #[serde(skip)]
  pub(crate) eab_config: Option<ExternalAccountBinding>,

  #[serde(skip)]
  /// The account ID of this account.
  pub id: String,

  /// The status of this account.
  pub status: AccountStatus,
  /// An array of URLs that the server can use to contact the client for
  /// issues related to this account.
  pub contact: Option<Vec<String>>,
  /// Including this field in a newAccount request, with a value of true,
  /// indicates the client's agreement with the terms of service.
  pub terms_of_service_agreed: Option<bool>,
  // TODO(lucacasonato): enable this once LE supports it
  // /// A URL from which a list of orders submitted by this account can be
  // /// fetched
  // #[serde(rename = "orders")]
  // pub(crate) orders_url: Option<String>,
}

/// An builder that is used to create / retrieve an [`Account`] from the
/// ACME server.
#[derive(Debug)]
pub struct AccountBuilder {
  directory: Arc<Directory>,

  private_key: Option<PKey<Private>>,
  eab_config: Option<ExternalAccountBinding>,

  contact: Option<Vec<String>>,
  terms_of_service_agreed: Option<bool>,
  only_return_existing: Option<bool>,
}

impl AccountBuilder {
  /// This creates a new [`AccountBuilder`]. This can be used to create a new
  /// account (if the server has not seen the private key before), or to retrieve
  /// an existing account (using a previously used private key).
  pub fn new(directory: Arc<Directory>) -> Self {
    AccountBuilder {
      directory,
      private_key: None,
      eab_config: None,
      contact: None,
      terms_of_service_agreed: None,
      only_return_existing: None,
    }
  }

  /// The private key that is used to sign requests to the ACME server. This
  /// may not be the same as a certificate private key.
  pub fn private_key(&mut self, private_key: PKey<Private>) -> &mut Self {
    self.private_key = Some(private_key);
    self
  }

  pub fn external_account_binding(
    &mut self,
    key_id: String,
    private_key: PKey<Private>,
  ) -> &mut Self {
    self.eab_config = Some(ExternalAccountBinding {
      key_id,
      private_key,
    });
    self
  }

  /// The contact information for the account. For example this could be a
  /// `vec!["email:hello@lcas.dev".to_string()]`. The supported contact types
  /// vary from one ACME server to another.
  pub fn contact(&mut self, contact: Vec<String>) -> &mut Self {
    self.contact = Some(contact);
    self
  }

  /// If you agree to the ACME server terms of service.
  pub fn terms_of_service_agreed(
    &mut self,
    terms_of_service_agreed: bool,
  ) -> &mut Self {
    self.terms_of_service_agreed = Some(terms_of_service_agreed);
    self
  }

  /// Do not try to create a new account. If this is set, only an existing account
  /// will be returned.
  pub fn only_return_existing(
    &mut self,
    only_return_existing: bool,
  ) -> &mut Self {
    self.only_return_existing = Some(only_return_existing);
    self
  }

  /// This will create / retrieve an [`Account`] from the ACME server.
  ///
  /// If the [`AccountBuilder`] does not contain a private key, a new
  /// 4096 bit RSA key will be generated (using the system random). If
  /// a key is generated, it can be retrieved from the created [`Account`]
  /// through the [`Account::private_key`] method.
  #[instrument(level = Level::INFO, name = "acme2::AccountBuilder::build", err, skip(self), fields(contact = ?self.contact, terms_of_service_agreed = ?self.terms_of_service_agreed, only_return_existing = ?self.only_return_existing, private_key_id = field::Empty))]
  pub async fn build(&mut self) -> Result<Arc<Account>, Error> {
    let private_key = if let Some(private_key) = self.private_key.clone() {
      private_key
    } else {
      gen_rsa_private_key(4096)?
    };

    let url = self.directory.new_account_url.clone();

    let external_account_binding = if let Some(eab_config) = &self.eab_config {
      let payload = serde_json::to_string(&Jwk::new(&private_key)).unwrap();

      Some(jws(
        &url,
        None,
        &payload,
        &eab_config.private_key,
        Some(eab_config.key_id.clone()),
      )?)
    } else {
      None
    };

    let (res, headers) = self
      .directory
      .authenticated_request::<_, Account>(
        &url,
        json!({
          "contact": self.contact,
          "termsOfServiceAgreed": self.terms_of_service_agreed,
          "onlyReturnExisting": self.only_return_existing,
          // TODO: omit if None?
          "externalAccountBinding": external_account_binding,
        }),
        private_key.clone(),
        None,
      )
      .await?;
    let res: Result<Account, Error> = res.into();
    let mut acc = res?;

    let account_id = map_transport_err(
      headers
        .get(reqwest::header::LOCATION)
        .ok_or_else(|| {
          transport_err("mandatory location header in newAccount not present")
        })?
        .to_str(),
    )?
    .to_string();
    Span::current().record("account_id", &field::display(&account_id));

    acc.directory = Some(self.directory.clone());
    acc.private_key = Some(private_key);
    acc.eab_config = self.eab_config.clone();
    acc.id = account_id;
    Ok(Arc::new(acc))
  }
}

impl Account {
  /// Retrieve the private key for this account.
  pub fn private_key(&self) -> PKey<Private> {
    self.private_key.clone().unwrap()
  }
}
