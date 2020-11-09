use crate::account::Account;
use crate::resources::*;
use anyhow::Error;
use serde::Deserialize;
use serde_json::json;
use std::rc::Rc;

#[derive(Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
/// The status of this order.  Possible values are "pending", "ready",
/// processing", "valid", and "invalid".
pub enum OrderStatus {
  Pending,
  Ready,
  Processing,
  Valid,
  Invalid,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// An ACME order object represents a client's request for a certificate
/// and is used to track the progress of that order through to issuance.
pub struct Order {
  /// The status of this order.
  pub status: OrderStatus,
  /// The timestamp after which the server will consider this order
  /// invalid.
  pub expires: Option<String>,
  /// An array of identifier objects that the order pertains to.
  pub identifiers: Vec<Identifier>,
  /// The requested value of the notBefore field in the certificate.
  pub not_before: Option<String>,
  /// The requested value of the notAfter field in the certificate.
  pub not_after: Option<String>,
  #[serde(rename = "authorizations")]
  /// For pending orders, the authorizations that the client needs to
  /// complete before the requested certificate can be issued. For
  /// final orders (in the "valid" or "invalid" state), the
  /// authorizations that were completed.
  pub(crate) authorization_urls: Vec<String>,
  #[serde(rename = "finalize")]
  /// A URL that a CSR must be POSTed to once all of the order's
  /// authorizations are satisfied to finalize the order.
  pub(crate) finalize_url: String,
  #[serde(rename = "certificate")]
  /// A URL for the certificate that has been issued in response to
  /// this order.
  pub(crate) certificate_url: Option<String>,
}

#[derive(Debug)]
pub struct OrderBuilder {
  account: Rc<Account>,

  identifiers: Vec<Identifier>,
  // TODO(lucacasonato): externalAccountBinding
}

impl OrderBuilder {
  pub fn new(account: Rc<Account>) -> Self {
    OrderBuilder {
      account,
      identifiers: vec![],
    }
  }

  pub fn set_identifiers(&mut self, identifiers: Vec<Identifier>) -> &mut Self {
    self.identifiers = identifiers;
    self
  }

  pub fn add_dns_identifier(&mut self, fqdn: String) -> &mut Self {
    self.identifiers.push(Identifier {
      typ: "dns".to_string(),
      value: fqdn,
    });
    self
  }

  pub async fn build(&mut self) -> Result<Order, Error> {
    let dir = self.account.directory.clone().unwrap();
    let url = dir.new_order_url.clone();

    let (res, _) = dir
      .authenticated_request::<AcmeResult<Order>>(
        &url,
        json!({
          "identifiers": self.identifiers,
        }),
        self.account.private_key.clone().unwrap(),
        Some(self.account.private_key_id.clone()),
      )
      .await?;

    res.into()
  }
}
