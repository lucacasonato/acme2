use crate::resources::*;
use serde::Deserialize;

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
