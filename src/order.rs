use crate::account::Account;
use crate::helpers::*;
use anyhow::Error;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509Name;
use openssl::x509::X509Req;
use openssl::x509::X509;
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
  #[serde(skip)]
  pub(crate) account: Option<Arc<Account>>,
  #[serde(skip)]
  pub(crate) url: String,

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

  /// The error that occurred while processing the order, if any.
  pub error: Option<AcmeError>,

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
  account: Arc<Account>,

  identifiers: Vec<Identifier>,
  // TODO(lucacasonato): externalAccountBinding
}

impl OrderBuilder {
  pub fn new(account: Arc<Account>) -> Self {
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

  #[instrument(level = Level::INFO, name = "acme2_slim::OrderBuilder::build", err, skip(self), fields(identifiers = ?self.identifiers, order_url = field::Empty))]
  pub async fn build(&mut self) -> Result<Order, Error> {
    let dir = self.account.directory.clone().unwrap();

    let (res, headers) = dir
      .authenticated_request::<_, Order>(
        &dir.new_order_url,
        json!({
          "identifiers": self.identifiers,
        }),
        self.account.private_key.clone().unwrap(),
        Some(self.account.private_key_id.clone()),
      )
      .await?;

    let res: Result<Order, Error> = res.into();
    let mut order = res?;

    let order_url = headers
      .get(reqwest::header::LOCATION)
      .ok_or_else(|| {
        anyhow::anyhow!(
          "mandatory location header in newOrder response not present"
        )
      })?
      .to_str()?
      .to_string();
    Span::current().record("order_url", &field::display(&order_url));

    order.account = Some(self.account.clone());
    order.url = order_url;

    Ok(order)
  }
}

pub enum CSR {
  Automatic(PKey<Private>),
  Custom(X509Req),
}

fn gen_csr(
  pkey: &PKey<openssl::pkey::Private>,
  domains: Vec<String>,
) -> Result<X509Req, Error> {
  if domains.is_empty() {
    return Err(anyhow::anyhow!(
      "You need to supply at least one domain name"
    ));
  }

  let mut builder = X509Req::builder()?;
  let name = {
    let mut name = X509Name::builder()?;
    name.append_entry_by_text("CN", &domains[0])?;
    name.build()
  };
  builder.set_subject_name(&name)?;

  // Add all domains as SANs
  let san_extension = {
    let mut san = SubjectAlternativeName::new();
    for domain in domains.iter() {
      san.dns(domain);
    }
    san.build(&builder.x509v3_context(None))?
  };
  let mut stack = Stack::new()?;
  stack.push(san_extension)?;
  builder.add_extensions(&stack)?;

  builder.set_pubkey(&pkey)?;
  builder.sign(pkey, MessageDigest::sha256())?;

  Ok(builder.build())
}

impl Order {
  #[instrument(level = Level::INFO, name = "acme2_slim::Order::finalize", err, skip(self, csr), fields(order_url = %self.url, status = field::Empty))]
  pub async fn finalize(&self, csr: CSR) -> Result<Order, Error> {
    let csr = match csr {
      CSR::Automatic(pkey) => gen_csr(
        &pkey,
        self
          .identifiers
          .iter()
          .map(|f| f.value.clone())
          .collect::<Vec<_>>(),
      )?,
      CSR::Custom(csr) => csr,
    };

    let csr_b64 = b64(&csr.to_der()?);

    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Order>(
        &self.finalize_url,
        json!({ "csr": csr_b64 }),
        account.private_key.clone().unwrap(),
        Some(account.private_key_id.clone()),
      )
      .await?;
    let res: Result<Order, Error> = res.into();
    let mut order = res?;
    Span::current().record("status", &field::debug(&order.status));
    order.account = Some(account.clone());
    order.url = self.url.clone();
    Ok(order)
  }

  #[instrument(level = Level::INFO, name = "acme2_slim::Order::certificate", err, skip(self), fields(order_url = %self.url, has_certificate = field::Empty))]
  pub async fn certificate(&self) -> Result<Option<Vec<X509>>, Error> {
    Span::current().record("has_certificate", &self.certificate_url.is_some());
    let certificate_url = match self.certificate_url.clone() {
      Some(certificate_url) => certificate_url,
      None => return Ok(None),
    };

    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let res = directory
      .authenticated_request_raw(
        &certificate_url,
        "",
        &account.private_key.clone().unwrap(),
        &Some(account.private_key_id.clone()),
      )
      .await?;

    let bytes = res.bytes().await?;

    Ok(Some(X509::stack_from_pem(&bytes)?))
  }

  #[instrument(level = Level::DEBUG, name = "acme2_slim::Order::poll", err, skip(self), fields(order_url = %self.url, status = field::Empty))]
  pub async fn poll(&self) -> Result<Order, Error> {
    let account = self.account.clone().unwrap();
    let directory = account.directory.clone().unwrap();

    let (res, _) = directory
      .authenticated_request::<_, Order>(
        &self.url,
        json!(""),
        account.private_key.clone().unwrap(),
        Some(account.private_key_id.clone()),
      )
      .await?;
    let res: Result<Order, Error> = res.into();
    let mut order = res?;
    Span::current().record("status", &field::debug(&order.status));
    order.account = Some(account.clone());
    order.url = self.url.clone();
    Ok(order)
  }

  #[instrument(level = Level::INFO, name = "acme2_slim::Order::wait_ready", err, skip(self), fields(order_url = %self.url))]
  pub async fn wait_ready(
    self,
    poll_interval: Duration,
  ) -> Result<Order, Error> {
    let mut order = self;

    while order.status == OrderStatus::Pending {
      debug!(
        { delay = ?poll_interval },
        "Order still pending. Waiting to poll."
      );
      tokio::time::delay_for(poll_interval).await;
      order = order.poll().await?;
    }

    Ok(order)
  }

  #[instrument(level = Level::INFO, name = "acme2_slim::Order::wait_ready", err, skip(self), fields(order_url = %self.url))]
  pub async fn wait_done(
    self,
    poll_interval: Duration,
  ) -> Result<Order, Error> {
    let mut order = self;

    while order.status == OrderStatus::Pending
      || order.status == OrderStatus::Ready
      || order.status == OrderStatus::Processing
    {
      debug!(
        { delay = ?poll_interval, status = ?order.status },
        "Order not done. Waiting to poll."
      );
      tokio::time::delay_for(poll_interval).await;
      order = order.poll().await?;
    }

    Ok(order)
  }
}
