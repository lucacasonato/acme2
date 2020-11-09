#[macro_use]
extern crate error_chain;

use crate::cert::CertificateSigner;
use crate::challenge::Challenge;
use crate::challenge::CheckResponse;
use core::fmt::Debug;
use core::fmt::Display;
use helper::*;
use jwt::{Jwk, Jws};
use log::info;

use register::AccountRegistration;
use reqwest::header::CONTENT_TYPE;
use reqwest::header::LOCATION;
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use tokio::fs;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::X509;

use error::Result;
use serde::{Deserialize, Serialize};
use serde_json::{to_string, Value};

pub mod cert;
mod challenge;
pub mod error;
mod helper;
mod jwt;
mod register;

pub const LETSENCRYPT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org\
                                                     /directory";
pub const LETSENCRYPT_AGREEMENT_URL: &str = "https://letsencrypt.org/documents/LE-SA-v1.2-\
                                                     November-15-2017.pdf";
/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETSENCRYPT_INTERMEDIATE_CERT_URL: &str = "https://letsencrypt.org/certs/\
                                                             lets-encrypt-x3-cross-signed.pem";
/// Default bit lenght for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;

/*pub mod prelude {
  pub use super::{Directory, Account, Challenge};
}*/

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DirectoryMetadata {
    terms_of_service: Option<String>,
    website: Option<String>,
    caa_identities: Option<Vec<String>>,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DirectoryResources {
    key_change: String,
    meta: DirectoryMetadata,
    new_account: String,
    new_nonce: String,
    new_order: String,
    revoke_cert: String,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}
#[derive(Clone)]
pub struct Directory {
    /// Base URL of directory
    url: String,
    resources: DirectoryResources,
}

impl Directory {
    /// Creates a Directory from
    /// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
    pub async fn lets_encrypt() -> Result<Directory> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL).await
    }

    /// Creates a Directory from directory URL.
    ///
    /// Example directory for testing `acme-client` crate with staging API:
    ///
    /// ```rust
    /// # use acme2_slim::error::Result;
    /// # async fn try_main() -> Result<()> {
    /// use acme2_slim::Directory;
    /// let dir = Directory::from_url("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main () { try_main().await.unwrap(); }
    /// ```
    pub async fn from_url(url: &str) -> Result<Directory> {
        let client = client()?;

        let res = client.get(url).send().await?;

        let resources = res.json().await?;

        Ok(Directory {
            url: url.to_owned(),
            resources,
        })
    }

    /// Consumes directory and creates new AccountRegistration.
    ///
    /// AccountRegistration is used to register an account.
    ///
    /// ```rust,no_run
    /// # use acme2_slim::error::Result;
    /// # async fn try_main() -> Result<()> {
    /// use acme2_slim::Directory;
    ///
    /// let directory = Directory::lets_encrypt().await?;
    /// let account = directory.account_registration()
    ///                        .email("example@example.org")
    ///                        .register().await?;
    /// # Ok(()) }
    /// # #[tokio::main]
    /// # async fn main () { try_main().await.unwrap(); }
    /// ```
    pub fn account_registration(self) -> AccountRegistration {
        AccountRegistration {
            directory: self,
            pkey: None,
            email: None,
            contact: None,
            agreement: None,
        }
    }

    pub fn new_account_url(&self) -> String {
        self.resources.new_account.clone()
    }
    pub fn new_order_url(&self) -> String {
        self.resources.new_order.clone()
    }

    pub fn new_noince_url(&self) -> String {
        self.resources.new_nonce.clone()
    }

    pub fn revoke_cert_url(&self) -> String {
        self.resources.revoke_cert.clone()
    }

    /// Gets nonce header from directory.
    ///
    async fn get_nonce(&self) -> Result<String> {
        let client = client()?;
        let res = client.get(&self.resources.new_nonce).send().await?;
        res.headers()
            .get("Replay-Nonce")
            .ok_or_else(|| "Replay-Nonce header not found".into())
            // TODO(lucacasonato): handle this error
            .map(|nonce| nonce.to_str().unwrap().to_string())
    }

    /// Makes a new post request to directory, signs payload with pkey.
    ///
    /// Returns the result struct that is deserialized from the result
    async fn request<T: Serialize, E>(
        &self,
        account: &mut Account,
        url: &str,
        payload: T,
    ) -> Result<E>
    where
        for<'de> E: Deserialize<'de>,
    {
        let jws = Jws::new(url, account, payload).await?;

        let client = client()?;

        let res = client
            .post(url)
            .header(CONTENT_TYPE, "application/jose+json")
            .body(jws.to_string()?)
            .send()
            .await?;

        let maybe_loc = res.headers().get(LOCATION).cloned();

        if let Some(loc) = maybe_loc {
            if account.pkey_id.is_none() {
                // TODO(lucacasonato): handle this error
                account.pkey_id = Some(loc.to_str().unwrap().to_string());
            }
        }

        Ok(res.json().await?)
    }
}

pub struct Account {
    directory: Directory,
    pkey: PKey<openssl::pkey::Private>,
    pkey_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevokeResponse {
    none: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Identifier {
    #[serde(rename = "type")]
    itype: String,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateOrderResponse {
    finalize_url: String,
    pub challenges: Vec<Challenge>,
    pub domains: Vec<String>,
}

impl CreateOrderResponse {
    pub fn get_dns_challenges(&self) -> Vec<Challenge> {
        self.challenges
            .iter()
            .cloned()
            .filter(|p| p.ctype == "dns-01")
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NewOrderRequest {
    identifiers: Vec<Identifier>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OrderResponse {
    status: String,
    expires: String,
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

impl Account {
    /// Creates a new identifier authorization object for domain
    pub async fn create_order<T: AsRef<str> + Debug + Clone + Display>(
        &mut self,
        domains: &[T],
    ) -> Result<CreateOrderResponse> {
        info!(
            "Sending identifier authorization request for {:?}",
            domains.to_vec()
        );

        let mut challenges: Vec<Challenge> = Vec::new();

        let req = NewOrderRequest {
            identifiers: {
                domains
                    .iter()
                    .map(|i| Identifier {
                        itype: "dns".to_string(),
                        value: i.to_string(),
                    })
                    .collect()
            },
        };
        let directory = self.directory().clone();

        let new_order: OrderResponse = directory
            .request(self, &directory.resources.new_order, req)
            .await?;

        for auth_url in new_order.authorizations {
            let mut resp: CheckResponse = directory.request(self, &auth_url, "").await?;

            for challenge in resp.challenges.iter_mut() {
                let key_authorization = format!(
                    "{}.{}",
                    challenge.token,
                    b64(&hash(
                        MessageDigest::sha256(),
                        &to_string(&Jwk::new(self.pkey()))?.into_bytes()
                    )?)
                );
                challenge.key_authorization = key_authorization.clone();
                challenge.domain = Some(resp.identifier.value.clone());
                challenges.push(challenge.clone());
            }
        }

        Ok(CreateOrderResponse {
            finalize_url: new_order.finalize,
            challenges,
            domains: domains.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// Creates a new `CertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`CertificateSigner`](struct.CertificateSigner.html) for details.
    pub fn certificate_signer(&self) -> CertificateSigner {
        CertificateSigner {
            account: self,
            pkey: None,
            csr: None,
        }
    }

    /// Revokes a signed certificate from pem formatted file
    pub async fn revoke_certificate_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = fs::read(path).await?;
        let cert = X509::from_pem(&content)?;
        self.revoke_certificate(&cert).await
    }

    /// Revokes a signed certificate
    pub async fn revoke_certificate(&mut self, cert: &X509) -> Result<()> {
        let mut map = HashMap::new();
        map.insert("certificate".to_owned(), b64(&cert.to_der()?));
        let directory = self.directory().clone();

        let _response: RevokeResponse = directory
            .request(self, &directory.resources.revoke_cert, map)
            .await?;

        Ok(())
    }

    /// Writes account private key to a writer
    pub async fn write_private_key<W: AsyncWrite>(&self, mut writer: Pin<&mut W>) -> Result<()> {
        writer
            .write_all(&self.pkey().private_key_to_pem_pkcs8()?)
            .await?;
        Ok(())
    }

    /// Saves account private key to a file
    pub async fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = fs::File::create(path).await?;
        self.write_private_key(Pin::new(&mut file)).await
    }

    /// Returns a reference to account private key
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }

    /// Returns a reference to directory used to create account
    pub fn directory(&self) -> &Directory {
        &self.directory
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[tokio::test]
    #[ignore]
    async fn test_order() {
        let _ = env_logger::init();
        let mut account = crate::jwt::tests::test_acc().await.unwrap();
        let order = account.create_order(&["test.lcas.dev"]).await.unwrap();

        for chal in order.get_dns_challenges() {
            println!(
                "Add {} to .acme-challenge.{}",
                chal.signature().unwrap(),
                &chal.domain.as_ref().unwrap()
            );

            chal.validate(&account, Duration::from_secs(5))
                .await
                .unwrap();
        }

        let signer = account.certificate_signer();

        signer
            .sign_certificate(&order, Duration::from_secs(5))
            .await
            .unwrap()
            .save_signed_certificate("tests/cert.pem")
            .await
            .unwrap();
    }
}
