use crate::{error::Result, helper::*, Account};
use crate::{jwt::Jws, CreateOrderResponse, OrderResponse};
use log::info;
use openssl::x509::X509;
use openssl::{pkey::PKey, x509::X509Req};
use reqwest::header::CONTENT_TYPE;
use reqwest::header::LOCATION;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

#[derive(Serialize, Deserialize, Clone)]
pub struct CsrRequest {
    csr: String,
}

/// A signed certificate.
pub struct SignedCertificate {
    certs: Vec<X509>,
    csr: X509Req,
    pkey: PKey<openssl::pkey::Private>,
}

pub struct CertificateSigner<'a> {
    pub(crate) account: &'a Account,
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) csr: Option<X509Req>,
}

impl<'a> CertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> CertificateSigner<'a> {
        self.pkey = Some(pkey);
        self
    }

    /// Load PEM formatted PKey from file
    pub async fn pkey_from_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(path).await?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> CertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub async fn csr_from_file<P: AsRef<Path>>(
        mut self,
        pkey_path: P,
        csr_path: P,
    ) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(pkey_path).await?);
        let content = fs::read(csr_path).await?;
        self.csr = Some(X509Req::from_pem(&content)?);
        Ok(self)
    }

    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub async fn sign_certificate(
        self,
        order: &CreateOrderResponse,
        poll_interval: Duration,
    ) -> Result<SignedCertificate> {
        info!("Signing certificate");
        let domains: Vec<&str> = order.domains.iter().map(|s| &s[..]).collect();

        let pkey = gen_key()?;
        let csr = gen_csr(&pkey, &domains)?;
        let payload = &csr.to_der()?;

        let csr_payload = CsrRequest { csr: b64(payload) };

        let client = client()?;

        let jws = Jws::new(&order.finalize_url, &self.account, csr_payload)
            .await?
            .to_string()?;

        let resp = client
            .post(&order.finalize_url)
            .header(CONTENT_TYPE, "application/jose+json")
            .body(jws)
            .send()
            .await?;

        let location = resp
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut order_response: OrderResponse = resp.json().await?;

        while order_response.status == "processing" || order_response.certificate.is_none() {
            tokio::time::delay_for(poll_interval).await;

            let jws = Jws::new(&location, &self.account, "").await?.to_string()?;

            let resp = client
                .post(&location)
                .header(CONTENT_TYPE, "application/jose+json")
                .body(jws)
                .send()
                .await?;

            order_response = resp.json().await?;
        }

        Ok(SignedCertificate {
            certs: order_response.get_certificates(&self.account).await?,
            csr,
            pkey,
        })
    }
}

impl OrderResponse {
    async fn get_certificates(&self, account: &Account) -> Result<Vec<X509>> {
        let client = client()?;

        let jws = Jws::new(&self.certificate.clone().unwrap(), &account, "")
            .await?
            .to_string()?;

        let cert_resp = client
            .post(&self.certificate.clone().unwrap())
            .header(CONTENT_TYPE, "application/jose+json")
            .body(jws)
            .send()
            .await?;

        let crt_der = cert_resp.text().await?;

        let cert = X509::stack_from_pem(&crt_der.as_bytes())?;

        Ok(cert)
    }
}

impl SignedCertificate {
    /// Saves signed certificate to a file
    pub async fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = fs::File::create(path).await?;
        self.write_signed_certificate(Pin::new(&mut file)).await
    }

    /// Saves private key used to sign certificate to a file
    pub async fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = fs::File::create(path).await?;
        self.write_private_key(Pin::new(&mut file)).await
    }

    /// Saves CSR used to sign certificateto to a file
    pub async fn save_csr<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = fs::File::create(path).await?;
        self.write_csr(Pin::new(&mut file)).await
    }

    /// Writes signed certificate to writer.
    pub async fn write_signed_certificate<W: AsyncWrite>(
        &self,
        mut writer: Pin<&mut W>,
    ) -> Result<()> {
        for cert in self.cert() {
            writer.write_all(&cert.to_pem()?).await?;
        }
        Ok(())
    }

    /// Writes private key used to sign certificate to a writer
    pub async fn write_private_key<W: AsyncWrite>(&self, mut writer: Pin<&mut W>) -> Result<()> {
        writer
            .write_all(&self.pkey().private_key_to_pem_pkcs8()?)
            .await?;
        Ok(())
    }

    /// Writes CSR used to sign certificateto a writer
    pub async fn write_csr<W: AsyncWrite>(&self, mut writer: Pin<&mut W>) -> Result<()> {
        writer.write_all(&self.csr().to_pem()?).await?;
        Ok(())
    }

    /// Returns reference to certificate
    pub fn cert(&self) -> &Vec<X509> {
        &self.certs
    }

    /// Returns reference to CSR used to sign certificate
    pub fn csr(&self) -> &X509Req {
        &self.csr
    }

    /// Returns reference to pkey used to sign certificate
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }
}
