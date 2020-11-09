use std::path::Path;
use tokio::fs;

use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Name, X509Req};
use openssl::{pkey::PKey, rsa::Rsa};

use crate::error::Result;

/// Generates new PKey.
pub(crate) fn gen_key() -> Result<PKey<openssl::pkey::Private>> {
    let rsa = Rsa::generate(super::BIT_LENGTH)?;
    let key = PKey::from_rsa(rsa)?;
    Ok(key)
}

/// base64 Encoding with URL and Filename Safe Alphabet.
pub(crate) fn b64(data: &[u8]) -> String {
    ::base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
}

/// Reads PKey from Path.
pub(crate) async fn read_pkey<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>> {
    let content = fs::read(path).await?;
    let key = PKey::private_key_from_pem(&content)?;
    Ok(key)
}

/// Generates X509Req (CSR) from domain names.
///
/// This function will generate a CSR and sign it with PKey.
///
/// Returns X509Req and PKey used to sign X509Req.
pub(crate) fn gen_csr(pkey: &PKey<openssl::pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    if domains.is_empty() {
        return Err("You need to supply at least one or more domain names".into());
    }

    let mut builder = X509Req::builder()?;
    let name = {
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", domains[0])?;
        name.build()
    };
    builder.set_subject_name(&name)?;

    // if more than one domain name is supplied
    // add them as SubjectAlternativeName
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

pub(crate) fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?)
}
