use crate::error::*;
use base64::Engine;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::Deserialize;
use serde::Serialize;

/// This is a identifier for a resource that the ACME server
/// can provision certificates for (a domain).
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
    /// The type of identifier.
    pub r#type: String,
    /// The identifier itself.
    pub value: String,
}

pub(crate) fn b64(data: &[u8]) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );

    engine.encode(data)
}

/// Generate a new RSA private key using the specified size,
/// using the system random.
pub fn gen_rsa_private_key(bits: u32) -> Result<PKey<Private>, Error> {
    let rsa = Rsa::generate(bits)?;
    let key = PKey::from_rsa(rsa)?;
    Ok(key)
}

/// Generate a new P256 EC private key using the system random.
pub fn gen_ec_p256_private_key() -> Result<PKey<Private>, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let rsa = EcKey::generate(&group)?;
    let key = PKey::from_ec_key(rsa)?;
    Ok(key)
}
