use crate::error::*;
use crate::helpers::*;
use openssl::bn::BigNumContext;
use openssl::ec::{EcKey, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

#[derive(Serialize, Deserialize, Clone, Default)]
struct JwsHeader {
  nonce: String,
  alg: String,
  url: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  kid: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  jwk: Option<Jwk>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kty")]
pub(crate) enum Jwk {
  RSA { e: String, n: String },
  EC { crv: String, x: String, y: String },
}

impl Jwk {
  pub fn new(pkey: &PKey<Private>) -> Result<Jwk, Error> {
    if let Ok(r) = pkey.rsa() {
      return Ok(Jwk::new_from_rsa(&r));
    }

    if let Ok(e) = pkey.ec_key() {
      if e.group().curve_name() == Some(Nid::X9_62_PRIME256V1) {
        return Jwk::new_from_p256(&e);
      }
    }

    Err(Error::Other("unsupported private key type".into()))
  }

  fn new_from_rsa(pkey: &Rsa<Private>) -> Jwk {
    Jwk::RSA {
      e: b64(&pkey.e().to_vec()),
      n: b64(&pkey.n().to_vec()),
    }
  }

  fn new_from_p256(pkey: &EcKey<Private>) -> Result<Jwk, Error> {
    let public = pkey.public_key();

    // Convert to JWK-suitable form, see
    // https://www.openssl.org/docs/man3.0/man3/EC_GROUP_copy.html
    // for descriptions of Compressed/Uncompressed encodings
    let mut ctx = BigNumContext::new().unwrap();
    let bytes = public
      .to_bytes(pkey.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
      .unwrap();

    assert_eq!(65, bytes.len());
    let bytes = &bytes[1..]; // truncate 0x04
    let x = &bytes[0..bytes.len() / 2];
    let y = &bytes[bytes.len() / 2..];

    Ok(Jwk::EC {
      crv: "P-256".into(),
      x: b64(x),
      y: b64(y),
    })
  }

  fn sign_sha256(&self, pkey: &PKey<Private>, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)?;
    signer.update(payload)?;
    let bytes = signer.sign_to_vec()?;
    Ok(match self {
      Jwk::RSA { .. } => bytes,
      Jwk::EC { .. } => {
        // OpenSSL encodes EC signatures in ASN.1 by default.
        // See: https://stackoverflow.com/a/69109085/1264974
        // We parse ASN1 here to transform the signature in simple "concatenated" form
        // as used by JWS.
        let result : (asn1::BigInt, asn1::BigInt) = asn1::parse(&bytes, |d| {
          return d.read_element::<asn1::Sequence>()?.parse(|d| {
            let r = d.read_element::<asn1::BigInt>()?;
            let s = d.read_element::<asn1::BigInt>()?;
            return Ok((r, s));
          });
        }).map_err(Error::Other)?;

        let r = result.0.as_bytes();
        let s = result.1.as_bytes();
        // Per [asn1::BigInt::new]:
        // "<...> if the high bit would be set in the first octet, a leading `\x00`
        // [is] prepended (to disambiguate from negative values)."
        //
        // Strip that first byte if it exists.
        let r = &r[r.len() - 32..];
        let s = &s[s.len() - 32..];

        let mut bytes = Vec::with_capacity(r.len() + s.len());
        bytes.extend_from_slice(r);
        bytes.extend_from_slice(s);
        bytes
      }
    })
  }
}

pub(crate) fn jws(
  url: &str,
  nonce: String,
  payload: &str,
  pkey: &PKey<Private>,
  account_id: Option<String>,
) -> Result<String, Error> {
  let payload_b64 = b64(&payload.as_bytes());
  let jwk = Jwk::new(&pkey)?;

  let mut header = JwsHeader {
    nonce,
    alg: match &jwk {
      Jwk::RSA { .. } => "RS256",
      Jwk::EC { crv, .. } if crv == "P-256" => "ES256",
      _ => unreachable!("Key other than RSA or EC P-256 should not have been created by Jwk::new"),
    }
    .into(),
    url: url.to_string(),
    ..Default::default()
  };

  if let Some(kid) = account_id {
    header.kid = kid.into();
  } else {
    header.jwk = Some(jwk.clone());
  }

  let protected_b64 = b64(&serde_json::to_string(&header)?.into_bytes());

  let to_sign = format!("{}.{}", protected_b64, payload_b64);
  let signature = jwk.sign_sha256(pkey, to_sign.as_bytes())?;
  let signature_b64 = b64(&signature);

  let res = serde_json::to_string(&json!({
    "protected": protected_b64,
    "payload": payload_b64,
    "signature": signature_b64
  }))?;
  println!("{}", res);
  Ok(res)
}

#[cfg(test)]
mod test {
  use super::*;
  use openssl::ec::{EcGroup, EcKey};

  #[test]
  fn test_jws() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    assert_eq!(
      "",
      jws("http://foo", "bar".into(), "payload", &key, None).unwrap()
    )
  }
}
