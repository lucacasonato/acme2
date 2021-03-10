# acme2

A [Tokio](https://crates.io/crates/tokio) and
[OpenSSL](https://crates.io/crates/openssl) based
[ACMEv2](https://tools.ietf.org/html/rfc8555) client.

Features:

- ACME v2 support, tested against Let's Encrypt and Pebble
- Fully async, using `reqwest` / Tokio
- Support for DNS01 and HTTP01 validation
- Fully instrumented with `tracing`

## Example

This example demonstrates how to provision a certificate for the domain
`example.com` using `http-01` validation.

```rust
use acme2::gen_rsa_private_key;
use acme2::AccountBuilder;
use acme2::AuthorizationStatus;
use acme2::ChallengeStatus;
use acme2::DirectoryBuilder;
use acme2::Error;
use acme2::OrderBuilder;
use acme2::OrderStatus;
use acme2::CSR;
use std::time::Duration;

const LETS_ENCRYPT_URL: &'static str =
  "https://acme-v02.api.letsencrypt.org/directory";

#[tokio::main]
async fn main() -> Result<(), Error> {
  // Create a new ACMEv2 directory for Let's Encrypt.
  let dir = DirectoryBuilder::new(LETS_ENCRYPT_URL.to_string())
    .build()
    .await?;

  // Create an ACME account to use for the order. For production
  // purposes, you should keep the account (and private key), so
  // you can renew your certificate easily.
  let mut builder = AccountBuilder::new(dir.clone());
  builder.contact(vec!["mailto:hello@lcas.dev".to_string()]);
  builder.terms_of_service_agreed(true);
  let account = builder.build().await?;

  // Create a new order for a specific domain name.
  let mut builder = OrderBuilder::new(account);
  builder.add_dns_identifier("example.com".to_string());
  let order = builder.build().await?;

  // Get the list of needed authorizations for this order.
  let authorizations = order.authorizations().await?;
  for auth in authorizations {
    // Get an http-01 challenge for this authorization (or panic
    // if it doesn't exist).
    let challenge = auth.get_challenge("http-01").unwrap();

    // At this point in time, you must configure your webserver to serve
    // a file at `https://example.com/.well-known/${challenge.token}`
    // with the content of `challenge.key_authorization()??`.

    // Start the validation of the challenge.
    let challenge = challenge.validate().await?;

    // Poll the challenge every 5 seconds until it is in either the
    // `valid` or `invalid` state.
    let challenge = challenge.wait_done(Duration::from_secs(5), 3).await?;

    assert_eq!(challenge.status, ChallengeStatus::Valid);

    // You can now remove the challenge file hosted on your webserver.

    // Poll the authorization every 5 seconds until it is in either the
    // `valid` or `invalid` state.
    let authorization = auth.wait_done(Duration::from_secs(5), 3).await?;
    assert_eq!(authorization.status, AuthorizationStatus::Valid)
  }

  // Poll the order every 5 seconds until it is in either the
  // `ready` or `invalid` state. Ready means that it is now ready
  // for finalization (certificate creation).
  let order = order.wait_ready(Duration::from_secs(5), 3).await?;

  assert_eq!(order.status, OrderStatus::Ready);

  // Generate an RSA private key for the certificate.
  let pkey = gen_rsa_private_key(4096)?;

  // Create a certificate signing request for the order, and request
  // the certificate.
  let order = order.finalize(CSR::Automatic(pkey)).await?;

  // Poll the order every 5 seconds until it is in either the
  // `valid` or `invalid` state. Valid means that the certificate
  // has been provisioned, and is now ready for download.
  let order = order.wait_done(Duration::from_secs(5), 3).await?;

  assert_eq!(order.status, OrderStatus::Valid);

  // Download the certificate, and panic if it doesn't exist.
  let cert = order.certificate().await?.unwrap();
  assert!(cert.len() > 1);

  Ok(())
}
```

## Development

To run the tests, you will need to install `pebble` and `pebble-challtestsrv`.

Start these before running the tests with these commands (in seperate shells):

```shell
pebble -config ./pebble-config.json -strict
```

```shell
pebble-challtestsrv
```

### Windows

To compile on Windows you will need OpenSSL. Here is an easy way to get it
installed.

(example in Git Bash)

```bash
git clone https://github.com/microsoft/vcpkg
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg.exe install openssl
./vcpkg.exe install openssl:x64-windows-static
# Add OPENSSL_DIR=/vcpkg/path/installed/x64-windows-static
cargo build
```

## Licence

This project is licenced under MIT. See LICENCE file for more.
