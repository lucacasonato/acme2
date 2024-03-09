use crate::common::chaltestsrv::TestServ;
use crate::common::pebble::PebbleBuilder;
use crate::common::test_env::TestEnv;
use acme2_eab::*;
use base64::Engine;
use common::pebble::Pebble;
use openssl::pkey::PKey;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

mod common;

async fn pebble_http_client() -> reqwest::Client {
    let raw = tokio::fs::read("./certs/pebble.minica.pem").await.unwrap();
    let cert = reqwest::Certificate::from_pem(&raw).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap()
}

async fn pebble_directory(pebble: &Pebble) -> Arc<Directory> {
    let http_client = pebble_http_client().await;

    DirectoryBuilder::new(pebble.directory_url.to_string())
        .http_client(http_client)
        .build()
        .await
        .unwrap()
}

async fn pebble_account(pebble: &Pebble) -> Arc<Account> {
    let dir = pebble_directory(pebble).await;
    let mut builder = AccountBuilder::new(dir);

    let account = builder
        .contact(vec!["mailto:hello@lcas.dev".to_string()])
        .terms_of_service_agreed(true)
        .build()
        .await
        .unwrap();

    assert!(!account.id.is_empty());

    account
}

#[tokio::test]
async fn test_client_creation_pebble() {
    let mut env = TestEnv::new("test_client_creation_pebble");
    let pebble = Pebble::new_default(&mut env).await.unwrap();

    let dir = pebble_directory(&pebble).await;

    let meta = dir.meta.clone().unwrap();

    assert_eq!(meta.caa_identities, None);
    assert_eq!(meta.website, None);
    env.stop().await;
}

#[tokio::test]
async fn test_account_creation_pebble() {
    let mut env = TestEnv::new("test_account_creation_pebble");
    let pebble = Pebble::new_default(&mut env).await.unwrap();

    let dir = pebble_directory(&pebble).await;

    let mut builder = AccountBuilder::new(dir.clone());
    let account = builder
        .contact(vec!["mailto:hello@lcas.dev".to_string()])
        .terms_of_service_agreed(true)
        .build()
        .await
        .unwrap();

    assert!(!account.id.is_empty());

    let mut builder = AccountBuilder::new(dir.clone());
    let account2 = builder
        .contact(vec!["mailto:hello@lcas.dev".to_string()])
        .terms_of_service_agreed(true)
        .build()
        .await
        .unwrap();

    assert!(!account.id.is_empty());
    assert_eq!(account.status, AccountStatus::Valid);
    assert_eq!(account2.status, AccountStatus::Valid);
    env.stop().await;
}

#[tokio::test]
async fn test_account_creation_pebble_eab() {
    let private_key = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W";
    let key_id = "kid-1";

    let mut env = TestEnv::new("test_account_creation_pebble_eab");
    let pebble = PebbleBuilder::new()
        .with_eab_keypair(key_id, private_key)
        .build(&mut env)
        .await
        .unwrap();

    let dir = pebble_directory(&pebble).await;

    let eab_key = {
        let value_b64 = private_key;
        let value = base64::engine::general_purpose::STANDARD
            .decode(&value_b64)
            .unwrap();
        PKey::hmac(&value).unwrap()
    };

    let mut builder = AccountBuilder::new(dir.clone());
    let account = builder
        .contact(vec!["mailto:hello@lcas.dev".to_string()])
        .external_account_binding(key_id.to_string(), eab_key)
        .terms_of_service_agreed(true)
        .build()
        .await
        .unwrap();

    assert!(!account.id.is_empty());
    assert_eq!(account.status, AccountStatus::Valid);

    env.stop().await;
}

#[tokio::test]
async fn test_order_http01_challenge_pebble_rsa() {
    let mut env = TestEnv::new("test_order_http01_challenge_pebble_rsa");
    let testserv = TestServ::new(&mut env).await.unwrap();
    let pebble = PebbleBuilder::new()
        .with_http_port(testserv.http_port)
        .build(&mut env)
        .await
        .unwrap();

    let account = pebble_account(&pebble).await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
        .add_dns_identifier("host.docker.internal".to_string())
        .build()
        .await
        .unwrap();

    let authorizations = order.authorizations().await.unwrap();

    let client = reqwest::Client::new();
    for auth in authorizations {
        let challenge = auth.get_challenge("http-01").unwrap();

        assert_eq!(challenge.status, ChallengeStatus::Pending);

        let response = client
            .post(format!("{}add-http01", testserv.management_url))
            .json(&json!({
              "token": challenge.token,
              "content": challenge.key_authorization().unwrap().unwrap()
            }))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());

        let challenge = challenge.validate().await.unwrap();
        let challenge = challenge
            .wait_done(Duration::from_secs(5), 3)
            .await
            .unwrap();

        println!("{:#?}", challenge.error);
        assert_eq!(challenge.status, ChallengeStatus::Valid);

        let authorization = auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
        assert_eq!(authorization.status, AuthorizationStatus::Valid);
    }

    assert_eq!(order.status, OrderStatus::Pending);

    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Ready);

    let pkey = gen_rsa_private_key(4096).unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();

    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Valid);

    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);

    env.stop().await;
}

#[tokio::test]
async fn test_order_http01_challenge_pebble_ec() {
    let mut env = TestEnv::new("test_order_http01_challenge_pebble_ec");
    let testserv = TestServ::new(&mut env).await.unwrap();
    let pebble = PebbleBuilder::new()
        .with_http_port(testserv.http_port)
        .build(&mut env)
        .await
        .unwrap();

    let account = pebble_account(&pebble).await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
        .add_dns_identifier("host.docker.internal".to_string())
        .build()
        .await
        .unwrap();

    let authorizations = order.authorizations().await.unwrap();

    let client = pebble_http_client().await;
    for auth in authorizations {
        let challenge = auth.get_challenge("http-01").unwrap();

        assert_eq!(challenge.status, ChallengeStatus::Pending);

        client
            .post(format!("{}add-http01", testserv.management_url))
            .json(&json!({
              "token": challenge.token,
              "content": challenge.key_authorization().unwrap().unwrap()
            }))
            .send()
            .await
            .unwrap();

        let challenge = challenge.validate().await.unwrap();
        let challenge = challenge
            .wait_done(Duration::from_secs(5), 3)
            .await
            .unwrap();

        println!("{:#?}", challenge.error);
        assert_eq!(challenge.status, ChallengeStatus::Valid);

        let authorization = auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
        assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);

    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Ready);

    let pkey = gen_ec_p256_private_key().unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();

    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();

    assert_eq!(order.status, OrderStatus::Valid);

    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);

    env.stop().await;
}

#[tokio::test]
async fn test_order_dns01_challenge_pebble() {
    let mut env = TestEnv::new("test_order_dns01_challenge_pebble");
    let testserv = TestServ::new(&mut env).await.unwrap();
    let pebble = PebbleBuilder::new()
        .with_dns_port(testserv.dns_port)
        .build(&mut env)
        .await
        .unwrap();

    let account = pebble_account(&pebble).await;

    let mut builder = OrderBuilder::new(account);
    let order = builder
        .add_dns_identifier("test-order-dns01-challenge-pebble.lcas.dev".to_string())
        .build()
        .await
        .unwrap();
    let authorizations = order.authorizations().await.unwrap();
    let client = pebble_http_client().await;

    for auth in authorizations {
        let challenge = auth.get_challenge("dns-01").unwrap();

        assert_eq!(challenge.status, ChallengeStatus::Pending);
        client
            .post(format!("{}set-txt", testserv.management_url))
            .json(&json!({
              "host": "_acme-challenge.test-order-dns01-challenge-pebble.lcas.dev.",
              "value": challenge.key_authorization_encoded().unwrap().unwrap(),
            }))
            .send()
            .await
            .unwrap();
        let challenge = challenge.validate().await.unwrap();
        let challenge = challenge
            .wait_done(Duration::from_secs(5), 3)
            .await
            .unwrap();
        println!("{:#?}", challenge.error);
        assert_eq!(challenge.status, ChallengeStatus::Valid);

        let authorization = auth.wait_done(Duration::from_secs(5), 3).await.unwrap();
        assert_eq!(authorization.status, AuthorizationStatus::Valid)
    }

    assert_eq!(order.status, OrderStatus::Pending);
    let order = order.wait_ready(Duration::from_secs(5), 3).await.unwrap();
    assert_eq!(order.status, OrderStatus::Ready);
    let pkey = gen_rsa_private_key(4096).unwrap();
    let order = order.finalize(Csr::Automatic(pkey)).await.unwrap();
    let order = order.wait_done(Duration::from_secs(5), 3).await.unwrap();
    assert_eq!(order.status, OrderStatus::Valid);
    let cert = order.certificate().await.unwrap().unwrap();
    assert!(cert.len() > 1);

    env.stop().await;
}
