use super::test_env::TestEnv;
use crate::common::docker::Container;
use crate::common::wait::wait_for_url;
use anyhow::Result;
use bollard::container::Config;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const PEBBLE_IMAGE: &str = "letsencrypt/pebble:v2.3.1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PebbleConfig {
    pub listen_address: SocketAddr,
    pub management_listen_address: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub http_port: u16,
    pub tls_port: u16,
    #[serde(rename = "ocspResponderURL")]
    pub ocsp_responder_url: String,
    pub external_account_binding_required: bool,
    #[serde(rename = "externalAccountMACKeys")]
    pub external_account_mac_keys: HashMap<String, String>,
}

impl Default for PebbleConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:14000".parse().unwrap(),
            management_listen_address: "0.0.0.0:15000".parse().unwrap(),
            certificate: PathBuf::from("test/certs/localhost/cert.pem"),
            private_key: PathBuf::from("test/certs/localhost/key.pem"),
            http_port: 5002,
            tls_port: 5001,
            ocsp_responder_url: "".to_owned(),
            external_account_binding_required: false,
            external_account_mac_keys: HashMap::new(),
        }
    }
}

fn get_start_script(dns_port: Option<u16>) -> String {
    if let Some(dns_port) = dns_port {
        format!(
            r#"#!/bin/sh

set -e

DNS_PORT={}
DNS_IP=$(getent hosts host.docker.internal | awk '{{ print $1 }}')
DNS_SERVER=$DNS_IP:$DNS_PORT

echo "Starting pebble with DNS server $DNS_SERVER"

/usr/bin/pebble -config /etc/pebble/config.json -dnsserver $DNS_SERVER
"#,
            dns_port
        )
    } else {
        r#"#!/bin/sh

set -e

echo "Starting pebble"

/usr/bin/pebble -config /etc/pebble/config.json
"#
        .to_owned()
    }
}

pub struct PebbleBuilder {
    dns_port: Option<u16>,
    config: PebbleConfig,
}

impl PebbleBuilder {
    pub fn new() -> Self {
        Self {
            dns_port: None,
            config: PebbleConfig::default(),
        }
    }

    pub fn with_dns_port(&mut self, port: u16) -> &mut Self {
        self.dns_port = Some(port);
        self
    }

    pub fn with_eab_keypair(&mut self, key_id: &str, key: &str) -> &mut Self {
        self.config
            .external_account_mac_keys
            .insert(key_id.to_string(), key.to_string());
        self
    }

    pub fn with_http_port(&mut self, port: u16) -> &mut Self {
        self.config.http_port = port;
        self
    }

    pub async fn build(&mut self, env: &mut TestEnv) -> Result<Pebble> {
        let pebble = Pebble::new_from_config(env, self.dns_port, &self.config).await?;
        Ok(pebble)
    }
}

pub struct Pebble {
    pub directory_url: Url,
}

impl Pebble {
    async fn directory_url(container: &Container) -> Url {
        let v = format!(
            "https://127.0.0.1:{}/dir",
            container.get_tcp_port(14000).await.unwrap()
        );

        Url::parse(&v).unwrap()
    }

    pub async fn new_default(env: &mut TestEnv) -> Result<Pebble> {
        Self::new_from_config(env, None, &PebbleConfig::default()).await
    }

    async fn new_from_config(
        env: &mut TestEnv,
        dns_port: Option<u16>,
        pebble_config: &PebbleConfig,
    ) -> Result<Pebble> {
        let scratch_dir = env.scratch_dir.clone();

        let pebble_dir = scratch_dir.canonicalize()?.join("pebble");
        std::fs::create_dir_all(&pebble_dir)?;

        std::fs::write(
            pebble_dir.join("config.json"),
            serde_json::to_string_pretty(&json!({"pebble": pebble_config}))?,
        )?;

        std::fs::write(pebble_dir.join("start.sh"), get_start_script(dns_port))?;

        std::fs::set_permissions(
            pebble_dir.join("start.sh"),
            std::fs::Permissions::from_mode(0o755),
        )?;

        let config = Config {
            image: Some(PEBBLE_IMAGE.to_string()),
            cmd: Some(vec!["/etc/pebble/start.sh".to_string()]),
            env: Some(vec![
                // https://github.com/letsencrypt/pebble?tab=readme-ov-file#testing-at-full-speed
                "PEBBLE_VA_NOSLEEP=1".to_string(),
            ]),
            host_config: Some(bollard::service::HostConfig {
                binds: Some(vec![format!(
                    "{}:/etc/pebble",
                    pebble_dir.to_str().unwrap()
                )]),
                port_bindings: Some(
                    vec![(
                        "14000/tcp".to_string(),
                        Some(vec![bollard::service::PortBinding {
                            host_ip: Some("0.0.0.0".to_string()),
                            host_port: None,
                        }]),
                    )]
                    .into_iter()
                    .collect(),
                ),
                extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let container = env.start_container("pebble", &config).await?;

        let directory_url = Self::directory_url(&container).await;

        wait_for_url(&directory_url, 5).await?;

        let pebble = Pebble { directory_url };

        Ok(pebble)
    }
}
