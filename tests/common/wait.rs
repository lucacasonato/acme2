use anyhow::{anyhow, Result};
use reqwest::Url;
use std::time::{Duration, SystemTime};

const POLL_LOOP_SLEEP: u64 = 100;

pub async fn wait_for_url(url: &Url, timeout_seconds: u64) -> Result<()> {
    let initial_time = SystemTime::now();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    loop {
        let result = client
            .get(url.clone())
            .timeout(Duration::from_secs(1))
            .send()
            .await;

        match result {
            Ok(_) => return Ok(()),
            Err(e) => {
                if SystemTime::now()
                    .duration_since(initial_time)
                    .unwrap()
                    .as_secs()
                    > timeout_seconds
                {
                    return Err(anyhow!(
                        "Failed to load URL {} after {} seconds. Last error was {:?}",
                        url,
                        timeout_seconds,
                        e
                    ));
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(POLL_LOOP_SLEEP)).await;
    }
}
