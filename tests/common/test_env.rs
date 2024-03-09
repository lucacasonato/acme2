use super::docker::Container;
use anyhow::Result;
use bollard::{container::Config, Docker};
use std::path::PathBuf;

pub struct TestEnv {
    docker: Docker,
    containers: Vec<Container>,
    pub scratch_dir: PathBuf,
    pub name: String,
}

impl TestEnv {
    pub fn new(name: &str) -> Self {
        let docker = bollard::Docker::connect_with_local_defaults().unwrap();
        let containers = vec![];

        let scratch_dir = PathBuf::from("test-scratch").join(name);
        if scratch_dir.exists() {
            std::fs::remove_dir_all(&scratch_dir).unwrap();
        }
        std::fs::create_dir_all(&scratch_dir).unwrap();

        Self {
            docker,
            containers,
            scratch_dir,
            name: name.to_string(),
        }
    }

    pub async fn start_container(
        &mut self,
        name: &str,
        config: &Config<String>,
    ) -> Result<Container> {
        let log_dir = self.scratch_dir.join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let container = Container::create(
            name.to_string(),
            self.docker.clone(),
            config.clone(),
            Some(log_dir),
        )
        .await?;

        self.containers.push(container.clone());

        Ok(container)
    }

    pub async fn stop(&mut self) {
        while let Some(container) = self.containers.pop() {
            container.stop().await.unwrap();
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if !self.containers.is_empty() {
            // panic!("TestEnv dropped before containers stopped");
            println!("TestEnv dropped before containers stopped");
        }
    }
}
