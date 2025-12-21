use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::Context as _;

use crate::common::pathfinder_instance::Config;
use crate::common::utils::{self, create_log_file, feeder_gateway_bin};

pub struct FeederGateway {
    process: Child,
    db_dir: PathBuf,
    port: Option<u16>,
}

impl FeederGateway {
    /// Spawns a local feeder gateway instance that reads from the database
    /// file located in the given proposer's database directory.
    ///
    /// # Important
    ///
    /// The spawned instance will be terminated when the returned
    /// [`FeederGateway`] is dropped.
    pub fn spawn(proposer_config: &Config) -> anyhow::Result<Self> {
        let db_dir = proposer_config.db_dir();
        let stdout_path = proposer_config.test_dir.join(format!("fgw_stdout.log"));
        let stdout_file = create_log_file("Feeder Gateway", &stdout_path)?;
        let stderr_path = proposer_config.test_dir.join(format!("fgw_stderr.log"));
        let stderr_file = create_log_file("Feeder Gateway", &stderr_path)?;

        let feeder_bin = feeder_gateway_bin();
        let process = Command::new(feeder_bin)
            .args([
                "--port=0",
                "--expected-version=76",
                db_dir.join("custom.sqlite").to_str().expect("Valid utf8"),
            ])
            .stdout(stdout_file)
            .stderr(stderr_file)
            .env("RUST_LOG", "trace")
            .env("RUST_BACKTRACE", "full")
            .spawn()
            .context("Spawning local feeder gateway")?;

        Ok(Self {
            process,
            db_dir,
            port: None,
        })
    }

    pub async fn wait_for_ready(
        &mut self,
        poll_interval: Duration,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let pid = self.process.id();
        let port = tokio::time::timeout(
            timeout,
            utils::wait_for_port(pid, "feeder_gateway", &self.db_dir, poll_interval),
        )
        .await??;
        self.port = Some(port);
        Ok(())
    }

    pub fn port(&self) -> u16 {
        self.port
            .expect("Port is not set. Call wait_for_ready first.")
    }

    fn terminate(&mut self) {
        utils::terminate(&mut self.process, "Feeder gateway");
    }
}

impl Drop for FeederGateway {
    fn drop(&mut self) {
        self.terminate();
    }
}
