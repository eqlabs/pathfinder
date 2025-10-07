//! Utilities for spawning and managing Pathfinder instances.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use http::StatusCode;
use tokio::time::sleep;

/// Successfully spawned Pathfinder instance is terminated when dropped.
pub struct PathfinderInstance {
    process: Child,
    name: &'static str,
    monitor_port: u16,
    rpc_port: u16,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

/// Configuration for a Pathfinder instance.
#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub name: &'static str,
    pub monitor_port: u16,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub boot_port: Option<u16>,
    pub my_validator_address: u8,
    pub validator_addresses: Vec<u8>,
    pub pathfinder_bin: &'a PathBuf,
    pub fixture_dir: &'a PathBuf,
    pub test_dir: &'a Path,
}

impl PathfinderInstance {
    /// Spawns a new Pathfinder instance with the given configuration. The
    /// instance is not guaranteed to be ready after this function returns.
    /// Use `wait_for_ready` to wait until the instance is ready to accept
    /// requests.
    ///
    /// # Important
    /// The spawned instance will be terminated when the returned
    /// `PathfinderInstance` is dropped.
    pub fn spawn(config: Config<'_>) -> anyhow::Result<Self> {
        let id_file = config.fixture_dir.join(format!("id_{}.json", config.name));
        let db_file = config.test_dir.join(format!("db-{}", config.name));
        let stdout_path = config.test_dir.join(format!("{}_stdout.log", config.name));
        let stdout_file = File::create(stdout_path.clone()).context(format!(
            "Creating stdout log file for pathfinder instance {}",
            config.name
        ))?;
        let stderr_path = config.test_dir.join(format!("{}_stderr.log", config.name));
        let stderr_file = File::create(stderr_path.clone()).context(format!(
            "Creating stderr log file for pathfinder instance {}",
            config.name
        ))?;
        let mut command = Command::new(config.pathfinder_bin);
        let command = command
            .stdout(stdout_file)
            .stderr(stderr_file)
            .env(
                "RUST_LOG",
                "pathfinder_lib=trace,pathfinder=trace,pathfinder_consensus=trace,p2p=off,\
                 informalsystems_malachitebft_core_consensus=trace",
            )
            .args([
                "--ethereum.url=https://ethereum-sepolia-rpc.publicnode.com",
                "--network=sepolia-testnet",
                format!("--data-directory={}", db_file.display()).as_str(),
                "--debug.pretty-log=true",
                "--color=never",
                format!("--monitor-address=127.0.0.1:{}", config.monitor_port).as_str(),
                "--sync.enable=false",
                "--rpc.enable=true",
                format!("--http-rpc=127.0.0.1:{}", config.rpc_port).as_str(),
                "--consensus.enable=true",
                // Currently the proposer address always points to Alice (0x1).
                "--consensus.proposer-addresses=0x1",
                format!(
                    "--consensus.my-validator-address={:#x}",
                    config.my_validator_address
                )
                .as_str(),
                format!(
                    "--consensus.validator-addresses={}",
                    config
                        .validator_addresses
                        .iter()
                        .map(|a| format!("0x{a}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
                .as_str(),
                format!("--p2p.consensus.identity-config-file={}", id_file.display()).as_str(),
                format!(
                    "--p2p.consensus.listen-on=/ip4/127.0.0.1/tcp/{}",
                    config.p2p_port
                )
                .as_str(),
                "--p2p.consensus.experimental.direct-connection-timeout=1",
                "--p2p.consensus.experimental.eviction-timeout=1",
            ]);
        if let Some(boot_port) = config.boot_port {
            // Peer ID from `fixtures/id_Alice.json`.
            command.arg(format!(
                "--p2p.consensus.bootstrap-addresses=/ip4/127.0.0.1/tcp/{boot_port}/p2p/\
                 12D3KooWDJryKaxjwNCk6yTtZ4GbtbLrH7JrEUTngvStaDttLtid"
            ));
        }
        if config.name == "Bob" {
            command.arg("--integration-testing.inject-failure.on-proposal-decided=1");
        }

        let process = command
            .spawn()
            .context(format!("Spawning pathfinder process for {}", config.name))?;
        Ok(Self {
            process,
            name: config.name,
            monitor_port: config.monitor_port,
            rpc_port: config.rpc_port,
            stdout_path,
            stderr_path,
        })
    }

    /// Waits until the instance is ready to accept requests on the monitor
    /// port, or until `timeout` is reached. Polls every `poll_interval`.
    /// If the timeout is reached, an error is returned.
    pub async fn wait_for_ready(
        &self,
        poll_interval: Duration,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let fut = async move {
            let stopwatch = Instant::now();
            loop {
                match reqwest::get(format!("http://127.0.0.1:{}/ready", self.monitor_port)).await {
                    Ok(response) if response.status() == StatusCode::OK => {
                        println!(
                            "Pathfinder instance {} ready after {} s",
                            self.name,
                            stopwatch.elapsed().as_secs()
                        );
                        return;
                    }
                    _ => println!("Pathfinder instance {} not ready yet", self.name),
                }

                sleep(poll_interval).await;
            }
        };
        if tokio::time::timeout(timeout, fut).await.is_err() {
            anyhow::bail!(
                "Timeout waiting for Pathfinder instance {} to be ready",
                self.name
            );
        }
        Ok(())
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    fn terminate(&mut self) {
        _ = Command::new("kill")
            // It's supposed to be the default signal in `kill`, but let's be explicit.
            .arg("-TERM")
            .arg(self.process.id().to_string())
            .status();

        // See if SIGTERM worked.
        match self.process.try_wait() {
            Ok(Some(status)) => {
                println!(
                    "Pathfinder instance {} (pid: {}) terminated with status: {status}",
                    self.name,
                    self.process.id()
                );
            }
            Ok(None) => match self.process.wait() {
                Ok(status) => {
                    println!(
                        "Pathfinder instance {} (pid: {}) terminated with status: {status}",
                        self.name,
                        self.process.id()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Error waiting for Pathfinder instance {} (pid: {}) to terminate: {e}",
                        self.name,
                        self.process.id(),
                    );
                    if let Err(error) = self.process.kill() {
                        eprintln!(
                            "Error killing Pathfinder instance {} (pid: {}): {error}",
                            self.name,
                            self.process.id(),
                        );
                    }
                }
            },
            Err(e) => {
                eprintln!(
                    "Error terminating Pathfinder instance {} (pid: {}): {e}",
                    self.name,
                    self.process.id(),
                );
                if let Err(error) = self.process.kill() {
                    eprintln!(
                        "Error killing Pathfinder instance {} (pid: {}): {error}",
                        self.name,
                        self.process.id(),
                    );
                }
            }
        }
    }

    pub fn enable_log_dump(enable: bool) {
        DUMP_LOGS_ON_DROP.store(enable, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for PathfinderInstance {
    fn drop(&mut self) {
        self.terminate();

        if DUMP_LOGS_ON_DROP.load(std::sync::atomic::Ordering::Relaxed) {
            let stdout = std::fs::read_to_string(&self.stdout_path)
                .unwrap_or("Error reading file".to_string());
            println!("Pathfinder instance {} stdout log:\n{stdout}", self.name);
            let stderr = std::fs::read_to_string(&self.stderr_path)
                .unwrap_or("Error reading file".to_string());
            println!("Pathfinder instance {} stderr log:\n{stderr}", self.name);
        }
    }
}

static DUMP_LOGS_ON_DROP: AtomicBool = AtomicBool::new(true);

impl<'a> Config<'a> {
    const NAMES: &'static [&'static str] = &[
        "Alice", "Bob", "Charlie", "Dan", "Eve", "Frank", "Grace", "Heidi",
    ];

    /// The first node will always be the boot node.
    pub fn for_set(
        set_size: usize,
        pathfinder_bin: &'a PathBuf,
        fixture_dir: &'a PathBuf,
        test_dir: &'a Path,
    ) -> Vec<Self> {
        assert!(
            set_size <= Self::NAMES.len(),
            "Max {} instances supported",
            Self::NAMES.len()
        );
        (0..set_size)
            .map(|i| Self {
                name: Self::NAMES[i],
                monitor_port: 9090 + i as u16,
                rpc_port: 9545 + i as u16,
                p2p_port: 50001 + i as u16,
                boot_port: if i == 0 { None } else { Some(50001) },
                my_validator_address: (i + 1) as u8,
                // The set is deduplicated when consensus task is started, so including the own
                // validator address is fine.
                validator_addresses: (1..=set_size as u8).collect::<Vec<_>>(),
                test_dir,
                pathfinder_bin,
                fixture_dir,
            })
            .collect()
    }
}

pub fn pathfinder_bin() -> PathBuf {
    let mut path = manifest_dir_path();
    assert!(path.pop());
    assert!(path.pop());
    path.push("target");
    #[cfg(debug_assertions)]
    {
        path.push("debug");
    }
    #[cfg(not(debug_assertions))]
    {
        path.push("release");
    }
    path.push("pathfinder");
    path
}

pub fn fixture_dir() -> PathBuf {
    let mut path = manifest_dir_path();
    path.push("tests");
    path.push("fixtures");
    path
}

fn manifest_dir_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
}
