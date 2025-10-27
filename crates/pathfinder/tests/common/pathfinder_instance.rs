//! Utilities for spawning and managing Pathfinder instances.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use http::StatusCode;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Represents a running Pathfinder instance.
pub struct PathfinderInstance {
    process: Child,
    name: &'static str,
    monitor_port: AtomicU16,
    consensus_p2p_port: AtomicU16,
    rpc_port_watch_tx: watch::Sender<u16>,
    rpc_port_watch_rx: watch::Receiver<u16>,
    db_dir: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// `true` if [`PathfinderInstance::exited_wit_error`] returned
    /// `Ok(_)`.
    is_terminated: bool,
}

/// Configuration for a Pathfinder instance.
#[derive(Debug, Clone)]
pub struct Config {
    pub name: &'static str,
    pub boot_port: Option<u16>,
    pub my_validator_address: u8,
    pub validator_addresses: Vec<u8>,
    pub pathfinder_bin: PathBuf,
    pub fixture_dir: PathBuf,
    pub test_dir: PathBuf,
    pub inject_failure: Option<InjectFailure>,
}

#[derive(Debug, Clone, Copy)]
pub enum InjectFailure {
    OnProposalRx(u64),
    _OnProposalDecided(u64),
}

impl PathfinderInstance {
    /// Spawns a new Pathfinder instance with the given configuration. The
    /// instance is not guaranteed to be ready after this function returns.
    /// Use [`wait_for_ready`](PathfinderInstance::wait_for_ready) to wait until
    /// the instance is ready to accept requests.
    ///
    /// # Important
    ///
    /// The spawned instance will be terminated when the returned
    /// [`PathfinderInstance`] is dropped, unless
    /// [`exited_with_error`](PathfinderInstance::exited_with_error) already
    /// returned `Ok(_)`, which means that the instance has already exited.
    pub fn spawn(config: Config) -> anyhow::Result<Self> {
        let id_file = config.fixture_dir.join(format!("id_{}.json", config.name));
        let db_dir = config.test_dir.join(format!("db-{}", config.name));
        let stdout_path = config.test_dir.join(format!("{}_stdout.log", config.name));
        let stdout_file = create_log_file(&config, &stdout_path)?;
        let stderr_path = config.test_dir.join(format!("{}_stderr.log", config.name));
        let stderr_file = create_log_file(&config, &stderr_path)?;

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
                format!("--data-directory={}", db_dir.display()).as_str(),
                "--debug.pretty-log=true",
                "--color=never",
                "--monitor-address=127.0.0.1:0",
                "--sync.enable=false",
                "--rpc.enable=true",
                "--http-rpc=127.0.0.1:0",
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
                "--p2p.consensus.listen-on=/ip4/127.0.0.1/tcp/0",
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

        config.inject_failure.map(|i| {
            command
                .arg(i.as_cli_arg())
                .arg("--integration-tests.disable-db-verification=true")
        });

        let process = command
            .spawn()
            .context(format!("Spawning pathfinder process for {}", config.name))?;

        println!(
            "Pathfinder instance {:<7} (pid: {}) has been spawned",
            config.name,
            process.id()
        );

        let (rpc_port_watch_tx, rpc_port_watch_rx) = watch::channel(0u16);

        Ok(Self {
            process,
            name: config.name,
            monitor_port: AtomicU16::new(0),
            consensus_p2p_port: AtomicU16::new(0),
            rpc_port_watch_tx,
            rpc_port_watch_rx,
            db_dir,
            stdout_path,
            stderr_path,
            is_terminated: false,
        })
    }

    pub fn with_rpc_port_watch(
        mut self,
        (tx, rx): (watch::Sender<u16>, watch::Receiver<u16>),
    ) -> Self {
        self.rpc_port_watch_tx = tx;
        self.rpc_port_watch_rx = rx;
        self
    }

    /// Checks if the instance has exited with a non-zero exit code.
    pub fn exited_with_error(&mut self) -> anyhow::Result<bool> {
        match self.process.try_wait() {
            Ok(Some(status)) if !status.success() => {
                self.is_terminated = true;
                Ok(true)
            }
            Ok(Some(_)) | Ok(None) => {
                self.is_terminated = true;
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!(
                "Error checking if Pathfinder instance {} (pid: {}) has exited: {e}",
                self.name,
                self.process.id()
            )),
        }
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
            let pid = self.process.id();
            let (monitor_port, rpc_port, p2p_port) = tokio::join!(
                Self::wait_for_port(pid, "monitor", &self.db_dir, poll_interval),
                Self::wait_for_port(pid, "rpc", &self.db_dir, poll_interval),
                Self::wait_for_port(pid, "p2p_consensus", &self.db_dir, poll_interval),
            );
            let monitor_port = monitor_port?;
            self.monitor_port.store(monitor_port, Ordering::Relaxed);
            self.rpc_port_watch_tx.send(rpc_port?)?;
            self.consensus_p2p_port.store(p2p_port?, Ordering::Relaxed);

            loop {
                match reqwest::get(format!("http://127.0.0.1:{monitor_port}/ready")).await {
                    Ok(response) if response.status() == StatusCode::OK => {
                        println!(
                            "Pathfinder instance {:<7} ready after {} s",
                            self.name,
                            stopwatch.elapsed().as_secs()
                        );
                        return anyhow::Ok(());
                    }
                    _ => println!("Pathfinder instance {:<7} not ready yet", self.name),
                }

                sleep(poll_interval).await;
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                anyhow::bail!(
                    "Timeout waiting for Pathfinder instance {} to be ready",
                    self.name
                )
            }
        }
    }

    async fn wait_for_port(
        pid: u32,
        port_name: &str,
        db_dir: &Path,
        poll_interval: Duration,
    ) -> anyhow::Result<u16> {
        let port_file = db_dir.join(format!("pid_{pid}_{port_name}_port"));
        loop {
            match tokio::fs::read_to_string(&port_file).await {
                Ok(port_str) => {
                    let port = port_str
                        .trim()
                        .parse::<u16>()
                        .context(format!("Parsing port value in {}", port_file.display()))?;
                    return Ok(port);
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    // File not found yet, continue polling.
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Error reading port file {}: {e}",
                        port_file.display()
                    ));
                }
            }

            sleep(poll_interval).await;
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn rpc_port_watch_rx(&self) -> watch::Receiver<u16> {
        self.rpc_port_watch_rx.clone()
    }

    pub fn rpc_port_watch(&self) -> (watch::Sender<u16>, watch::Receiver<u16>) {
        (
            self.rpc_port_watch_tx.clone(),
            self.rpc_port_watch_rx.clone(),
        )
    }

    pub fn consensus_p2p_port(&self) -> u16 {
        self.consensus_p2p_port.load(Ordering::Relaxed)
    }

    fn terminate(&mut self) {
        if self.is_terminated {
            println!(
                "Pathfinder instance {:<7} (pid: {}) has already exited",
                self.name,
                self.process.id()
            );
            return;
        }

        println!(
            "Pathfinder instance {:<7} (pid: {}) terminating...",
            self.name,
            self.process.id()
        );

        _ = Command::new("kill")
            // It's supposed to be the default signal in `kill`, but let's be explicit.
            .arg("-TERM")
            .arg(self.process.id().to_string())
            .status();

        // See if SIGTERM worked.
        match self.process.try_wait() {
            Ok(Some(status)) => {
                println!(
                    "Pathfinder instance {:<7} (pid: {}) terminated with status: {status}",
                    self.name,
                    self.process.id()
                );
            }
            Ok(None) => match self.process.wait() {
                Ok(status) => {
                    println!(
                        "Pathfinder instance {:<7} (pid: {}) terminated with status: {status}",
                        self.name,
                        self.process.id()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Error waiting for Pathfinder instance {:<7} (pid: {}) to terminate: {e}",
                        self.name,
                        self.process.id(),
                    );
                    if let Err(error) = self.process.kill() {
                        eprintln!(
                            "Error killing Pathfinder instance {:<7} (pid: {}): {error}",
                            self.name,
                            self.process.id(),
                        );
                    }
                }
            },
            Err(e) => {
                eprintln!(
                    "Error terminating Pathfinder instance {:<7} (pid: {}): {e}",
                    self.name,
                    self.process.id(),
                );
                if let Err(error) = self.process.kill() {
                    eprintln!(
                        "Error killing Pathfinder instance {:<7} (pid: {}): {error}",
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

fn create_log_file(config: &Config, stdout_path: &Path) -> Result<File, anyhow::Error> {
    let stdout_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(stdout_path)
        .context(format!(
            "Creating log file {} for Pathfinder instance {}",
            stdout_path.display(),
            config.name
        ))?;
    Ok(stdout_file)
}

impl Drop for PathfinderInstance {
    fn drop(&mut self) {
        self.terminate();

        if DUMP_LOGS_ON_DROP.load(std::sync::atomic::Ordering::Relaxed) {
            let stdout = std::fs::read_to_string(&self.stdout_path)
                .unwrap_or("Error reading file".to_string());
            println!("Pathfinder instance {:<7} stdout log:\n{stdout}", self.name);
            let stderr = std::fs::read_to_string(&self.stderr_path)
                .unwrap_or("Error reading file".to_string());
            println!("Pathfinder instance {:<7} stderr log:\n{stderr}", self.name);
        }
    }
}

static DUMP_LOGS_ON_DROP: AtomicBool = AtomicBool::new(true);

impl Config {
    const NAMES: &'static [&'static str] = &[
        "Alice", "Bob", "Charlie", "Dan", "Eve", "Frank", "Grace", "Heidi",
    ];

    /// The first node will always be the boot node.
    pub fn for_set(
        set_size: usize,
        pathfinder_bin: &Path,
        fixture_dir: &Path,
        test_dir: &Path,
    ) -> Vec<Self> {
        assert!(
            set_size <= Self::NAMES.len(),
            "Max {} instances supported",
            Self::NAMES.len()
        );
        (0..set_size)
            .map(|i| Self {
                name: Self::NAMES[i],
                boot_port: None,
                my_validator_address: (i + 1) as u8,
                // The set is deduplicated when consensus task is started, so including the own
                // validator address is fine.
                validator_addresses: (1..=set_size as u8).collect::<Vec<_>>(),
                test_dir: test_dir.to_path_buf(),
                pathfinder_bin: pathfinder_bin.to_path_buf(),
                fixture_dir: fixture_dir.to_path_buf(),
                inject_failure: None,
            })
            .collect()
    }

    pub fn with_inject_failure(mut self, inject_failure: Option<InjectFailure>) -> Self {
        self.inject_failure = inject_failure;
        self
    }

    pub fn with_boot_port(mut self, port: u16) -> Self {
        self.boot_port = Some(port);
        self
    }
}

impl InjectFailure {
    pub fn as_cli_arg(&self) -> String {
        match self {
            Self::OnProposalRx(n) => {
                format!("--integration-tests.inject-failure.on-proposal-rx={n}")
            }
            Self::_OnProposalDecided(n) => {
                format!("--integration-tests.inject-failure.on-proposal-decided={n}")
            }
        }
    }
}

/// A guard that aborts the task when dropped.
pub struct AbortGuard {
    jh: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl From<JoinHandle<anyhow::Result<()>>> for AbortGuard {
    fn from(jh: JoinHandle<anyhow::Result<()>>) -> Self {
        Self { jh }
    }
}

/// Monitors `instance` for exit with non-zero exit code. If that happens,
/// respawns the instance with `config` and waits for it to be ready. The
/// respawned instance is not returned, but it will be kept alive until the end
/// of the test (i.e., until `test_timeout` is reached).
pub fn respawn_on_fail(
    mut instance: PathfinderInstance,
    config: Config,
    ready_poll_interval: Duration,
    ready_timeout: Duration,
    test_timeout: Duration,
) -> AbortGuard {
    let mut child_signal = signal(SignalKind::child()).unwrap();

    tokio::spawn(async move {
        if child_signal.recv().await.is_some() {
            println!("Got SIGCHLD!");
            match instance.exited_with_error() {
                Ok(true) => {
                    println!("Respawning {}...", instance.name());
                    let watch = instance.rpc_port_watch();
                    drop(instance);
                    let instance = PathfinderInstance::spawn(config)?.with_rpc_port_watch(watch);
                    instance
                        .wait_for_ready(ready_poll_interval, ready_timeout)
                        .await?;
                    println!("{} is ready again", instance.name());
                    // Let the instance exist for the rest of the test.
                    tokio::time::sleep(test_timeout).await;
                }
                Ok(false) => {
                    println!("{} exited cleanly, not respawning", instance.name());
                    drop(instance);
                }
                Err(e) => {
                    eprintln!("Error checking if {} exited cleanly: {e}", instance.name());
                    // Assume that the process did not exit, the worst that can
                    // happen is that the kill on drop will fail.
                }
            }
        }

        Ok(())
    })
    .into()
}
