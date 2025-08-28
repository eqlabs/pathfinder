//! Build pathfinder in debug:
//! ```
//! cargo build -p pathfinder --bin pathfinder -F p2p
//! ```
//!
//! Run the test:
//! ```
//! cargo test --test consensus_smoke -p pathfinder -F p2p -- --nocapture --ignored
//! ```

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::Context;
use http::StatusCode;
use serde::Deserialize;
use tokio::time::sleep;

#[ignore = "Sort out CI for this test, https://github.com/eqlabs/pathfinder/issues/2977"]
#[tokio::test]
async fn consensus_3_node_smoke_test() -> anyhow::Result<()> {
    const NUM_NODES: usize = 3;
    const MIN_REQUIRED_DECIDED_HEIGHT: u64 = 10;
    const TEST_TIMEOUT: Duration = Duration::from_secs(120);
    const READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
    const HEIGHT_POLL_INTERVAL: Duration = Duration::from_secs(1);

    let stopwatch = Instant::now();

    let pathfinder_bin = pathfinder_bin();
    let fixture_dir = fixture_dir();
    let test_dir = tempfile::Builder::new()
        .disable_cleanup(true)
        .tempdir()
        .context("Creating temporary directory for test artifacts")?;
    println!(
        "Test artifacts will be stored in {}",
        test_dir.path().display()
    );

    let mut configs =
        Config::for_set(NUM_NODES, &pathfinder_bin, &fixture_dir, test_dir.path()).into_iter();

    // Alice is the boot node, so we want her up and running first.
    let alice = PathfinderInstance::spawn(configs.next().unwrap())?;
    alice.wait_for_ready(READY_POLL_INTERVAL).await;

    let bob = PathfinderInstance::spawn(configs.next().unwrap())?;
    let charlie = PathfinderInstance::spawn(configs.next().unwrap())?;

    tokio::join!(
        bob.wait_for_ready(READY_POLL_INTERVAL),
        charlie.wait_for_ready(READY_POLL_INTERVAL)
    );

    let spawn_rpc_client = |rpc_port| {
        tokio::spawn(wait_for_height(
            rpc_port,
            MIN_REQUIRED_DECIDED_HEIGHT,
            HEIGHT_POLL_INTERVAL,
        ))
    };

    println!(
        "All RPC clients and nodes spawned and ready after {} s",
        stopwatch.elapsed().as_secs()
    );

    let alice_client = spawn_rpc_client(alice.rpc_port);
    let bob_client = spawn_rpc_client(bob.rpc_port);
    let charlie_client = spawn_rpc_client(charlie.rpc_port);

    let test_result = tokio::select! {
        _ = sleep(TEST_TIMEOUT) => {
            eprintln!("Test timed out after {TEST_TIMEOUT:?}");
            Err(anyhow::anyhow!("Test timed out after {TEST_TIMEOUT:?}"))
        }

        test_result = async {
            tokio::join!(alice_client, bob_client, charlie_client)
        } => {
            let (a, b, c) = test_result;
            a.context("Joining Alice's RPC client task")?;
            b.context("Joining Bob's RPC client task")?;
            c.context("Joining Charlie's RPC client task")?;
            Ok(())
        }

        _ = tokio::signal::ctrl_c() => {
            eprintln!("Received Ctrl-C, terminating test early");
            Err(anyhow::anyhow!("Test interrupted by user"))
        }
    };

    alice.terminate()?;
    bob.terminate()?;
    charlie.terminate()?;

    test_result
}

async fn wait_for_height(rpc_port: u16, height: u64, poll_interval: Duration) {
    loop {
        // Sleeping first actually makes sense here, because the node will likely not
        // have any decided heights immediately after the RPC server is ready.
        sleep(poll_interval).await;

        let Ok(reply) = reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{rpc_port}/rpc/pathfinder/unstable"
            ))
            .body(r#"{"jsonrpc":"2.0","id":0,"method":"pathfinder_consensusInfo","params":[]}"#)
            .header("Content-Type", "application/json")
            .send()
            .await
        else {
            println!("Node on port {rpc_port} not responding yet");
            continue;
        };

        let Reply {
            result: Height {
                highest_decided_height,
            },
        } = reply.json::<Reply>().await.unwrap();

        println!("Node on port {rpc_port} highest_decided_height: {highest_decided_height:?}");

        if let Some(highest_decided_height) = highest_decided_height {
            if highest_decided_height >= height {
                return;
            }
        }
    }
}

#[derive(Deserialize)]
struct Reply {
    result: Height,
}

#[derive(Deserialize)]
struct Height {
    highest_decided_height: Option<u64>,
}

struct PathfinderInstance {
    process: Child,
    name: &'static str,
    monitor_port: u16,
    rpc_port: u16,
}

#[derive(Debug, Clone)]
struct Config<'a> {
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
    fn spawn(config: Config<'_>) -> anyhow::Result<Self> {
        let id_file = config.fixture_dir.join(format!("id_{}.json", config.name));
        let db_file = config.test_dir.join(format!("db-{}", config.name));
        let stdout_file = File::create(config.test_dir.join(format!("{}_stdout.log", config.name)))
            .context(format!(
                "Creating stdout log file for pathfinder instance {}",
                config.name
            ))?;
        let stderr_file = File::create(config.test_dir.join(format!("{}_stderr.log", config.name)))
            .context(format!(
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
                "--consensus.proposer-address=0x1",
                format!(
                    "--consensus.my-validator-address=0x{}",
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

        let process = command
            .spawn()
            .context(format!("Spawning pathfinder process for {}", config.name))?;
        Ok(Self {
            process,
            name: config.name,
            monitor_port: config.monitor_port,
            rpc_port: config.rpc_port,
        })
    }

    async fn wait_for_ready(&self, poll_interval: Duration) {
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
    }

    fn terminate(mut self) -> anyhow::Result<()> {
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
                        "Error waiting for Pathfinder instance {} (pid: {}) to terminate: {}",
                        self.name,
                        self.process.id(),
                        e
                    );
                    self.process.kill().context(format!(
                        "Killing Pathfinder instance {} (pid: {})",
                        self.name,
                        self.process.id()
                    ))?;
                }
            },
            Err(e) => {
                eprintln!(
                    "Error terminating Pathfinder instance {} (pid: {}): {}",
                    self.name,
                    self.process.id(),
                    e
                );
                self.process.kill().context(format!(
                    "Killing Pathfinder instance {} (pid: {})",
                    self.name,
                    self.process.id()
                ))?;
            }
        }

        Ok(())
    }
}

impl<'a> Config<'a> {
    const NAMES: &'static [&'static str] = &[
        "Alice", "Bob", "Charlie", "Dan", "Eve", "Frank", "Grace", "Heidi",
    ];

    /// The first node will always be the boot node.
    fn for_set(
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

fn pathfinder_bin() -> PathBuf {
    let mut path = manifest_dir_path();
    assert!(path.pop());
    assert!(path.pop());
    path.push("target");
    path.push("debug");
    path.push("pathfinder");
    path
}

fn fixture_dir() -> PathBuf {
    let mut path = manifest_dir_path();
    path.push("tests");
    path.push("fixtures");
    path
}

fn manifest_dir_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
}
