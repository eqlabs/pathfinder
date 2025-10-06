//! Build pathfinder in debug:
//! ```
//! cargo build -p pathfinder --bin pathfinder -F p2p
//! ```
//!
//! Run the test:
//! ```
//! cargo test --test consensus_smoke -p pathfinder -F p2p -- --nocapture
//! ```

#[cfg(feature = "p2p")]
mod common;

#[cfg(feature = "p2p")]
mod test {
    use std::time::{Duration, Instant};

    use anyhow::Context;
    use tokio::time::sleep;

    use super::common::pathfinder_instance::{
        fixture_dir,
        pathfinder_bin,
        Config,
        PathfinderInstance,
    };
    use super::common::rpc_client::wait_for_height;

    // If the env variable `PATHFINDER_CONSENSUS_TEST_DUMP_CHILD_LOGS_ON_FAIL` is
    // set, the stdout and stderr logs of each Pathfinder instance will be
    // dumped automatically to the parent process descriptors if the test fails.
    // Otherwise you need to inspect the temporary directory that is created to
    // hold the test artifacts.
    #[tokio::test]
    async fn consensus_3_node_smoke_test() -> anyhow::Result<()> {
        PathfinderInstance::enable_log_dump(
            std::env::var_os("PATHFINDER_CONSENSUS_TEST_DUMP_CHILD_LOGS_ON_FAIL").is_some(),
        );

        const NUM_NODES: usize = 3;
        const MIN_REQUIRED_DECIDED_HEIGHT: u64 = 20;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
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

        assert!(pathfinder_bin.exists(), "Pathfinder binary not found");
        assert!(fixture_dir.exists(), "Fixture directory not found");

        let mut configs =
            Config::for_set(NUM_NODES, &pathfinder_bin, &fixture_dir, test_dir.path()).into_iter();

        let alice = PathfinderInstance::spawn(configs.next().unwrap())?;
        alice
            .wait_for_ready(READY_POLL_INTERVAL, READY_TIMEOUT)
            .await?;

        let bob = PathfinderInstance::spawn(configs.next().unwrap())?;
        let charlie = PathfinderInstance::spawn(configs.next().unwrap())?;

        let (bob_rdy, charlie_rdy) = tokio::join!(
            bob.wait_for_ready(READY_POLL_INTERVAL, READY_TIMEOUT),
            charlie.wait_for_ready(READY_POLL_INTERVAL, READY_TIMEOUT)
        );
        bob_rdy?;
        charlie_rdy?;

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

        let alice_client = spawn_rpc_client(alice.rpc_port());
        let bob_client = spawn_rpc_client(bob.rpc_port());
        let charlie_client = spawn_rpc_client(charlie.rpc_port());

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
                // Don't dump logs if the test succeeded.
                PathfinderInstance::enable_log_dump(false);
                Ok(())
            }

            _ = tokio::signal::ctrl_c() => {
                eprintln!("Received Ctrl-C, terminating test early");
                Err(anyhow::anyhow!("Test interrupted by user"))
            }
        };

        test_result
    }
}
