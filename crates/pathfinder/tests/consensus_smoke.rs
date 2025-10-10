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
    mod consensus_3_nodes {
        use std::time::Duration;
        use std::vec;

        use anyhow::Context;
        use tokio::task::JoinError;
        use tokio::time::sleep;

        use crate::common::pathfinder_instance::{respawn_on_fail, PathfinderInstance};
        use crate::common::rpc_client::wait_for_height;
        use crate::common::utils;

        // If the env variable `PATHFINDER_CONSENSUS_TEST_DUMP_CHILD_LOGS_ON_FAIL` is
        // set, the stdout and stderr logs of each Pathfinder instance will be
        // dumped automatically to the parent process descriptors if the test fails.
        // Otherwise you need to inspect the temporary directory that is created to
        // hold the test artifacts.
        #[tokio::test]
        async fn happy_path() -> anyhow::Result<()> {
            const NUM_NODES: usize = 3;
            const HEIGHT: u64 = 20;
            const READY_TIMEOUT: Duration = Duration::from_secs(20);
            const TEST_TIMEOUT: Duration = Duration::from_secs(120);
            const POLL_READY: Duration = Duration::from_millis(500);
            const POLL_HEIGHT: Duration = Duration::from_secs(1);

            let (configs, stopwatch) = utils::setup(NUM_NODES)?;
            let mut configs = configs.into_iter();

            let alice = PathfinderInstance::spawn(configs.next().unwrap())?;
            alice.wait_for_ready(POLL_READY, READY_TIMEOUT).await?;

            let bob_cfg = configs.next().unwrap();

            let bob = PathfinderInstance::spawn(bob_cfg.clone())?;
            let charlie = PathfinderInstance::spawn(configs.next().unwrap())?;

            let (bob_rdy, charlie_rdy) = tokio::join!(
                bob.wait_for_ready(POLL_READY, READY_TIMEOUT),
                charlie.wait_for_ready(POLL_READY, READY_TIMEOUT)
            );
            bob_rdy?;
            charlie_rdy?;

            utils::log_elapsed(stopwatch);

            let alice_client = wait_for_height(&alice, HEIGHT, POLL_HEIGHT);
            let bob_client = wait_for_height(&bob, HEIGHT, POLL_HEIGHT);
            let charlie_client = wait_for_height(&charlie, HEIGHT, POLL_HEIGHT);

            let _guard = respawn_on_fail(bob, bob_cfg, POLL_READY, READY_TIMEOUT, TEST_TIMEOUT);

            tokio::select! {
                _ = sleep(TEST_TIMEOUT) => {
                    eprintln!("Test timed out after {TEST_TIMEOUT:?}");
                    Err(anyhow::anyhow!("Test timed out after {TEST_TIMEOUT:?}"))
                }

                test_result = futures::future::join_all(vec![alice_client, bob_client, charlie_client]) => {
                    test_result.into_iter().collect::<Result<Vec<_>, JoinError>>().context("Joining all RPC client tasks")?;

                    // Don't dump logs if the test succeeded.
                    PathfinderInstance::enable_log_dump(false);
                    Ok(())
                }

                _ = tokio::signal::ctrl_c() => {
                    eprintln!("Received Ctrl-C, terminating test early");
                    Err(anyhow::anyhow!("Test interrupted by user"))
                }
            }
        }
    }
}
