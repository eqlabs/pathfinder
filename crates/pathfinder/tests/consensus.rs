//! Build pathfinder in debug:
//! ```
//! cargo build -p pathfinder --bin pathfinder -F p2p -F integration-testing
//! ```
//!
//! Run the test:
//! ```
//! cargo test --test consensus -p pathfinder -F p2p -F integration-testing -- --nocapture
//! ```

#[cfg(feature = "p2p")]
mod common;

#[cfg(feature = "p2p")]
mod test {
    mod consensus_3_nodes {
        use std::time::Duration;
        use std::vec;

        use rstest::rstest;

        use crate::common::pathfinder_instance::{
            respawn_on_fail,
            InjectFailure,
            PathfinderInstance,
        };
        use crate::common::rpc_client::wait_for_height;
        use crate::common::utils;

        #[rstest]
        #[case::happy_path(None)]
        // #[case::fail_on_proposal_rx(Some(InjectFailure2::OnProposalRx(12)))]
        // #[case::fail_on_proposal_decided(InjectFailure2::OnProposalDecided(12))]
        #[tokio::test]
        async fn test_test(#[case] inject_failure: Option<InjectFailure>) -> anyhow::Result<()> {
            const NUM_NODES: usize = 3;
            // System contracts start to matter after block 10
            const HEIGHT: u64 = 15;
            const READY_TIMEOUT: Duration = Duration::from_secs(20);
            const TEST_TIMEOUT: Duration = Duration::from_secs(120);
            const POLL_READY: Duration = Duration::from_millis(500);
            const POLL_HEIGHT: Duration = Duration::from_secs(1);

            let (configs, stopwatch) = utils::setup(NUM_NODES)?;
            let mut configs = configs.into_iter();

            let alice = PathfinderInstance::spawn(configs.next().unwrap())?;
            alice.wait_for_ready(POLL_READY, READY_TIMEOUT).await?;

            let bob_cfg = configs.next().unwrap().with_inject_failure(inject_failure);

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

            let _maybe_guard = match inject_failure {
                Some(i) => Some(respawn_on_fail(
                    bob,
                    bob_cfg,
                    POLL_READY,
                    READY_TIMEOUT,
                    TEST_TIMEOUT,
                )),
                None => None,
            };

            utils::wait_for_test_end(vec![alice_client, bob_client, charlie_client], TEST_TIMEOUT)
                .await
        }
    }
}
