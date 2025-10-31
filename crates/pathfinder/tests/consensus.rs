//! Build pathfinder in debug:
//! ```
//! cargo build -p pathfinder --bin pathfinder -F p2p -F consensus-integration-tests
//! ```
//!
//! Run the test:
//! ```
//! cargo test --test consensus -p pathfinder -F p2p -F consensus-integration-tests -- --nocapture
//! ```

#[cfg(all(feature = "p2p", feature = "consensus-integration-tests"))]
mod common;

#[cfg(all(feature = "p2p", feature = "consensus-integration-tests"))]
mod test {
    use std::time::Duration;
    use std::vec;

    use futures::future::Either;
    use rstest::rstest;

    use crate::common::pathfinder_instance::{respawn_on_fail, InjectFailure, PathfinderInstance};
    use crate::common::rpc_client::wait_for_height;
    use crate::common::utils;

    // TODO Test cases that should be supported by the integration tests:
    // - proposals:
    //   - non-empty proposals (L1 handlers + transactions that modify storage),
    //   - empty proposals, which follow the spec, ie. no transaction batches:
    //      - ProposalInit,
    //      - ProposalCommitment,
    //      - ProposalFin,
    //   - consider supporting empty proposals with an empty transaction batch, not
    //     fully following the spec:
    //      - ProposalInit,
    //      - BlockInfo,
    //      - TransactionBatch([]),
    //      - TransactionsFin,
    //      - ProposalCommitment,
    //      - ProposalFin,
    // - node set sizes:
    //   - 3 nodes, network stalls if 1 node fails,
    //   - 4 nodes, network continues if 1 node fails, catchup via sync mechanism is
    //     activated,
    // - failure injection (tests recovery from crashes/terminations at different
    //   stages):
    //   - none (happy path),
    //   - fail on the first part of a proposal received,
    //   - fail before transactions fin received,
    //   - fail before proposal fin received,
    //   - fail on proposal decided but not committed,
    //   - fail on proposal committed,
    //   - fail on prevote received,
    //   - fail on precommit received.
    #[rstest]
    #[case::happy_path(None)]
    #[case::fail_on_proposal_rx(Some(InjectFailure::OnProposalRx(12)))]
    // TODO this test currently fails because the node doesn't properly recover proposals that
    // were decided but not committed before crashing.
    // #[case::fail_on_proposal_decided(Some(InjectFailure::_OnProposalDecided(12)))]
    #[tokio::test]
    async fn consensus_3_nodes(
        #[case] inject_failure: Option<InjectFailure>,
    ) -> anyhow::Result<()> {
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

        let boot_port = alice.consensus_p2p_port();
        let mut configs = configs.map(|cfg| cfg.with_boot_port(boot_port));

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

        // Use channels to send and update of the rpc port
        let alice_client = wait_for_height(&alice, HEIGHT, POLL_HEIGHT);
        let bob_client = wait_for_height(&bob, HEIGHT, POLL_HEIGHT);
        let charlie_client = wait_for_height(&charlie, HEIGHT, POLL_HEIGHT);

        // Either to work around clippy: "manual implementation of `Option::map`"
        let _maybe_guard = match inject_failure {
            Some(_) => Either::Left(respawn_on_fail(
                bob,
                bob_cfg,
                POLL_READY,
                READY_TIMEOUT,
                TEST_TIMEOUT,
            )),
            None => Either::Right(bob),
        };

        utils::wait_for_test_end(vec![alice_client, bob_client, charlie_client], TEST_TIMEOUT).await
    }
}
