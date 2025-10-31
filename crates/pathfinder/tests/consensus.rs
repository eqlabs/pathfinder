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
    use pathfinder_lib::config::integration_testing::{InjectFailureConfig, InjectFailureTrigger};
    use rstest::rstest;

    use crate::common::pathfinder_instance::{respawn_on_fail, PathfinderInstance};
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
    // -----
    // FIXME these pass when run individually, but fail when run together
    // -----
    #[case::fail_on_proposal_init_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalInitRx }))]
    #[case::fail_on_batch_info_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::BlockInfoRx }))]
    #[case::fail_on_transaction_batch_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::TransactionBatchRx }))]
    #[case::fail_on_transactions_fin_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::TransactionsFinRx }))]
    #[case::fail_on_proposal_commitment_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalCommitmentRx }))]
    #[case::fail_on_proposal_fin_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalFinRx }))]
    // TODO this sometime passes when run together
    #[case::fail_on_entire_proposal_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::EntireProposalRx }))]
    // TODO this sometime passes when run together
    #[case::fail_on_entire_proposal_persisted(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::EntireProposalPersisted }))]
    // -----
    // FIXME All pass up to this point if run individually
    // -----
    // TODO this one fails even when run individually [why?]
    #[case::fail_on_prevote_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::PrevoteRx }))]
    // TODO this one fails even when run individually [why?]
    #[case::fail_on_precommit_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::PrecommitRx }))]
    // TODO this one fails even when run individually, because we don't have proper proposal
    // recovery yet
    #[case::fail_on_proposal_decided(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalDecided }))]
    // TODO this one fails when run together, even though it should pass
    #[case::fail_on_proposal_committed(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalCommitted }))]
    #[tokio::test]
    async fn consensus_3_nodes(
        #[case] inject_failure: Option<InjectFailureConfig>,
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
