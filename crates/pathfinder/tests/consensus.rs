//! Build pathfinder in debug:
//! ```
//! cargo build -p pathfinder --bin pathfinder -F p2p -F consensus-integration-tests
//! ```
//!
//! Run the test:
//! ```
//! PATHFINDER_TEST_ENABLE_PORT_MARKER_FILES=1 cargo nextest run --test consensus -p pathfinder --features p2p,consensus-integration-tests
//! ```
//!
//! # Important
//!
//! Please do not use `cargo test` as it does not run parallel test cases in
//! separate processes, and this will interfere with `PathfinderInstance` using
//! `SIGCHLD` to detect that a Pathfinder process has exited.

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
    //   - [ ] non-empty proposals (L1 handlers + transactions that modify storage):
    //      - ProposalInit,
    //      - BlockInfo,
    //      - TransactionBatch(/*Non-empty vec of transactions*/),
    //      - TransactionsFin,
    //      - ProposalCommitment,
    //      - ProposalFin,
    //   - [x] empty proposals, which follow the spec, ie. no transaction batches:
    //      - ProposalInit,
    //      - ProposalCommitment,
    //      - ProposalFin,
    // - node set sizes:
    //   - [x] 3 nodes, network stalls if 1 node fails,
    //   - [ ] 4 nodes, network continues if 1 node fails, catchup via sync
    //     mechanism is activated,
    // - [x] failure injection (tests recovery from crashes/terminations at
    //   different stages),
    // - [ ] ??? any missing significant failure injection points ???.
    #[rstest]
    #[case::happy_path(None)]
    // TODO Usually proposal parts at H=13 arrive before the local consensus engine emits a decided
    // upon event for H=12. The network moves to H=13, while locally H=12 is uncommitted, so
    // executing and thus committing H=13 locally is deferred indefinitely. With fully implemented
    // proposal recovery, this should be resolved.
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_proposal_init_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalInitRx }))]
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_block_info_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::BlockInfoRx }))]
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_transaction_batch_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::TransactionBatchRx }))]
    #[ignore = "TransactionsFin is not currently present in fake proposals, so this test is the \
                same as the happy path right now."]
    #[case::fail_on_transactions_fin_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::TransactionsFinRx }))]
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_proposal_commitment_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalCommitmentRx }))]
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_proposal_fin_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalFinRx }))]
    #[case::fail_on_entire_proposal_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::EntireProposalRx }))]
    #[case::fail_on_entire_proposal_persisted(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::EntireProposalPersisted }))]
    #[ignore = "TODO Determine why the test fails"]
    #[case::fail_on_prevote_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::PrevoteRx }))]
    #[ignore = "TODO Proposal recovery not fully implemented yet"]
    #[case::fail_on_precommit_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::PrecommitRx }))]
    #[ignore = "TODO Proposal recovery not fully implemented yet"]
    #[case::fail_on_proposal_decided(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ProposalDecided }))]
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
