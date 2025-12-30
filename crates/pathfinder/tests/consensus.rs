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

    use crate::common::feeder_gateway::FeederGateway;
    use crate::common::pathfinder_instance::{respawn_on_fail, PathfinderInstance};
    use crate::common::rpc_client::{get_consensus_info, wait_for_block_exists, wait_for_height};
    use crate::common::utils;

    // TODO Test cases that should be supported by the integration tests:
    // - proposals:
    //   - [ ] non-empty proposals (L1 handlers + transactions that modify storage):
    //      - ProposalInit,
    //      - BlockInfo,
    //      - TransactionBatch(/*Non-empty vec of transactions*/),
    //      - ExecutedTransactionCount,
    //      - ProposalFin,
    //   - [x] empty proposals, which follow the spec, ie. no transaction batches:
    //      - ProposalInit,
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
    #[ignore = "ExecutedTransactionCount is not currently present in fake proposals, so this test \
                is the same as the happy path right now."]
    #[case::fail_on_executed_transaction_count_rx(Some(InjectFailureConfig { height: 13, trigger: InjectFailureTrigger::ExecutedTransactionCountRx }))]
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

    // TODO(consensus)
    //
    // 1. Apparently the test waits until H=20 and H=13 for Dan, but in
    // fact consensus in all nodes reaches H=33 before the test finishes on my
    // (ie. Chris') machine
    //
    // 2. Change the test so that Dan actually catches up to the current
    // consensus height, whatever it is, this will require some custom FGW
    //
    // 3. IMPORTANT: assert that there is no leftover data for lower heights when
    //    Dan finally catches up
    #[tokio::test]
    async fn consensus_3_nodes_fourth_node_joins_late_can_catch_up() -> anyhow::Result<()> {
        const NUM_NODES: usize = 4;
        // System contracts start to matter after block 10
        const HEIGHT_TO_ADD_FOURTH_NODE: u64 = 15;
        const FINAL_HEIGHT: u64 = 20;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
        const TEST_TIMEOUT: Duration = Duration::from_secs(120);
        const POLL_READY: Duration = Duration::from_millis(500);
        const POLL_HEIGHT: Duration = Duration::from_secs(1);

        let (configs, stopwatch) = utils::setup(NUM_NODES)?;

        let alice_cfg = configs.first().unwrap();
        let mut _fgw = FeederGateway::spawn(&alice_cfg)?;
        _fgw.wait_for_ready(POLL_READY, READY_TIMEOUT).await?;

        // We want everybody to have sync enabled so that not only Alice, Bob, and
        // Charlie decide upon the new blocks but also they are able to **commit the
        // blocks to their main DBs**. The trick is that the FGw will not provide any
        // meaningful data to the 3 nodes because it's feeding off of Alice's DB which
        // means it'll always be lagging behind the nodes that achieve consensus.
        //
        // This means that initially Dan will be actually syncing from the FGw until he
        // catches up with the other nodes, at which point he should be committing the
        // consensus-decided blocks to his own main DB, before actually sync is able to
        // get them from the FGw.
        //
        // TODO !!! not only wait for decided upon but also committed to main DB
        let mut configs = configs.into_iter().map(|cfg| {
            cfg.with_local_feeder_gateway(_fgw.port())
                .with_sync_enabled()
        });
        let alice = PathfinderInstance::spawn(configs.next().unwrap())?;
        alice.wait_for_ready(POLL_READY, READY_TIMEOUT).await?;

        let boot_port = alice.consensus_p2p_port();
        let mut configs = configs.map(|cfg| cfg.with_boot_port(boot_port));

        let bob = PathfinderInstance::spawn(configs.next().unwrap())?;
        let charlie = PathfinderInstance::spawn(configs.next().unwrap())?;

        let (bob_rdy, charlie_rdy) = tokio::join!(
            bob.wait_for_ready(POLL_READY, READY_TIMEOUT),
            charlie.wait_for_ready(POLL_READY, READY_TIMEOUT)
        );
        bob_rdy?;
        charlie_rdy?;

        utils::log_elapsed(stopwatch);

        // Use channels to send and update the rpc port
        let alice_decided = wait_for_height(&alice, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);
        let bob_decided = wait_for_height(&bob, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);
        let charlie_decided = wait_for_height(&charlie, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);
        let alice_committed = wait_for_block_exists(&alice, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);
        let charlie_committed =
            wait_for_block_exists(&charlie, HEIGHT_TO_ADD_FOURTH_NODE, POLL_HEIGHT);

        utils::wait_for_test_end(
            vec![
                alice_decided,
                bob_decided,
                charlie_decided,
                alice_committed,
                bob_committed,
                charlie_committed,
            ],
            TEST_TIMEOUT,
        )
        .await?;

        let dan_cfg = configs.next().unwrap().with_sync_enabled();

        let dan = PathfinderInstance::spawn(dan_cfg.clone())?;
        dan.wait_for_ready(POLL_READY, READY_TIMEOUT).await?;

        let alice_decided = wait_for_height(&alice, FINAL_HEIGHT, POLL_HEIGHT);
        let bob_decided = wait_for_height(&bob, FINAL_HEIGHT, POLL_HEIGHT);
        let charlie_decided = wait_for_height(&charlie, FINAL_HEIGHT, POLL_HEIGHT);
        let alice_committed = wait_for_block_exists(&alice, FINAL_HEIGHT, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, FINAL_HEIGHT, POLL_HEIGHT);
        let charlie_committed = wait_for_block_exists(&charlie, FINAL_HEIGHT, POLL_HEIGHT);

        // Wait for a block that was decided before this node joined to be synced.
        // let dan_client = wait_for_block_exists(&dan, HEIGHT_TO_ADD_FOURTH_NODE - 2,
        // POLL_HEIGHT);
        let dan_decided = wait_for_height(&dan, FINAL_HEIGHT, POLL_HEIGHT);
        let dan_committed = wait_for_block_exists(&dan, FINAL_HEIGHT, POLL_HEIGHT);

        utils::wait_for_test_end(
            vec![
                alice_decided,
                bob_decided,
                charlie_decided,
                dan_decided,
                alice_committed,
                bob_committed,
                charlie_committed,
                dan_committed,
            ],
            TEST_TIMEOUT,
        )
        .await
    }

    /// A slightly different failure scenario from [consensus_3_nodes]. We are
    /// not causing the process to exit but instead forcing nodes to send
    /// outdated votes which leads to them being punished by their peers
    /// (via peer score penalties).
    #[rstest]
    #[ignore = "We need a custom fgw to actually test consensus ahead of fgw"]
    #[case::consensus_ahead_of_fgw(true)]
    #[case::fgw_ahead_of_consensus(false)]
    #[tokio::test]
    async fn consensus_3_nodes_outdated_votes_lead_to_peer_score_changes(
        #[case] consensus_ahead_of_fgw: bool,
    ) {
        const NUM_NODES: usize = 3;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
        const TEST_TIMEOUT: Duration = Duration::from_secs(60);
        const POLL_READY: Duration = Duration::from_millis(500);
        const POLL_HEIGHT: Duration = Duration::from_secs(1);

        const LAST_VALID_HEIGHT: u64 = 6;

        let (configs, stopwatch) = utils::setup(NUM_NODES).unwrap();

        let inject_failure = InjectFailureConfig {
            // Starting from this height..
            height: LAST_VALID_HEIGHT + 1,
            // ..send outdated votes.
            trigger: InjectFailureTrigger::OutdatedVote,
        };
        // Do this for all three nodes, one of them will be picked to send a proposal
        // at LAST_VALID_HEIGHT + 1 and the other two will be the sabotaging nodes.
        let mut configs = configs.into_iter().map(|cfg| {
            cfg.with_inject_failure(Some(inject_failure))
                .with_sync_enabled()
        });

        let alice = PathfinderInstance::spawn(configs.next().unwrap()).unwrap();
        alice
            .wait_for_ready(POLL_READY, READY_TIMEOUT)
            .await
            .unwrap();

        let boot_port = alice.consensus_p2p_port();
        let mut configs = configs.map(|cfg| cfg.with_boot_port(boot_port));

        let bob = PathfinderInstance::spawn(configs.next().unwrap()).unwrap();
        let charlie = PathfinderInstance::spawn(configs.next().unwrap()).unwrap();

        let (bob_rdy, charlie_rdy) = tokio::join!(
            bob.wait_for_ready(POLL_READY, READY_TIMEOUT),
            charlie.wait_for_ready(POLL_READY, READY_TIMEOUT)
        );

        bob_rdy.unwrap();
        charlie_rdy.unwrap();

        utils::log_elapsed(stopwatch);

        if consensus_ahead_of_fgw {
            // Wait until all three nodes reach `LAST_VALID_HEIGHT`..
            let alice_client = wait_for_height(&alice, LAST_VALID_HEIGHT, POLL_HEIGHT);
            let bob_client = wait_for_height(&bob, LAST_VALID_HEIGHT, POLL_HEIGHT);
            let charlie_client = wait_for_height(&charlie, LAST_VALID_HEIGHT, POLL_HEIGHT);

            utils::wait_for_test_end(vec![alice_client, bob_client, charlie_client], TEST_TIMEOUT)
                .await
                .unwrap();
        } else {
            // Sync will keep on downloading blocks from sepolia and consensus
            // will just stall at H=0, which we don't really care about as much
            // as we care about one of the nodes getting a penalty.
        }

        // ..then wait a bit more for the next height, which should never become decided
        // upon because one of the nodes is sabotaging the consensus network (sending
        // outdated votes) and getting punished by the other two nodes.
        let alice_client = wait_for_height(&alice, LAST_VALID_HEIGHT + 1, POLL_HEIGHT);
        let bob_client = wait_for_height(&bob, LAST_VALID_HEIGHT + 1, POLL_HEIGHT);
        let charlie_client = wait_for_height(&charlie, LAST_VALID_HEIGHT + 1, POLL_HEIGHT);

        let err = utils::wait_for_test_end(
            vec![alice_client, bob_client, charlie_client],
            POLL_HEIGHT * 10,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Test timed out"));

        let alice_peer_score_changes = get_peer_score_changes(&alice).await.unwrap();
        let bob_peer_score_changes = get_peer_score_changes(&bob).await.unwrap();
        let charlie_peer_score_changes = get_peer_score_changes(&charlie).await.unwrap();

        assert!(
            alice_peer_score_changes > 0
                || bob_peer_score_changes > 0
                || charlie_peer_score_changes > 0,
            "At least one node should have changed peer scores after punishing the sabotaging node"
        );
    }

    async fn get_peer_score_changes(instance: &PathfinderInstance) -> anyhow::Result<u64> {
        let rpc_port = instance.rpc_port_watch().1.borrow().1;
        let reply = get_consensus_info(instance.name(), rpc_port).await?;
        let peer_score_changes = reply.result.peer_score_change_counter.unwrap_or_default();
        Ok(peer_score_changes)
    }
}
