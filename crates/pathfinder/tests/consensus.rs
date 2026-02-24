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

    use futures::StreamExt;
    use pathfinder_lib::config::integration_testing::{InjectFailureConfig, InjectFailureTrigger};
    use rstest::rstest;

    use crate::common::feeder_gateway::FeederGateway;
    use crate::common::pathfinder_instance::{respawn_on_fail2, PathfinderInstance};
    use crate::common::rpc_client::{
        get_cached_artifacts_info,
        get_consensus_info,
        wait_for_block_exists,
        wait_for_height,
    };
    use crate::common::utils;

    // TODO Test cases that should be supported by the integration tests:
    // - proposals:
    //   - [x] non-empty proposals (L1 handlers + transactions that modify storage):
    //      - ProposalInit,
    //      - BlockInfo,
    //      - TransactionBatch(/*Non-empty vec of transactions*/),
    //      - ExecutedTransactionCount,
    //      - ProposalFin,
    //   - [ ] empty proposals, which follow the spec, ie. no transaction batches:
    //      - ProposalInit,
    //      - ProposalFin,
    // - node set sizes:
    //   - [x] 3 nodes, network stalls if 1 node fails,
    //   - [x] 4 nodes, network continues if 1 node fails, catchup via sync
    //     mechanism is activated (`fourth_node_joins_late_can_catch_up` is
    //     sufficient here),
    // - [x] failure injection (tests recovery from crashes/terminations at
    //   different stages),
    // - [ ] ??? any missing significant failure injection points ???.
    #[rstest]
    #[case::happy_path(None)]
    #[case::fail_on_proposal_init_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ProposalInitRx }))]
    #[case::fail_on_block_info_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::BlockInfoRx }))]
    #[case::fail_on_transaction_batch_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::TransactionBatchRx }))]
    #[case::fail_on_executed_transaction_count_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ExecutedTransactionCountRx }))]
    #[case::fail_on_proposal_fin_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ProposalFinRx }))]
    #[case::fail_on_proposal_finalized(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ProposalFinalized }))]
    #[case::fail_on_prevote_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::PrevoteRx }))]
    #[case::fail_on_precommit_rx(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::PrecommitRx }))]
    #[case::fail_on_proposal_decided(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ProposalDecided }))]
    #[case::fail_on_proposal_committed(Some(InjectFailureConfig { height: 4, trigger: InjectFailureTrigger::ProposalCommitted }))]
    #[tokio::test]
    async fn consensus_3_nodes_with_failures(#[case] inject_failure: Option<InjectFailureConfig>) {
        use tokio::sync::mpsc;

        const NUM_NODES: usize = 3;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
        const TEST_TIMEOUT: Duration = Duration::from_secs(120);
        const POLL_READY: Duration = Duration::from_millis(500);
        const POLL_HEIGHT: Duration = Duration::from_secs(1);

        // Happy path is the only scenario which starts consensus from genesis at the
        // expense of all transactions being reverted since they're random, invalid L1
        // handlers.
        let (configs, boot_height, stopwatch) = utils::setup(NUM_NODES, false).unwrap();
        // utils::setup(NUM_NODES, inject_failure.is_some()).unwrap();

        // System contracts start to matter after block 10 but we have a separate
        // regression test for that, which checks that rollback at H>10 works correctly.
        let target_height: u64 = boot_height + 5;

        let alice_cfg = configs.first().unwrap();
        let mut fgw = FeederGateway::spawn(alice_cfg).unwrap();
        fgw.wait_for_ready(POLL_READY, READY_TIMEOUT).await.unwrap();

        // We want everybody to have sync enabled so that not only Alice, Bob, and
        // Charlie decide upon the new blocks but also they are able to **commit the
        // blocks to their main DBs**. The trick is that MOST OF THE TIME the FGw will
        // not provide any meaningful data to the 3 nodes because it's feeding
        // off of Alice's DB which means it'll always be lagging behind the
        // nodes that achieve consensus. However in reality, the FGw, will be sometimes
        // able to provide some blocks to Bob or Charlie faster than they themselves
        // acquire a positive decision from their consensus engines.
        //
        // Additionally, dummy proposal creation relies on the parent block being
        // committed to the main DB, so sync needs to be enabled for that as well.
        let mut configs = configs.into_iter().map(|cfg| {
            cfg.with_local_feeder_gateway(fgw.port())
                .with_sync_enabled()
        });

        let alice = PathfinderInstance::spawn(configs.next().unwrap()).unwrap();
        alice
            .wait_for_ready(POLL_READY, READY_TIMEOUT)
            .await
            .unwrap();

        let boot_port = alice.consensus_p2p_port();
        let mut configs = configs.map(|cfg| cfg.with_boot_port(boot_port));

        let bob_cfg = configs.next().unwrap().with_inject_failure(inject_failure);

        let bob = PathfinderInstance::spawn(bob_cfg.clone()).unwrap();
        let charlie = PathfinderInstance::spawn(configs.next().unwrap()).unwrap();

        let (bob_rdy, charlie_rdy) = tokio::join!(
            bob.wait_for_ready(POLL_READY, READY_TIMEOUT),
            charlie.wait_for_ready(POLL_READY, READY_TIMEOUT)
        );
        bob_rdy.unwrap();
        charlie_rdy.unwrap();

        utils::log_elapsed(stopwatch);

        let (tx, rx) = mpsc::channel(target_height as usize * 3);
        let rx = tokio_stream::wrappers::ReceiverStream::new(rx);

        let alice_decided = wait_for_height(&alice, target_height, POLL_HEIGHT, Some(tx));
        let bob_decided = wait_for_height(&bob, target_height, POLL_HEIGHT, None);
        let charlie_decided = wait_for_height(&charlie, target_height, POLL_HEIGHT, None);
        let alice_committed = wait_for_block_exists(&alice, target_height, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, target_height, POLL_HEIGHT);
        let charlie_committed = wait_for_block_exists(&charlie, target_height, POLL_HEIGHT);

        let maybe_bob = respawn_on_fail2(
            inject_failure.is_some(),
            bob,
            bob_cfg,
            POLL_READY,
            READY_TIMEOUT,
        );

        utils::join_all(
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
        .await
        .unwrap();

        let decided_hnrs = rx.collect::<Vec<_>>().await;
        if let Some(x) = decided_hnrs.iter().find(|hnr| hnr.round() > 0) {
            println!("Network failed to recover in round 0 at (h:r): {x}");
        }

        let alice_artifacts = get_cached_artifacts_info(&alice, target_height)
            .await
            .unwrap();
        assert!(
            alice_artifacts.is_empty(),
            "Alice should not have leftover cached consensus data: {alice_artifacts:#?}"
        );

        if let Some(bob) = maybe_bob.instance() {
            let bob_artifacts = get_cached_artifacts_info(&bob, target_height)
                .await
                .unwrap();
            assert!(
                bob_artifacts.is_empty(),
                "Bob should not have leftover cached consensus data after respawn: \
                 {bob_artifacts:#?}"
            );
        }

        let charlie_artifacts = get_cached_artifacts_info(&charlie, target_height)
            .await
            .unwrap();
        assert!(
            charlie_artifacts.is_empty(),
            "Charlie should not have leftover cached consensus data: {charlie_artifacts:#?}"
        );
    }

    #[tokio::test]
    async fn consensus_3_nodes_fourth_node_joins_late_can_catch_up() {
        const NUM_NODES: usize = 4;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
        const RUNUP_TIMEOUT: Duration = Duration::from_secs(60);
        const CATCHUP_TIMEOUT: Duration = Duration::from_secs(60);
        const POLL_READY: Duration = Duration::from_millis(500);
        const POLL_HEIGHT: Duration = Duration::from_secs(1);

        let (configs, boot_height, stopwatch) = utils::setup(NUM_NODES, true).unwrap();

        // System contracts start to matter after block 10
        let height_to_add_fourth_node: u64 = boot_height + 3;
        let target_height: u64 = height_to_add_fourth_node + 2;

        let alice_cfg = configs.first().unwrap();
        let mut fgw = FeederGateway::spawn(alice_cfg).unwrap();
        fgw.wait_for_ready(POLL_READY, READY_TIMEOUT).await.unwrap();

        // We want everybody to have sync enabled so that not only Alice, Bob, and
        // Charlie decide upon the new blocks but also they are able to **commit the
        // blocks to their main DBs**. The trick is that MOST OF THE TIME the FGw will
        // not provide any meaningful data to the 3 nodes because it's feeding
        // off of Alice's DB which means it'll always be lagging behind the
        // nodes that achieve consensus. However in reality, the FGw, will be sometimes
        // able to provide some blocks to Bob or Charlie faster than they themselves
        // acquire a positive decision from their consensus engines.
        //
        // This means that initially Dan will be actually syncing from the FGw until he
        // catches up with the other nodes, at which point he should be committing the
        // consensus-decided blocks to his own main DB, before actually sync is able to
        // get them from the FGw.
        //
        // Additionally, dummy proposal creation relies on the parent block being
        // committed to the main DB, so sync needs to be enabled for that as well.
        let mut configs = configs.into_iter().map(|cfg| {
            cfg.with_local_feeder_gateway(fgw.port())
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

        // Use channels to send and update the rpc port
        let alice_decided = wait_for_height(&alice, height_to_add_fourth_node, POLL_HEIGHT, None);
        let bob_decided = wait_for_height(&bob, height_to_add_fourth_node, POLL_HEIGHT, None);
        let charlie_decided =
            wait_for_height(&charlie, height_to_add_fourth_node, POLL_HEIGHT, None);
        let alice_committed = wait_for_block_exists(&alice, height_to_add_fourth_node, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, height_to_add_fourth_node, POLL_HEIGHT);
        let charlie_committed =
            wait_for_block_exists(&charlie, height_to_add_fourth_node, POLL_HEIGHT);

        utils::join_all(
            vec![
                alice_decided,
                bob_decided,
                charlie_decided,
                alice_committed,
                bob_committed,
                charlie_committed,
            ],
            RUNUP_TIMEOUT,
        )
        .await
        .unwrap();

        let dan_cfg = configs.next().unwrap().with_sync_enabled();

        let dan = PathfinderInstance::spawn(dan_cfg.clone()).unwrap();
        dan.wait_for_ready(POLL_READY, READY_TIMEOUT).await.unwrap();

        let alice_decided = wait_for_height(&alice, target_height, POLL_HEIGHT, None);
        let bob_decided = wait_for_height(&bob, target_height, POLL_HEIGHT, None);
        let charlie_decided = wait_for_height(&charlie, target_height, POLL_HEIGHT, None);
        let dan_decided = wait_for_height(&dan, target_height, POLL_HEIGHT, None);
        let alice_committed = wait_for_block_exists(&alice, target_height, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, target_height, POLL_HEIGHT);
        let charlie_committed = wait_for_block_exists(&charlie, target_height, POLL_HEIGHT);
        let dan_committed = wait_for_block_exists(&dan, target_height, POLL_HEIGHT);

        utils::join_all(
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
            CATCHUP_TIMEOUT,
        )
        .await
        .unwrap();

        let alice_artifacts = get_cached_artifacts_info(&alice, target_height)
            .await
            .unwrap();
        assert!(
            alice_artifacts.is_empty(),
            "Alice should not have leftover cached consensus data: {alice_artifacts:#?}"
        );

        let bob_artifacts = get_cached_artifacts_info(&bob, target_height)
            .await
            .unwrap();
        assert!(
            bob_artifacts.is_empty(),
            "Bob should not have leftover cached consensus data: {bob_artifacts:#?}"
        );

        let charlie_artifacts = get_cached_artifacts_info(&charlie, target_height)
            .await
            .unwrap();
        assert!(
            charlie_artifacts.is_empty(),
            "Charlie should not have leftover cached consensus data: {charlie_artifacts:#?}"
        );

        let dan_artifacts = get_cached_artifacts_info(&dan, target_height)
            .await
            .unwrap();
        assert!(
            dan_artifacts.is_empty(),
            "Dan should not have leftover cached consensus data: {dan_artifacts:#?}"
        );
    }

    /// A slightly different failure scenario from
    /// [consensus_3_nodes_with_failures]. We are not causing the process to
    /// exit but instead forcing nodes to send outdated votes which leads to
    /// them being punished by their peers (via peer score penalties).
    #[tokio::test]
    async fn consensus_3_nodes_outdated_votes_lead_to_peer_score_changes() {
        const NUM_NODES: usize = 3;
        const READY_TIMEOUT: Duration = Duration::from_secs(20);
        const RUNUP_TIMEOUT: Duration = Duration::from_secs(60);
        const POLL_READY: Duration = Duration::from_millis(500);
        const POLL_HEIGHT: Duration = Duration::from_secs(1);

        let (configs, boot_blocks, stopwatch) = utils::setup(NUM_NODES, true).unwrap();

        let last_valid_height: u64 = boot_blocks + 5;

        let alice_cfg = configs.first().unwrap();
        let mut fgw = FeederGateway::spawn(alice_cfg).unwrap();
        fgw.wait_for_ready(POLL_READY, READY_TIMEOUT).await.unwrap();

        let inject_failure = InjectFailureConfig {
            // Starting from this height..
            height: last_valid_height + 1,
            // ..send outdated votes.
            trigger: InjectFailureTrigger::OutdatedVote,
        };
        // Do this for all three nodes, one of them will be picked to send a proposal
        // at last_valid_height + 1 and the other two will be the sabotaging nodes.
        let mut configs = configs.into_iter().map(|cfg| {
            cfg.with_inject_failure(Some(inject_failure))
                .with_local_feeder_gateway(fgw.port())
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

        // Wait until all three nodes reach `LAST_VALID_HEIGHT`..
        let alice_decided = wait_for_height(&alice, last_valid_height, POLL_HEIGHT, None);
        let bob_decided = wait_for_height(&bob, last_valid_height, POLL_HEIGHT, None);
        let charlie_decided = wait_for_height(&charlie, last_valid_height, POLL_HEIGHT, None);
        let alice_committed = wait_for_block_exists(&alice, last_valid_height, POLL_HEIGHT);
        let bob_committed = wait_for_block_exists(&bob, last_valid_height, POLL_HEIGHT);
        let charlie_committed = wait_for_block_exists(&charlie, last_valid_height, POLL_HEIGHT);

        utils::join_all(
            vec![
                alice_decided,
                bob_decided,
                charlie_decided,
                alice_committed,
                bob_committed,
                charlie_committed,
            ],
            RUNUP_TIMEOUT,
        )
        .await
        .unwrap();

        // ..then wait a bit more for the next height, which should never become decided
        // upon because one of the nodes is sabotaging the consensus network (sending
        // outdated votes) and getting punished by the other two nodes.
        let alice_decided = wait_for_height(&alice, last_valid_height + 1, POLL_HEIGHT, None);
        let bob_decided = wait_for_height(&bob, last_valid_height + 1, POLL_HEIGHT, None);
        let charlie_decided = wait_for_height(&charlie, last_valid_height + 1, POLL_HEIGHT, None);

        let err = utils::join_all(
            vec![alice_decided, bob_decided, charlie_decided],
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

        let alice_artifacts = get_cached_artifacts_info(&alice, last_valid_height)
            .await
            .unwrap();
        assert!(
            alice_artifacts.is_empty(),
            "Alice should not have leftover cached consensus data: {alice_artifacts:#?}"
        );

        let bob_artifacts = get_cached_artifacts_info(&bob, last_valid_height)
            .await
            .unwrap();
        assert!(
            bob_artifacts.is_empty(),
            "Bob should not have leftover cached consensus data: {bob_artifacts:#?}"
        );

        let charlie_artifacts = get_cached_artifacts_info(&charlie, last_valid_height)
            .await
            .unwrap();
        assert!(
            charlie_artifacts.is_empty(),
            "Charlie should not have leftover cached consensus data: {charlie_artifacts:#?}"
        );
    }

    async fn get_peer_score_changes(instance: &PathfinderInstance) -> anyhow::Result<u64> {
        let rpc_port = instance.rpc_port_watch().1.borrow().1;
        let reply = get_consensus_info(instance.name(), rpc_port).await?;
        let peer_score_changes = reply.result.peer_score_change_counter.unwrap_or_default();
        Ok(peer_score_changes)
    }
}
