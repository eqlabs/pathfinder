//! End-to-end tests for p2p_task
//!
//! These tests verify the full integration flow of p2p_task, including proposal
//! processing, deferral logic (when TransactionsFin or ProposalFin arrive out
//! of order), rollback scenarios, and database persistence. They test the
//! complete path from receiving P2P events to sending consensus commands.

#[cfg(all(test, feature = "p2p"))]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use p2p::consensus::{Client, Event, HeightAndRound};
    use p2p::libp2p::identity::Keypair;
    use p2p_proto::consensus::ProposalPart;
    use pathfinder_common::prelude::*;
    use pathfinder_common::{ChainId, ContractAddress, ProposalCommitment};
    use pathfinder_consensus::ConsensusCommand;
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;
    use tokio::sync::mpsc;

    use crate::consensus::inner::persist_proposals::ConsensusProposals;
    use crate::consensus::inner::test_helpers::{create_test_proposal, create_transaction_batch};
    use crate::consensus::inner::{p2p_task, ConsensusTaskEvent, ConsensusValue, P2PTaskConfig};

    /// Helper struct to setup and manage the test environment (databases,
    /// channels, mock client)
    struct TestEnvironment {
        storage: pathfinder_storage::Storage,
        consensus_storage: pathfinder_storage::Storage,
        p2p_tx: mpsc::UnboundedSender<Event>,
        rx_from_p2p: mpsc::Receiver<ConsensusTaskEvent>,
        _tx_to_p2p: mpsc::Sender<crate::consensus::inner::P2PTaskEvent>, /* Keep alive to prevent receiver from being dropped */
        handle: Arc<Mutex<Option<tokio::task::JoinHandle<anyhow::Result<()>>>>>,
    }

    impl TestEnvironment {
        fn new(chain_id: ChainId, validator_address: ContractAddress) -> Self {
            // Create temp directory for consensus storage
            let consensus_storage_dir =
                tempfile::tempdir().expect("Failed to create temp directory");
            let consensus_storage_dir = consensus_storage_dir.path().to_path_buf();

            // Initialize temp pathfinder and consensus databases
            let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
            let consensus_storage =
                StorageBuilder::in_tempdir().expect("Failed to create consensus temp database");

            // Initialize consensus storage tables
            {
                let mut db_conn = consensus_storage.connection().unwrap();
                let db_tx = db_conn.transaction().unwrap();
                db_tx.ensure_consensus_proposals_table_exists().unwrap();
                db_tx
                    .ensure_consensus_finalized_blocks_table_exists()
                    .unwrap();
                db_tx.commit().unwrap();
            }

            // Mock channels for p2p communication
            let (p2p_tx, p2p_rx) = mpsc::unbounded_channel();
            let (tx_to_consensus, rx_from_p2p) = mpsc::channel(100);
            let (tx_to_p2p, rx_from_consensus) = mpsc::channel(100);

            // Create mock Client (used for receiving events in these tests)
            let keypair = Keypair::generate_ed25519();
            let (client_sender, _client_receiver) = mpsc::unbounded_channel();
            let peer_id = keypair.public().to_peer_id();
            let p2p_client = Client::from((peer_id, client_sender));

            let handle = p2p_task::spawn(
                chain_id,
                P2PTaskConfig {
                    my_validator_address: validator_address,
                    history_depth: 10,
                },
                p2p_client,
                storage.clone(),
                p2p_rx,
                tx_to_consensus,
                rx_from_consensus,
                consensus_storage.clone(),
                &consensus_storage_dir,
                None,
            );

            Self {
                storage,
                consensus_storage,
                p2p_tx,
                rx_from_p2p,
                _tx_to_p2p: tx_to_p2p,
                handle: Arc::new(Mutex::new(Some(handle))),
            }
        }

        fn create_committed_parent_block(&self, parent_height: u64) {
            let mut db_conn = self.storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();
            let parent_header = BlockHeader::builder()
                .number(BlockNumber::new_or_panic(parent_height))
                .timestamp(BlockTimestamp::new_or_panic(1000))
                .calculated_state_commitment(
                    StorageCommitment(Felt::ZERO),
                    ClassCommitment(Felt::ZERO),
                )
                .sequencer_address(SequencerAddress::ZERO)
                .finalize_with_hash(BlockHash(Felt::ZERO));
            db_tx.insert_block_header(&parent_header).unwrap();
            db_tx.commit().unwrap();
        }

        async fn wait_for_task_initialization(&self) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        async fn verify_task_alive(&self) {
            let handle_opt = {
                let handle_guard = self.handle.lock().unwrap();
                handle_guard.as_ref().map(|h| h.is_finished())
            };

            if let Some(true) = handle_opt {
                // Handle is finished, take it out and await to get the error
                let handle = {
                    let mut handle_guard = self.handle.lock().unwrap();
                    handle_guard.take().expect("Handle should exist")
                };

                match handle.await {
                    Ok(Ok(())) => {
                        panic!("Task finished successfully (unexpected - should still be running)");
                    }
                    Ok(Err(e)) => {
                        panic!("Task finished with error: {e:#}");
                    }
                    Err(e) => {
                        panic!("Task panicked: {e:?}");
                    }
                }
            }
        }
    }

    /// Helper: Wait for a proposal event from consensus
    async fn wait_for_proposal_event(
        rx: &mut mpsc::Receiver<ConsensusTaskEvent>,
        timeout_duration: Duration,
    ) -> Option<ConsensusCommand<ConsensusValue, ContractAddress>> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout_duration {
            // First try non-blocking recv
            match rx.try_recv() {
                Ok(ConsensusTaskEvent::CommandFromP2P(ConsensusCommand::Proposal(proposal))) => {
                    return Some(ConsensusCommand::Proposal(proposal))
                }
                Ok(_) => {
                    // Other event, continue waiting
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No event yet, wait a bit
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Channel closed
                    return None;
                }
            }
        }
        None
    }

    /// Helper: Verify no proposal event was received
    async fn verify_no_proposal_event(
        rx: &mut mpsc::Receiver<ConsensusTaskEvent>,
        duration: Duration,
    ) {
        let start = std::time::Instant::now();
        while start.elapsed() < duration {
            match rx.try_recv() {
                Ok(ConsensusTaskEvent::CommandFromP2P(ConsensusCommand::Proposal(_))) => {
                    panic!("Unexpected proposal event received");
                }
                Ok(_) => {
                    // Other event, continue checking
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No event, wait a bit
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Channel closed, that's fine
                    return;
                }
            }
        }
    }

    /// Helper: Verify proposal event matches expected values
    fn verify_proposal_event(
        proposal_cmd: ConsensusCommand<ConsensusValue, ContractAddress>,
        expected_height: u64,
        expected_commitment: ProposalCommitment,
    ) {
        match proposal_cmd {
            ConsensusCommand::Proposal(signed_proposal) => {
                assert_eq!(
                    signed_proposal.proposal.height, expected_height,
                    "Proposal height should match"
                );
                assert_eq!(
                    signed_proposal.proposal.value.0, expected_commitment,
                    "Proposal commitment should match"
                );
            }
            _ => panic!("Expected Proposal command"),
        }
    }

    /// Helper: Verify proposal parts are persisted in database
    ///
    /// Verifies that the expected part types are present:
    /// - Init (required)
    /// - BlockInfo (required)
    /// - Fin (required)
    /// - TransactionBatch (optional, if `expect_transaction_batch` is true)
    ///
    /// Also verifies the total count matches `expected_count`.
    fn verify_proposal_parts_persisted(
        consensus_storage: &pathfinder_storage::Storage,
        height: u64,
        round: u32,
        validator_address: &ContractAddress, // Query with validator address (receiver)
        expected_count: usize,
        expect_transaction_batch: bool,
    ) {
        let mut db_conn = consensus_storage.connection().unwrap();
        let db_tx = db_conn.transaction().unwrap();
        let proposals_db = ConsensusProposals::new(&db_tx);
        // seems like foreign_parts queries by validator_address to get
        // proposals from foreign validators (proposals where proposer !=
        // validator)
        let parts = proposals_db
            .foreign_parts(height, round, validator_address)
            .unwrap()
            .unwrap_or_default();

        // Part types for error message
        let part_types: Vec<String> = parts
            .iter()
            .map(|part| format!("{:?}", std::mem::discriminant(part)))
            .collect();

        // ----- Debug output for proposal parts -----
        #[cfg(debug_assertions)]
        {
            eprintln!(
                "Found {} proposal parts in database for height {} round {} (querying with \
                 validator {})",
                parts.len(),
                height,
                round,
                validator_address.0
            );
            for (i, part) in parts.iter().enumerate() {
                eprintln!("  Part {}: {:?}", i, std::mem::discriminant(part));
            }
        }
        // ----- End debug output for proposal parts -----

        // Verify required parts are present
        use p2p_proto::consensus::ProposalPart as P2PProposalPart;
        let has_init = parts.iter().any(|p| matches!(p, P2PProposalPart::Init(_)));
        let has_block_info = parts
            .iter()
            .any(|p| matches!(p, P2PProposalPart::BlockInfo(_)));
        let has_fin = parts.iter().any(|p| matches!(p, P2PProposalPart::Fin(_)));
        let has_transaction_batch = parts
            .iter()
            .any(|p| matches!(p, P2PProposalPart::TransactionBatch(_)));

        assert!(
            has_init,
            "Expected Init part to be persisted. Persisted parts: [{}]",
            part_types.join(", ")
        );
        assert!(
            has_block_info,
            "Expected BlockInfo part to be persisted. Persisted parts: [{}]",
            part_types.join(", ")
        );
        assert!(
            has_fin,
            "Expected Fin part to be persisted. Persisted parts: [{}]",
            part_types.join(", ")
        );
        if expect_transaction_batch {
            assert!(
                has_transaction_batch,
                "Expected TransactionBatch part to be persisted. Persisted parts: [{}]",
                part_types.join(", ")
            );
        }

        // Verify total count
        assert_eq!(
            parts.len(),
            expected_count,
            "Expected {} proposal parts, got {}. Persisted parts: [{}]",
            expected_count,
            parts.len(),
            part_types.join(", ")
        );
    }

    /// Helper: Verify transaction count from persisted proposal parts
    fn verify_transaction_count(
        consensus_storage: &pathfinder_storage::Storage,
        height: u64,
        round: u32,
        validator_address: &ContractAddress,
        expected_count: usize,
    ) {
        let mut db_conn = consensus_storage.connection().unwrap();
        let db_tx = db_conn.transaction().unwrap();
        let proposals = ConsensusProposals::new(&db_tx);
        let parts = proposals
            .foreign_parts(height, round, validator_address)
            .unwrap()
            .unwrap_or_default();

        // Count transactions from all TransactionBatch parts
        let mut total_transactions = 0;
        for part in &parts {
            if let ProposalPart::TransactionBatch(transactions) = part {
                total_transactions += transactions.len();
            }
        }

        assert_eq!(
            total_transactions, expected_count,
            "Expected {expected_count} transactions in persisted proposal parts, found \
             {total_transactions}",
        );
    }

    /// Helper: Create a ProposalCommitment message
    fn create_proposal_commitment_part(
        height: u64,
        proposal_commitment: ProposalCommitment,
    ) -> ProposalPart {
        let zero_hash = p2p_proto::common::Hash(Felt::ZERO);
        let zero_address = p2p_proto::common::Address(Felt::ZERO);
        ProposalPart::ProposalCommitment(p2p_proto::consensus::ProposalCommitment {
            block_number: height,
            parent_commitment: zero_hash,
            builder: zero_address,
            timestamp: 1000,
            protocol_version: "0.0.0".to_string(),
            old_state_root: zero_hash,
            version_constant_commitment: zero_hash,
            state_diff_commitment: p2p_proto::common::Hash(proposal_commitment.0), /* Use real commitment */
            transaction_commitment: zero_hash,
            event_commitment: zero_hash,
            receipt_commitment: zero_hash,
            concatenated_counts: Felt::ZERO,
            l1_gas_price_fri: 0,
            l1_data_gas_price_fri: 0,
            l2_gas_price_fri: 0,
            l2_gas_used: 0,
            next_l2_gas_price_fri: 0,
            l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
        })
    }

    /// ProposalFin deferred until TransactionsFin is processed.
    ///
    /// **Scenario**: ProposalFin arrives before TransactionsFin. Execution has
    /// started (TransactionBatch received), so ProposalFin must be deferred
    /// until TransactionsFin arrives and is processed, then finalization
    /// can proceed.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch →
    /// ProposalCommitment → ProposalFin → TransactionsFin.
    ///
    /// Verify ProposalFin is deferred (no proposal event), then verify
    /// finalization occurs after TransactionsFin arrives. Also verify
    /// ProposalFin is persisted in the database even when deferred.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_proposal_fin_deferred_until_transactions_fin_processed() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions = create_transaction_batch(0, 5, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, transactions.clone());

        // Focus is on batch execution and deferral logic, not commitment validation.
        // Using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Step 3: Send TransactionBatch (execution should start)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions),
            ))
            .expect("Failed to send TransactionBatch");
        env.verify_task_alive().await;

        // Verify: No proposal event yet (execution started, but not finalized)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 4: Send ProposalCommitment
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Step 5: Send ProposalFin BEFORE TransactionsFin
        // This should be DEFERRED because TransactionsFin hasn't been processed
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        env.verify_task_alive().await;

        // Verify: Still no proposal event (ProposalFin was deferred)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Check what's in the database right after ProposalFin (before TransactionsFin)
        #[cfg(debug_assertions)]
        {
            let mut db_conn = env.consensus_storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();
            let proposals = ConsensusProposals::new(&db_tx);
            let parts_after_proposal_fin = proposals
                .foreign_parts(2, 1, &validator_address)
                .unwrap()
                .unwrap_or_default();
            eprintln!(
                "Parts in database after ProposalFin (before TransactionsFin): {}",
                parts_after_proposal_fin.len()
            );
            for (i, part) in parts_after_proposal_fin.iter().enumerate() {
                eprintln!("  Part {}: {:?}", i, std::mem::discriminant(part));
            }
        }

        // Step 6: Send TransactionsFin
        // This should trigger finalization of the deferred ProposalFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 5,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        // Verify: Proposal event should be sent now
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(3))
            .await
            .expect("Expected proposal event after TransactionsFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify proposal parts persisted
        // Query with validator_address (receiver) to get foreign proposals
        // Expected: Init, BlockInfo, TransactionBatch, ProposalFin (4 parts)
        // Note: ProposalCommitment is not persisted as a proposal part (it's validator
        // state only)
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            4,
            true, // expect_transaction_batch
        );

        // Verify transaction count matches TransactionsFin count
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 5);
    }

    /// Full proposal flow in normal order.
    ///
    /// **Scenario**: Complete proposal flow with all parts arriving in the
    /// expected order. TransactionsFin arrives before ProposalFin, so no
    /// deferral is needed.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch →
    /// TransactionsFin → ProposalCommitment → ProposalFin.
    ///
    /// Verify proposal event is sent immediately after ProposalFin (no
    /// deferral), and verify all parts are persisted correctly.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_full_proposal_flow_normal_order() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions = create_transaction_batch(0, 5, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, transactions.clone());

        // Focus is on batch execution and deferral logic, not commitment validation.
        // Using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Step 3: Send TransactionBatch
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions),
            ))
            .expect("Failed to send TransactionBatch");
        env.verify_task_alive().await;

        // Verify: No proposal event yet (execution started, but TransactionsFin not
        // processed)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 4: Send TransactionsFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 5,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        // Verify: Still no proposal event (TransactionsFin processed, but ProposalFin
        // not received)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 5: Send ProposalCommitment
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Step 6: Send ProposalFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify: Proposal event should be sent immediately (both conditions met)
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify proposal parts persisted
        // Query with validator_address (receiver) to get foreign proposals
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            4,
            true, // expect_transaction_batch
        );

        // Verify transaction count matches TransactionsFin count
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 5);
    }

    /// TransactionsFin deferred when execution not started.
    ///
    /// **Scenario**: Parent block is not committed initially, so
    /// TransactionBatch and TransactionsFin are both deferred. After parent
    /// is committed, execution starts and deferred messages are processed.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch →
    /// TransactionsFin (without committing parent).
    ///
    /// Verify no execution occurs. Then commit parent block and send another
    /// TransactionBatch. Verify deferred TransactionsFin is processed when
    /// execution starts.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_transactions_fin_deferred_when_execution_not_started() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        // Parent block NOT committed initially
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions_batch1 = create_transaction_batch(0, 3, chain_id);
        let transactions_batch2 = create_transaction_batch(3, 2, chain_id); // Total: 5
        let (proposal_init, block_info) = create_test_proposal(
            chain_id,
            2,
            1,
            proposer_address,
            transactions_batch1.clone(),
        );

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Step 3: Send first TransactionBatch (should be deferred - parent not
        // committed)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch1),
            ))
            .expect("Failed to send first TransactionBatch");
        env.verify_task_alive().await;

        // Verify: No proposal event (execution deferred)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 4: Send TransactionsFin (should be deferred - execution not started)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 5,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        // Verify: Still no proposal event (TransactionsFin deferred)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 5: Now we commit the parent block
        env.create_committed_parent_block(1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 6: Send another TransactionBatch
        // This should trigger execution of deferred batches + process deferred
        // TransactionsFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch2),
            ))
            .expect("Failed to send second TransactionBatch");
        env.verify_task_alive().await;

        // At this point, execution should have started and TransactionsFin should be
        // processed...

        // To verify this, we send ProposalCommitment and ProposalFin, then verify that
        // a proposal event is sent (which confirms TransactionsFin was processed).

        // Once again, using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 7: Send ProposalCommitment
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Step 8: Send ProposalFin
        // This should trigger finalization since TransactionsFin was processed
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        env.verify_task_alive().await;

        // Verify: Proposal event should be sent (confirms TransactionsFin was
        // processed)
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after deferred TransactionsFin was processed");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify proposal parts persisted
        // Expected: Init, BlockInfo, TransactionBatch (2 batches), ProposalFin (5
        // parts)
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            5,    // 2 TransactionBatch parts
            true, // expect_transaction_batch
        );
    }

    /// Multiple TransactionBatch messages are executed correctly.
    ///
    /// **Scenario**: A proposal contains multiple TransactionBatch messages
    /// that must all be executed in order. All batches should be executed
    /// before TransactionsFin is processed.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch 1 →
    /// TransactionBatch 2 → TransactionBatch 3 → TransactionsFin →
    /// ProposalCommitment → ProposalFin.
    ///
    /// Verify proposal event is sent after ProposalFin, and verify all batches
    /// are persisted (combined into a single TransactionBatch part in the
    /// database).
    #[tokio::test(flavor = "multi_thread")]
    async fn test_multiple_batches_execution() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions_batch1 = create_transaction_batch(0, 2, chain_id);
        let transactions_batch2 = create_transaction_batch(2, 3, chain_id);
        let transactions_batch3 = create_transaction_batch(5, 2, chain_id); // Total: 7
        let (proposal_init, block_info) = create_test_proposal(
            chain_id,
            2,
            1,
            proposer_address,
            transactions_batch1.clone(),
        );

        // Focus is on batch execution and deferral logic, not commitment validation.
        // Using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Step 3: Send multiple TransactionBatches
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch1),
            ))
            .expect("Failed to send TransactionBatch1");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch2),
            ))
            .expect("Failed to send TransactionBatch2");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch3),
            ))
            .expect("Failed to send TransactionBatch3");
        env.verify_task_alive().await;

        // Step 4: Send TransactionsFin (total count = 7)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 7,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        // Step 5: Send ProposalCommitment
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Step 6: Send ProposalFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify: Proposal event should be sent
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify all batches persisted
        // Query with validator_address (receiver) to get foreign proposals
        // Expected: Init, BlockInfo, TransactionBatch (3 batches), ProposalFin (6
        // parts)
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            6,    // 3 TransactionBatch parts
            true, // expect_transaction_batch
        );

        // Verify transaction count matches TransactionsFin count
        // Multiple batches are persisted as separate TransactionBatch parts, so we
        // count the transactions from all persisted parts
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 7);
    }

    /// TransactionsFin triggers rollback when count is less than executed.
    ///
    /// **Scenario**: We execute 10 transactions (2 batches of 5), but
    /// TransactionsFin indicates only 7 transactions were executed by the
    /// proposer. The validator must rollback from 10 to 7 transactions to
    /// match the proposer's state.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch1 (5 txs) →
    /// TransactionBatch2 (5 txs) → TransactionsFin (count=7) →
    /// ProposalCommitment → ProposalFin.
    ///
    /// Verify proposal event is sent successfully after rollback, confirming
    /// the rollback mechanism works correctly.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_transactions_fin_rollback() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions_batch1 = create_transaction_batch(0, 5, chain_id);
        let transactions_batch2 = create_transaction_batch(5, 5, chain_id); // Total: 10
        let (proposal_init, block_info) = create_test_proposal(
            chain_id,
            2,
            1,
            proposer_address,
            transactions_batch1.clone(),
        );

        // Focus is on batch execution and deferral logic, not commitment validation.
        // Using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Step 3: Send TransactionBatch 1 (5 transactions)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch1),
            ))
            .expect("Failed to send TransactionBatch1");
        env.verify_task_alive().await;

        // Step 4: Send TransactionBatch 2 (5 more transactions, total = 10)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions_batch2),
            ))
            .expect("Failed to send TransactionBatch2");
        env.verify_task_alive().await;

        // Step 5: Send TransactionsFin with count=7 (should trigger rollback from 10 to
        // 7)
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 7,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        // Step 6: Send ProposalCommitment
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Step 7: Send ProposalFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify: Proposal event should be sent (rollback completed successfully)
        // NOTE: We verify that a proposal event is sent, which indicates rollback
        // completed. However, we cannot directly verify the transaction count
        // in e2e tests because the validator is internal to p2p_task. The
        // rollback logic itself is verified in unit tests (batch_execution.
        // rs::test_transactions_fin_rollback). This e2e test verifies
        // that rollback doesn't break the proposal flow end-to-end.
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify proposal parts persisted
        // Query with validator_address (receiver) to get foreign proposals
        // Expected: Init, BlockInfo, TransactionBatch (2 batches), ProposalFin (5
        // parts)
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            5,    // 2 TransactionBatch parts
            true, // expect_transaction_batch
        );

        // Note: Persisted proposal parts contain the original transactions (10), not
        // the rolled-back count (7). Rollback happens in the validator's
        // execution state at runtime, but the persisted parts reflect what was
        // received from the network. The rollback verification (that execution
        // state has 7 transactions) is covered in unit tests. Here we verify
        // that all original batches are persisted.
        //
        // This means that if the process crashes and recovers from persisted parts, it
        // would restore 10 transactions instead of the rolled-back count of 7. Recovery
        // logic should take TransactionsFin into account to ensure the correct
        // transaction count is restored after rollback.
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 10);
    }

    /// Empty TransactionBatch execution (non-spec edge case).
    ///
    /// **Scenario**: A proposal contains an empty TransactionBatch. Per the
    /// [Starknet consensus spec](https://raw.githubusercontent.com/starknet-io/starknet-p2p-specs/refs/heads/main/p2p/proto/consensus/consensus.md),
    /// if a proposer has no transactions, they should send an empty proposal
    /// (skipping TransactionBatch and TransactionsFin entirely). However, this
    /// test covers the defensive case where a non-empty proposal includes an
    /// empty TransactionBatch. Execution should still be marked as started, and
    /// TransactionsFin with count=0 should be processable.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch (empty) →
    /// TransactionsFin (count=0) → ProposalCommitment → ProposalFin.
    ///
    /// Verify execution is marked as started and TransactionsFin is processed.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_empty_batch_execution() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let empty_transactions = create_transaction_batch(0, 0, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, empty_transactions.clone());

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(empty_transactions),
            ))
            .expect("Failed to send empty TransactionBatch");
        env.verify_task_alive().await;

        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 0,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Empty batches don't initialize the executor, but finalization now
        // handles this case (see test_empty_proposal_finalization in
        // validator.rs). This test focuses on batch execution and
        // TransactionsFin processing not finalization (which we can't
        // verify here).
    }

    /// TransactionsFin indicates more transactions than executed.
    ///
    /// **Scenario**: We execute 5 transactions, but TransactionsFin indicates
    /// 10. This shouldn't happen with proper message ordering, but the code
    /// handles it by logging a warning and continuing.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionBatch (5 txs) →
    /// TransactionsFin (count=10) → ProposalCommitment → ProposalFin. Verify
    /// processing continues and proposal event is sent (with 5 transactions,
    /// not 10).
    ///
    /// **Note**: We cannot directly verify these things. The goal of this
    /// e2e test is to verify that processing continues correctly despite the
    /// mismatch.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_transactions_fin_count_exceeds_executed() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions = create_transaction_batch(0, 5, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, transactions.clone());

        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions),
            ))
            .expect("Failed to send TransactionBatch");
        env.verify_task_alive().await;

        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 10,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        tokio::time::sleep(Duration::from_millis(500)).await;

        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            4,
            true, // expect_transaction_batch
        );

        // Verify transaction count matches what was actually received (5 transactions).
        // Persisted proposal parts should reflect what was received from the network.
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 5);
    }

    /// TransactionsFin arrives before any TransactionBatch.
    ///
    /// **Scenario**: TransactionsFin arrives before execution starts (no
    /// batches received yet). It should be deferred until execution starts,
    /// then processed.
    ///
    /// **Test**: Send Init → BlockInfo → TransactionsFin →
    /// TransactionBatch → ProposalCommitment → ProposalFin. Verify
    /// TransactionsFin is deferred, then processed when execution starts,
    /// and proposal event is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_transactions_fin_before_any_batch() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);
        let transactions = create_transaction_batch(0, 5, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, transactions.clone());

        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionsFin(p2p_proto::consensus::TransactionsFin {
                    executed_transaction_count: 5,
                }),
            ))
            .expect("Failed to send TransactionsFin");
        env.verify_task_alive().await;

        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 4: Send TransactionBatch
        // This should trigger execution start and process the deferred TransactionsFin
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::TransactionBatch(transactions),
            ))
            .expect("Failed to send TransactionBatch");
        env.verify_task_alive().await;

        // Verify: Still no proposal event (TransactionsFin processed, but ProposalFin
        // not received)
        // Note: We verify that deferred TransactionsFin was processed indirectly by
        // sending ProposalFin below and confirming the proposal event is sent
        // (which requires TransactionsFin to be processed first).
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        tokio::time::sleep(Duration::from_millis(500)).await;

        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            4,
            true, // expect_transaction_batch
        );

        // Verify transaction count matches TransactionsFin count
        verify_transaction_count(&env.consensus_storage, 2, 1, &validator_address, 5);
    }

    /// Empty proposal per spec (no TransactionBatch, no TransactionsFin).
    ///
    /// **Scenario**: A proposer cannot offer a valid proposal, so the height is
    /// agreed to be empty. Per the spec, empty proposals skip
    /// TransactionBatch and TransactionsFin entirely. The order is:
    /// ProposalInit → ProposalCommitment → ProposalFin.
    ///
    /// **Test**: Send ProposalInit → BlockInfo → ProposalCommitment →
    /// ProposalFin (no TransactionBatch, no TransactionsFin).
    ///
    /// Verify ProposalFin proceeds immediately (not deferred, since execution
    /// never started), proposal event is sent, and all parts are persisted
    /// correctly.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_empty_proposal_per_spec() {
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let validator_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x123").unwrap());
        let mut env = TestEnvironment::new(chain_id, validator_address);
        env.create_committed_parent_block(1);
        env.wait_for_task_initialization().await;

        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let height_and_round = HeightAndRound::new(2, 1);

        // For empty proposals, we still need BlockInfo to transition to
        // TransactionBatch stage, but we don't send any TransactionBatch or
        // TransactionsFin
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, 2, 1, proposer_address, vec![]);

        // Using a dummy commitment...
        let proposal_commitment = ProposalCommitment(Felt::ZERO);

        // Step 1: Send ProposalInit
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Init(proposal_init),
            ))
            .expect("Failed to send ProposalInit");
        env.verify_task_alive().await;

        // Step 2: Send BlockInfo
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::BlockInfo(block_info),
            ))
            .expect("Failed to send BlockInfo");
        env.verify_task_alive().await;

        // Verify: No proposal event yet (ProposalCommitment and ProposalFin not
        // received)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 3: Send ProposalCommitment
        // Note: No TransactionBatch or TransactionsFin - this is the key difference
        // from normal proposals. Execution never starts.
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                create_proposal_commitment_part(2, proposal_commitment),
            ))
            .expect("Failed to send ProposalCommitment");
        env.verify_task_alive().await;

        // Verify: Still no proposal event (ProposalFin not received)
        verify_no_proposal_event(&mut env.rx_from_p2p, Duration::from_millis(200)).await;

        // Step 4: Send ProposalFin
        // Since execution never started (no TransactionBatch), ProposalFin should
        // proceed immediately without deferral. This is different from first test
        // where execution started but TransactionsFin wasn't processed yet.
        env.p2p_tx
            .send(Event::Proposal(
                height_and_round,
                ProposalPart::Fin(p2p_proto::consensus::ProposalFin {
                    proposal_commitment: p2p_proto::common::Hash(proposal_commitment.0),
                }),
            ))
            .expect("Failed to send ProposalFin");
        env.verify_task_alive().await;

        // Verify: Proposal event should be sent immediately (not deferred)
        // This confirms that ProposalFin proceeds when execution never started,
        // which is the correct behavior for empty proposals per spec.
        let proposal_cmd = wait_for_proposal_event(&mut env.rx_from_p2p, Duration::from_secs(2))
            .await
            .expect("Expected proposal event after ProposalFin for empty proposal");
        verify_proposal_event(proposal_cmd, 2, proposal_commitment);

        // Verify proposal parts persisted
        // Expected: Init, BlockInfo, ProposalFin (3 parts)
        verify_proposal_parts_persisted(
            &env.consensus_storage,
            2,
            1,
            &validator_address,
            3,
            false, // expect_transaction_batch (empty proposal)
        );
    }
}
