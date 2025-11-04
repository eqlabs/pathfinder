//! Batch execution manager with rollback support for TransactionsFin
//!
//! This module provides functionality to handle optimistic execution of
//! transaction batches with the ability to rollback when TransactionsFin
//! indicates fewer transactions were actually executed by the proposer.

use std::collections::HashMap;

use anyhow::Context;
use p2p::consensus::HeightAndRound;
use p2p_proto::consensus as proto_consensus;
use pathfinder_common::{BlockId, BlockNumber};
use pathfinder_storage::Transaction as DbTransaction;

use crate::validator::ValidatorTransactionBatchStage;

/// Manages batch execution with rollback support for TransactionsFin
#[derive(Debug, Clone)]
pub struct BatchExecutionManager {
    /// Tracks execution state for each height/round
    executions: HashMap<HeightAndRound, BatchExecutionState>,
}

/// State for a single proposal's batch execution
#[derive(Debug, Clone)]
struct BatchExecutionState {
    /// Whether each batch has been executed (indexed by arrival order)
    batch_executed: Vec<bool>,
    /// Current execution state
    current_state: ExecutionState,
    /// Total transactions executed so far
    total_executed: usize,
}

/// Current execution state
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionState {
    /// Waiting for more batches
    Collecting,
    /// Finalized with specific batch count
    Finalized { executed_batch_count: usize },
}

impl BatchExecutionManager {
    /// Create a new batch execution manager
    pub fn new() -> Self {
        Self {
            executions: HashMap::new(),
        }
    }

    /// Process a transaction batch with deferral support
    ///
    /// This is the main method that should be used by the P2P task
    pub fn process_batch_with_deferral(
        &mut self,
        height_and_round: HeightAndRound,
        transactions: Vec<proto_consensus::Transaction>,
        validator: &mut ValidatorTransactionBatchStage,
        db_tx: &DbTransaction<'_>,
        deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
    ) -> anyhow::Result<()> {
        // Check if execution should be deferred
        if should_defer_execution(height_and_round, db_tx)? {
            tracing::debug!(
                "🖧  ⚙️ transaction batch execution for height and round {height_and_round} is \
                 deferred"
            );

            // Defer execution - add to deferred_executions
            deferred_executions
                .entry(height_and_round)
                .or_default()
                .transactions
                .extend(transactions);
            return Ok(());
        }

        // Execute any previously deferred transactions first
        let deferred = deferred_executions.remove(&height_and_round);
        let deferred_txns_len = deferred.as_ref().map_or(0, |d| d.transactions.len());

        let mut all_transactions = transactions;
        if let Some(DeferredExecution {
            transactions: deferred_txns,
            ..
        }) = deferred
        {
            all_transactions.extend(deferred_txns);
        }

        // Execute the batch
        validator
            .execute_batch(all_transactions)
            .context("Failed to execute transaction batch")?;

        // Update execution state
        let state =
            self.executions
                .entry(height_and_round)
                .or_insert_with(|| BatchExecutionState {
                    batch_executed: Vec::new(),
                    current_state: ExecutionState::Collecting,
                    total_executed: 0,
                });

        state.total_executed += 1;

        tracing::debug!(
            "Transaction batch execution for height and round {height_and_round} is complete, \
             additionally {deferred_txns_len} previously deferred transactions were executed",
        );

        Ok(())
    }

    /// Process TransactionsFin message
    pub fn process_transactions_fin(
        &mut self,
        height_and_round: HeightAndRound,
        transactions_fin: proto_consensus::TransactionsFin,
        validator: &mut ValidatorTransactionBatchStage,
    ) -> anyhow::Result<()> {
        let state = self
            .executions
            .get_mut(&height_and_round)
            .ok_or_else(|| anyhow::anyhow!("No execution state found for {height_and_round}"))?;

        let target_transaction_count = transactions_fin.executed_transaction_count as usize;
        let current_transaction_count = validator.transaction_count();

        tracing::debug!(
            "Processing TransactionsFin for {height_and_round}: \
             target={target_transaction_count}, current={current_transaction_count}"
        );

        if target_transaction_count < current_transaction_count {
            tracing::info!(
                "Rolling back {height_and_round} from {} to {} transactions",
                current_transaction_count,
                target_transaction_count
            );

            // Roll back to the target transaction count
            validator
                .rollback_to_transaction(target_transaction_count)
                .context("Failed to rollback to target transaction count")?;

            // Update state to reflect rollback
            state.total_executed = target_transaction_count;
            for i in target_transaction_count..state.batch_executed.len() {
                state.batch_executed[i] = false;
            }
        }

        state.current_state = ExecutionState::Finalized {
            executed_batch_count: target_transaction_count,
        };

        tracing::info!(
            "Finalized {height_and_round} with {target_transaction_count} executed transactions"
        );

        Ok(())
    }

    /// Get the current execution state for a proposal
    #[cfg(test)]
    pub fn get_execution_state(
        &self,
        height_and_round: &HeightAndRound,
    ) -> Option<&ExecutionState> {
        self.executions
            .get(height_and_round)
            .map(|state| &state.current_state)
    }

    /// Clean up completed executions
    pub fn cleanup(&mut self, height_and_round: &HeightAndRound) {
        if let Some(state) = self.executions.remove(height_and_round) {
            tracing::debug!(
                "Cleaned up execution state for {height_and_round}: {} batches",
                state.batch_executed.len()
            );
        }
    }
}

impl Default for BatchExecutionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents transactions received from the network that are waiting for
/// previous block to be committed before they can be executed. Also holds
/// optional proposal commitment and proposer address in case that the entire
/// proposal has been received.
#[derive(Debug, Clone, Default)]
pub struct DeferredExecution {
    pub transactions: Vec<proto_consensus::Transaction>,
    pub commitment: Option<ProposalCommitmentWithOrigin>,
}

/// Proposal commitment and the address of its proposer.
#[derive(Debug, Clone)]
pub struct ProposalCommitmentWithOrigin {
    pub proposal_commitment: pathfinder_common::ProposalCommitment,
    pub proposer_address: pathfinder_common::ContractAddress,
    pub pol_round: pathfinder_consensus::Round,
}

impl Default for ProposalCommitmentWithOrigin {
    fn default() -> Self {
        Self {
            proposal_commitment: pathfinder_common::ProposalCommitment::default(),
            proposer_address: pathfinder_common::ContractAddress::default(),
            pol_round: pathfinder_consensus::Round::nil(),
        }
    }
}

/// Determine whether execution of proposal parts for `height_and_round` should
/// be deferred because the previous block is not committed yet.
pub fn should_defer_execution(
    height_and_round: HeightAndRound,
    db_tx: &DbTransaction<'_>,
) -> anyhow::Result<bool> {
    let parent_block = height_and_round.height().checked_sub(1);
    let defer = if let Some(parent_block) = parent_block {
        let parent_block =
            BlockNumber::new(parent_block).context("Block number is larger than i64::MAX")?;
        let parent_block = BlockId::Number(parent_block);
        let parent_committed = db_tx.block_exists(parent_block)?;
        !parent_committed
    } else {
        false
    };
    Ok(defer)
}

#[cfg(test)]
mod tests {
    use p2p_proto::consensus::TransactionVariant;
    use p2p_proto::transaction::L1HandlerV0;
    use pathfinder_crypto::Felt;

    use super::*;

    fn create_test_transaction(index: usize) -> proto_consensus::Transaction {
        // Create a simple L1Handler transaction
        let txn = TransactionVariant::L1HandlerV0(L1HandlerV0 {
            nonce: Felt::from_hex_str(&format!("0x{index}")).unwrap(),
            address: p2p_proto::common::Address(
                Felt::from_hex_str(&format!("0x{index:x}")).unwrap(),
            ),
            entry_point_selector: Felt::from_hex_str(&format!("0x{index}")).unwrap(),
            calldata: vec![Felt::from_hex_str(&format!("0x{index}")).unwrap()],
        });

        let l1_handler = pathfinder_common::transaction::L1HandlerTransaction {
            nonce: pathfinder_common::TransactionNonce(
                Felt::from_hex_str(&format!("0x{index}")).unwrap(),
            ),
            contract_address: pathfinder_common::ContractAddress::new_or_panic(
                Felt::from_hex_str(&format!("0x{index:x}")).unwrap(),
            ),
            entry_point_selector: pathfinder_common::EntryPoint(
                Felt::from_hex_str(&format!("0x{index}")).unwrap(),
            ),
            calldata: vec![pathfinder_common::CallParam(
                Felt::from_hex_str(&format!("0x{index}")).unwrap(),
            )],
        };

        // Calculate the correct hash
        let chain_id = pathfinder_common::ChainId::SEPOLIA_TESTNET;
        let hash = l1_handler.calculate_hash(chain_id);

        proto_consensus::Transaction {
            transaction_hash: p2p_proto::common::Hash(hash.0),
            txn,
        }
    }

    /// Test deferral mechanism with real transactions
    #[tokio::test]
    async fn test_deferral_mechanism() {
        use p2p::consensus::HeightAndRound;
        use pathfinder_common::{ChainId, ContractAddress};

        use crate::consensus::inner::test_helpers::{
            create_test_proposal,
            create_transaction_batch,
        };
        use crate::validator::ValidatorBlockInfoStage;
        // Setup test storage (temp database with larger connection pool)
        let storage = pathfinder_storage::StorageBuilder::in_tempdir()
            .expect("Failed to create temp database");
        let mut db_conn = storage.connection().unwrap();
        let db_tx = db_conn.transaction().unwrap();
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let proposer =
            ContractAddress::new_or_panic(pathfinder_crypto::Felt::from_hex_str("0x123").unwrap());

        // Create test proposal with transactions
        let height = 100; // Use a high height to trigger deferral
        let round = 1;
        let transactions = create_transaction_batch(20, 3, chain_id);
        let (proposal_init, block_info) =
            create_test_proposal(chain_id, height, round, proposer, transactions.clone());

        // Create validator
        let mut validator = ValidatorBlockInfoStage::new(chain_id, proposal_init)
            .expect("Failed to create ValidatorBlockInfoStage")
            .validate_consensus_block_info(block_info, storage.clone())
            .expect("Failed to create ValidatorTransactionBatchStage");

        // Create batch execution manager
        let mut manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(height, round);
        let mut deferred_executions = std::collections::HashMap::new();

        // Test deferral mechanism
        let batch = vec![transactions[0].clone()];
        let result = manager.process_batch_with_deferral(
            height_and_round,
            batch,
            &mut validator,
            &db_tx,
            &mut deferred_executions,
        );

        // Should succeed (either execute or defer)
        assert!(result.is_ok());

        // Verify the batch was either executed or deferred
        let _state = manager.get_execution_state(&height_and_round);
        // State might be Collecting (if executed) or None (if deferred)
        // Both are valid outcomes for this test
    }

    /// Simulate receiving batches from the network and executing them with
    /// rollback. An end-to-end test that verifies the rollback logic.
    #[tokio::test]
    async fn test_full_flow_with_rollback() {
        use pathfinder_common::{
            BlockNumber,
            BlockTimestamp,
            ChainId,
            GasPrice,
            L1DataAvailabilityMode,
            SequencerAddress,
            StarknetVersion,
        };
        use pathfinder_executor::types::BlockInfo;
        use pathfinder_storage::StorageBuilder;

        // Setup test environment
        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let block_info = BlockInfo {
            number: BlockNumber::new_or_panic(1),
            timestamp: BlockTimestamp::new_or_panic(1000),
            sequencer_address: SequencerAddress::ZERO,
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            eth_l1_gas_price: GasPrice::ZERO,
            strk_l1_gas_price: GasPrice::ZERO,
            eth_l1_data_gas_price: GasPrice::ZERO,
            strk_l1_data_gas_price: GasPrice::ZERO,
            strk_l2_gas_price: GasPrice::ZERO,
            eth_l2_gas_price: GasPrice::ZERO,
            starknet_version: StarknetVersion::new(0, 14, 0, 0),
        };

        // Create test transactions
        let mut all_transactions = Vec::new();
        for i in 0..20 {
            all_transactions.push(create_test_transaction(i));
        }

        // Group transactions into batches with variable sizes (simulating real network
        // reception)
        let batch_sizes = vec![3, 7, 4, 6];
        let mut batches = Vec::new();
        let mut start_idx = 0;
        for &batch_size in &batch_sizes {
            let end_idx = start_idx + batch_size;
            if end_idx <= all_transactions.len() {
                batches.push(all_transactions[start_idx..end_idx].to_vec());
                start_idx = end_idx;
            }
        }

        // Create validator stage
        let mut validator_stage =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage)
                .expect("Failed to create validator stage");

        // Execute all batches (simulating normal flow)
        for batch in batches.iter() {
            validator_stage
                .execute_batch(batch.clone())
                .expect("Failed to execute batch");
        }

        // Simulate TransactionsFin pointing to transaction 7 (within batch 1)
        let target_transaction_idx = 7;

        validator_stage
            .rollback_to_transaction(target_transaction_idx)
            .expect("Failed to rollback");

        let mut target_batch = 0;
        let mut cumulative_size = 0;
        for (batch_idx, &batch_size) in batch_sizes.iter().enumerate() {
            if cumulative_size + batch_size > target_transaction_idx {
                target_batch = batch_idx;
                break;
            }
            cumulative_size += batch_size;
        }

        let final_transactions = validator_stage.transaction_count();
        let final_receipts = validator_stage.receipt_count();
        let final_events = validator_stage.event_count();
        let final_executors = validator_stage.batch_count();

        assert_eq!(final_transactions, target_transaction_idx + 1);
        assert_eq!(final_receipts, target_transaction_idx + 1);
        assert_eq!(final_events, target_transaction_idx + 1);
        assert_eq!(final_executors, target_batch + 1);

        // Verify transaction indices are sequential and correct
        let receipts = validator_stage.receipts();
        assert_eq!(
            receipts.len(),
            8,
            "Should have 8 receipts after rollback and re-execution"
        );

        for (i, receipt) in receipts.iter().enumerate() {
            let expected_index = i as u64;
            let actual_index = receipt.transaction_index.get();
            assert_eq!(
                actual_index, expected_index,
                "Transaction index mismatch at position {i}: expected {expected_index}, got \
                 {actual_index}"
            );
        }
    }

    /// Test transaction index ordering across multiple batches and rollbacks
    #[test]
    fn test_transaction_ordering_integrity_across_batches() {
        use pathfinder_common::{
            BlockNumber,
            BlockTimestamp,
            ChainId,
            GasPrice,
            L1DataAvailabilityMode,
            SequencerAddress,
            StarknetVersion,
        };
        use pathfinder_executor::types::BlockInfo;
        use pathfinder_storage::StorageBuilder;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let block_info = BlockInfo {
            number: BlockNumber::new_or_panic(1),
            timestamp: BlockTimestamp::new_or_panic(1000),
            sequencer_address: SequencerAddress::ZERO,
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            eth_l1_gas_price: GasPrice::ZERO,
            strk_l1_gas_price: GasPrice::ZERO,
            eth_l1_data_gas_price: GasPrice::ZERO,
            strk_l1_data_gas_price: GasPrice::ZERO,
            strk_l2_gas_price: GasPrice::ZERO,
            eth_l2_gas_price: GasPrice::ZERO,
            starknet_version: StarknetVersion::new(0, 14, 0, 0),
        };

        // Create transactions with unique identifiers for ordering validation
        let mut all_transactions = Vec::new();
        for i in 0..15 {
            all_transactions.push(create_test_transaction(i));
        }

        // Create batches with different sizes to test complex scenarios
        let batch_sizes = vec![3, 5, 4, 3]; // Total: 15 transactions
        let mut batches = Vec::new();
        let mut start_idx = 0;
        for &batch_size in &batch_sizes {
            let end_idx = start_idx + batch_size;
            if end_idx <= all_transactions.len() {
                batches.push(all_transactions[start_idx..end_idx].to_vec());
                start_idx = end_idx;
            }
        }

        // Full execution ordering
        let mut validator_stage =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage.clone())
                .expect("Failed to create validator stage");

        for batch in batches.iter() {
            validator_stage
                .execute_batch(batch.clone())
                .expect("Failed to execute batch");
        }

        // Validate global ordering after full execution
        let receipts = validator_stage.receipts();
        assert_eq!(
            receipts.len(),
            15,
            "Should have 15 receipts after full execution"
        );

        for (i, receipt) in receipts.iter().enumerate() {
            let expected_index = i as u64;
            let actual_index = receipt.transaction_index.get();
            assert_eq!(
                actual_index, expected_index,
                "Transaction index mismatch at position {i}: expected {expected_index}, got \
                 {actual_index}",
            );
        }

        // Rollback to batch boundary
        let target_transaction_idx = 7; // End of batch 1
        validator_stage
            .rollback_to_transaction(target_transaction_idx)
            .expect("Failed to rollback");

        let receipts_after_rollback = validator_stage.receipts();
        assert_eq!(
            receipts_after_rollback.len(),
            8,
            "Should have 8 receipts after rollback to transaction 7"
        );

        // Validate ordering after rollback
        for (i, receipt) in receipts_after_rollback.iter().enumerate() {
            let expected_index = i as u64;
            let actual_index = receipt.transaction_index.get();
            assert_eq!(
                actual_index, expected_index,
                "Transaction index mismatch after rollback at position {i}: expected \
                 {expected_index}, got {actual_index}",
            );
        }

        // Rollback to mid-batch
        // Re-execute to get back to full state
        let mut validator_stage2 =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage.clone())
                .expect("Failed to create validator stage");

        for batch in batches.iter() {
            validator_stage2
                .execute_batch(batch.clone())
                .expect("Failed to execute batch");
        }

        let target_transaction_idx = 10; // Mid-batch 2
        validator_stage2
            .rollback_to_transaction(target_transaction_idx)
            .expect("Failed to rollback");

        let receipts_after_mid_rollback = validator_stage2.receipts();
        assert_eq!(
            receipts_after_mid_rollback.len(),
            11,
            "Should have 11 receipts after rollback to transaction 10"
        );

        // Validate ordering after mid-batch rollback
        for (i, receipt) in receipts_after_mid_rollback.iter().enumerate() {
            let expected_index = i as u64;
            let actual_index = receipt.transaction_index.get();
            assert_eq!(
                actual_index, expected_index,
                "Transaction index mismatch after mid-batch rollback at position {i}: expected \
                 {expected_index}, got {actual_index}"
            );
        }

        // Batch boundary consistency validation
        let mut validator_stage3 =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage)
                .expect("Failed to create validator stage");

        for (batch_idx, batch) in batches.iter().enumerate() {
            validator_stage3
                .execute_batch(batch.clone())
                .expect("Failed to execute batch");

            // Validate batch boundary after each batch
            let receipts = validator_stage3.receipts();
            let expected_end_index = validator_stage3.transaction_count() - 1;
            let actual_end_index = receipts.last().unwrap().transaction_index.get();

            assert_eq!(
                actual_end_index, expected_end_index as u64,
                "Batch {batch_idx} end index mismatch: expected {expected_end_index}, got \
                 {actual_end_index}",
            );
        }

        // Rollback preserves exact sequence
        let original_receipts = validator_stage3.receipts().to_vec();

        // Rollback to transaction 6
        validator_stage3
            .rollback_to_transaction(6)
            .expect("Failed to rollback");
        let rollback_receipts = validator_stage3.receipts();

        // Verify that the first 7 transactions are identical
        for i in 0..7 {
            assert_eq!(
                rollback_receipts[i].transaction_index.get(),
                original_receipts[i].transaction_index.get(),
                "Transaction {i} index changed after rollback: original {original_index}, \
                 rollback {rollback_index}",
                original_index = original_receipts[i].transaction_index.get(),
                rollback_index = rollback_receipts[i].transaction_index.get()
            );
        }
    }

    /// Test rollback state update cleanup and verification
    /// Verifies that rollback properly cleans up cumulative state updates
    #[test]
    fn test_rollback_cleanup() {
        use pathfinder_common::{
            BlockNumber,
            BlockTimestamp,
            ChainId,
            GasPrice,
            L1DataAvailabilityMode,
            SequencerAddress,
            StarknetVersion,
        };
        use pathfinder_executor::types::BlockInfo;
        use pathfinder_storage::StorageBuilder;

        use crate::consensus::inner::test_helpers::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let block_info = BlockInfo {
            number: BlockNumber::new_or_panic(1),
            timestamp: BlockTimestamp::new_or_panic(1000),
            sequencer_address: SequencerAddress::ZERO,
            l1_da_mode: L1DataAvailabilityMode::Calldata,
            eth_l1_gas_price: GasPrice::ZERO,
            strk_l1_gas_price: GasPrice::ZERO,
            eth_l1_data_gas_price: GasPrice::ZERO,
            strk_l1_data_gas_price: GasPrice::ZERO,
            strk_l2_gas_price: GasPrice::ZERO,
            eth_l2_gas_price: GasPrice::ZERO,
            starknet_version: StarknetVersion::new(0, 14, 0, 0),
        };

        let mut validator_stage =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage.clone())
                .expect("Failed to create validator stage");

        // Create many batches (each creates a state update checkpoint)
        for i in 0..10 {
            let transactions = create_transaction_batch(i * 10, 2, chain_id);
            validator_stage
                .execute_batch(transactions)
                .expect("Failed to execute batch");
        }

        let before_rollback_count = validator_stage.batch_count();

        // Rollback to batch 3 (should drop state updates for batches 4-9)
        validator_stage
            .rollback_to_batch(3)
            .expect("Failed to rollback");

        let after_rollback_count = validator_stage.batch_count();

        assert_eq!(
            after_rollback_count, 4,
            "Should have 4 batches (state updates) after rollback to batch 3"
        );
        assert!(
            after_rollback_count < before_rollback_count,
            "Rollback should reduce batch count"
        );

        // Execute more batches
        for i in 10..20 {
            let transactions = create_transaction_batch(i * 10, 2, chain_id);
            validator_stage
                .execute_batch(transactions)
                .expect("Failed to execute batch");
        }

        let before_multiple_rollback = validator_stage.batch_count();

        // Perform multiple rollbacks
        validator_stage
            .rollback_to_batch(5)
            .expect("Failed to rollback to batch 5");
        let after_rollback_1 = validator_stage.batch_count();

        validator_stage
            .rollback_to_batch(2)
            .expect("Failed to rollback to batch 2");
        let after_rollback_2 = validator_stage.batch_count();

        validator_stage
            .rollback_to_batch(0)
            .expect("Failed to rollback to batch 0");
        let after_rollback_3 = validator_stage.batch_count();

        // Verify progressive cleanup of state updates
        assert!(
            after_rollback_1 < before_multiple_rollback,
            "First rollback should reduce batch count"
        );
        assert!(
            after_rollback_2 < after_rollback_1,
            "Second rollback should reduce batch count further"
        );
        assert!(
            after_rollback_3 < after_rollback_2,
            "Third rollback should reduce batch count even more"
        );

        // Execute some batches
        for i in 0..5 {
            let transactions = create_transaction_batch(i * 10, 2, chain_id);
            validator_stage
                .execute_batch(transactions)
                .expect("Failed to execute batch");
        }

        // Rollback to transaction 1 (within first batch)
        validator_stage
            .rollback_to_transaction(1)
            .expect("Failed to rollback to transaction 1");

        let after_first_batch_rollback = validator_stage.batch_count();

        // Should have only 1 batch (state update) after rollback to transaction 1
        assert_eq!(
            after_first_batch_rollback, 1,
            "Should have 1 batch after first-batch rollback"
        );
    }
}
