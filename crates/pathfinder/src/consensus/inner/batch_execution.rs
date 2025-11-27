//! Batch execution manager with rollback support for TransactionsFin
//!
//! This module provides functionality to handle optimistic execution of
//! transaction batches with the ability to rollback when TransactionsFin
//! indicates fewer transactions were actually executed by the proposer.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use p2p::consensus::HeightAndRound;
use p2p_proto::consensus as proto_consensus;
use pathfinder_common::{BlockId, BlockNumber};
use pathfinder_executor::BlockExecutorExt;
use pathfinder_storage::Transaction as DbTransaction;

use crate::validator::{TransactionMapper, ValidatorTransactionBatchStage};

/// Manages batch execution with rollback support for TransactionsFin
#[derive(Debug, Clone)]
pub struct BatchExecutionManager {
    /// Tracks which proposals (height/round) have started execution.
    /// An entry exists here if at least one batch has been executed (not
    /// deferred).
    executing: HashSet<HeightAndRound>,
    /// Tracks which proposals (height/round) have had TransactionsFin
    /// processed. An entry exists here if TransactionsFin has been
    /// successfully processed for this height/round.
    transactions_fin_processed: HashSet<HeightAndRound>,
}

impl BatchExecutionManager {
    /// Create a new batch execution manager
    pub fn new() -> Self {
        Self {
            executing: HashSet::new(),
            transactions_fin_processed: HashSet::new(),
        }
    }

    /// Check if execution has started for the given height and round
    ///
    /// Returns `true` if at least one batch has been executed (not deferred)
    /// for this height/round.
    pub fn is_executing(&self, height_and_round: &HeightAndRound) -> bool {
        self.executing.contains(height_and_round)
    }

    /// Check if TransactionsFin has been processed for the given height and
    /// round
    ///
    /// Returns `true` if TransactionsFin has been successfully processed
    /// for this height/round.
    pub fn is_transactions_fin_processed(&self, height_and_round: &HeightAndRound) -> bool {
        self.transactions_fin_processed.contains(height_and_round)
    }

    /// Check if ProposalFin should be deferred for the given height and round
    ///
    /// ProposalFin should be deferred if execution has started but
    /// TransactionsFin hasn't been processed yet. This ensures that we
    /// don't finalize a proposal before we know the final transaction
    /// count.
    ///
    /// Note: This is in its own method to prevent drift with tests.
    pub fn should_defer_proposal_fin(&self, height_and_round: &HeightAndRound) -> bool {
        self.is_executing(height_and_round) && !self.is_transactions_fin_processed(height_and_round)
    }

    /// Process a transaction batch with deferral support
    ///
    /// This is the main method that should be used by the P2P task
    pub fn process_batch_with_deferral<E: BlockExecutorExt, T: TransactionMapper>(
        &mut self,
        height_and_round: HeightAndRound,
        transactions: Vec<proto_consensus::Transaction>,
        validator: &mut ValidatorTransactionBatchStage<E>,
        consensus_db_tx: &DbTransaction<'_>,
        deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
    ) -> anyhow::Result<()> {
        // Check if execution should be deferred
        if should_defer_execution(height_and_round, consensus_db_tx)? {
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
        let deferred_transactions_fin = deferred.as_ref().and_then(|d| d.transactions_fin);

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
            .execute_batch::<T>(all_transactions)
            .context("Failed to execute transaction batch")?;

        // Mark that execution has started for this height/round
        self.executing.insert(height_and_round);

        tracing::debug!(
            "Transaction batch execution for height and round {height_and_round} is complete, \
             additionally {deferred_txns_len} previously deferred transactions were executed",
        );

        // If TransactionsFin was deferred (arrived before execution started, e.g.,
        // because batches were deferred), process it now that execution has
        // started.
        // Assuming message ordering is guaranteed...
        //   (see p2p::consensus::handle_incoming_proposal_message)
        // ...if TransactionsFin is deferred, all batches are also in the deferred
        // entry, so we can safely process TransactionsFin here.
        if let Some(transactions_fin) = deferred_transactions_fin {
            tracing::debug!(
                "Processing deferred TransactionsFin for {height_and_round} after batch execution \
                 started"
            );
            self.process_transactions_fin::<E, T>(height_and_round, transactions_fin, validator)?;
        }

        Ok(())
    }

    /// Execute a batch of transactions and track execution state
    ///
    /// This is a simpler variant that doesn't handle deferral - used when we
    /// know execution should proceed immediately (e.g., when executing
    /// previously deferred transactions after the parent block is
    /// committed).
    pub fn execute_batch<E: BlockExecutorExt, T: TransactionMapper>(
        &mut self,
        height_and_round: HeightAndRound,
        transactions: Vec<proto_consensus::Transaction>,
        validator: &mut ValidatorTransactionBatchStage<E>,
    ) -> anyhow::Result<()> {
        // Mark that execution has started for this height/round, even if batch is
        // empty. This is necessary because TransactionsFin may arrive later and
        // requires execution to have started.
        self.executing.insert(height_and_round);

        if transactions.is_empty() {
            tracing::debug!(
                "Empty transaction batch for height and round {height_and_round} - execution \
                 marked as started"
            );
            return Ok(());
        }

        // Execute the batch
        validator
            .execute_batch::<T>(transactions)
            .context("Failed to execute transaction batch")?;

        tracing::debug!(
            "Transaction batch execution for height and round {height_and_round} is complete"
        );

        Ok(())
    }

    /// Process TransactionsFin message
    ///
    /// Processes TransactionsFin immediately with rollback support. Assumes
    /// execution has already started (at least one batch executed). If
    /// transactions are deferred, deferral should be handled by the caller
    /// before calling this function.
    pub fn process_transactions_fin<E: BlockExecutorExt, T: TransactionMapper>(
        &mut self,
        height_and_round: HeightAndRound,
        transactions_fin: proto_consensus::TransactionsFin,
        validator: &mut ValidatorTransactionBatchStage<E>,
    ) -> anyhow::Result<()> {
        // Verify that execution has started (at least one batch was executed, not
        // deferred)
        if !self.executing.contains(&height_and_round) {
            return Err(anyhow::anyhow!(
                "No execution state found for {height_and_round}. Execution should have started \
                 before processing TransactionsFin."
            ));
        }

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
            // Note: rollback_to_transaction takes a 0-based index, but
            // executed_transaction_count is a count. To keep N transactions,
            // we need to rollback to index N-1 (which keeps transactions 0 through N-1).
            let target_index = target_transaction_count
                .checked_sub(1)
                .context("Cannot rollback to 0 transactions")?;
            validator
                .rollback_to_transaction::<T>(target_index)
                .context("Failed to rollback to target transaction count")?;
        } else if target_transaction_count > current_transaction_count {
            // This shouldn't happen with proper message ordering and no protocol errors.
            // Ordering is guaranteed by p2p::consensus::handle_incoming_proposal_message.
            // TransactionsFin should arrive after all TransactionBatches, so we should have
            // at least as many transactions as TransactionsFin indicates.
            tracing::warn!(
                "TransactionsFin for {height_and_round} indicates {} transactions, but we only \
                 have {} transactions. This may indicate a protocol violation or missing batches.",
                target_transaction_count,
                current_transaction_count
            );
        }

        tracing::info!(
            "Finalized {height_and_round} with {target_transaction_count} executed transactions"
        );

        // Mark TransactionsFin as processed for this height/round
        self.transactions_fin_processed.insert(height_and_round);

        Ok(())
    }

    /// Clean up completed executions
    pub fn cleanup(&mut self, height_and_round: &HeightAndRound) {
        let had_execution = self.executing.remove(height_and_round);
        let had_transactions_fin = self.transactions_fin_processed.remove(height_and_round);
        if had_execution || had_transactions_fin {
            tracing::debug!("Cleaned up execution state for {height_and_round}");
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
/// proposal has been received. May also store TransactionsFin if it arrives
/// while transactions are deferred.
#[derive(Debug, Clone, Default)]
pub struct DeferredExecution {
    pub transactions: Vec<proto_consensus::Transaction>,
    pub commitment: Option<ProposalCommitmentWithOrigin>,
    pub transactions_fin: Option<proto_consensus::TransactionsFin>,
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
    cons_db_tx: &DbTransaction<'_>,
) -> anyhow::Result<bool> {
    let parent_block = height_and_round.height().checked_sub(1);
    let defer = if let Some(parent_block) = parent_block {
        let parent_block =
            BlockNumber::new(parent_block).context("Block number is larger than i64::MAX")?;
        let parent_block = BlockId::Number(parent_block);
        let parent_committed = cons_db_tx.block_exists(parent_block)?;
        !parent_committed
    } else {
        false
    };
    Ok(defer)
}

#[cfg(test)]
mod tests {
    use pathfinder_crypto::Felt;
    use pathfinder_executor::BlockExecutor;

    use super::*;
    use crate::validator::ProdTransactionMapper;

    /// Helper function to create a committed parent block in storage
    fn create_committed_parent_block(
        storage: &pathfinder_storage::Storage,
        parent_height: u64,
    ) -> anyhow::Result<()> {
        use pathfinder_common::prelude::*;
        let mut db_conn = storage.connection()?;
        let db_tx = db_conn.transaction()?;
        let block_id = BlockId::Number(BlockNumber::new_or_panic(parent_height));

        // Check if block already exists
        if db_tx.block_exists(block_id)? {
            return Ok(());
        }

        // Create a unique hash for this block to avoid conflicts
        let hash = BlockHash(Felt::from_hex_str(&format!("0x{parent_height:064x}")).unwrap());
        let parent_header = BlockHeader::builder()
            .number(BlockNumber::new_or_panic(parent_height))
            .timestamp(BlockTimestamp::new_or_panic(1000))
            .calculated_state_commitment(StorageCommitment(Felt::ZERO), ClassCommitment(Felt::ZERO))
            .sequencer_address(SequencerAddress::ZERO)
            .finalize_with_hash(hash);
        db_tx.insert_block_header(&parent_header)?;
        db_tx.commit()?;
        Ok(())
    }

    /// Helper function to create BlockInfo for tests
    fn create_test_block_info(number: u64) -> pathfinder_executor::types::BlockInfo {
        use pathfinder_common::{
            BlockNumber,
            BlockTimestamp,
            GasPrice,
            L1DataAvailabilityMode,
            SequencerAddress,
            StarknetVersion,
        };
        pathfinder_executor::types::BlockInfo {
            number: BlockNumber::new_or_panic(number),
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
        }
    }

    /// Test that BatchExecutionManager correctly tracks execution state and
    /// TransactionsFin processing. This verifies the tracking methods that
    /// are used by defer_or_execute_proposal_fin to determine
    /// whether ProposalFin should be deferred.
    #[tokio::test]
    async fn test_execution_state_tracking() {
        use p2p::consensus::HeightAndRound;
        use p2p_proto::consensus::TransactionsFin;
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
            ValidatorTransactionBatchStage::<BlockExecutor>::new(chain_id, block_info, storage)
                .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(2, 1);

        // Initially, execution should not have started
        assert!(
            !batch_execution_manager.is_executing(&height_and_round),
            "Execution should not have started initially"
        );
        assert!(
            !batch_execution_manager.is_transactions_fin_processed(&height_and_round),
            "TransactionsFin should not be processed initially"
        );

        // Execute a batch to start execution
        let transactions = create_transaction_batch(0, 5, chain_id);
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                transactions,
                &mut validator_stage,
            )
            .expect("Failed to execute batch");

        // Verify execution has started
        assert!(
            batch_execution_manager.is_executing(&height_and_round),
            "Execution should have started after execute_batch"
        );

        // Verify TransactionsFin has NOT been processed yet
        assert!(
            !batch_execution_manager.is_transactions_fin_processed(&height_and_round),
            "TransactionsFin should not be processed yet"
        );

        // Verify that ProposalFin should be deferred
        assert!(
            batch_execution_manager.should_defer_proposal_fin(&height_and_round),
            "ProposalFin should be deferred when execution started but TransactionsFin not \
             processed"
        );

        // Now process TransactionsFin
        let transactions_fin = TransactionsFin {
            executed_transaction_count: 5,
        };
        batch_execution_manager
            .process_transactions_fin::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                transactions_fin,
                &mut validator_stage,
            )
            .expect("Failed to process TransactionsFin");

        // Verify TransactionsFin is now marked as processed
        assert!(
            batch_execution_manager.is_transactions_fin_processed(&height_and_round),
            "TransactionsFin should be marked as processed after process_transactions_fin"
        );

        // Now ProposalFin should NOT be deferred
        assert!(
            !batch_execution_manager.should_defer_proposal_fin(&height_and_round),
            "ProposalFin should NOT be deferred after TransactionsFin is processed"
        );
    }

    /// Test that TransactionsFin arriving before any TransactionBatch is
    /// handled gracefully. TransactionsFin should be stored in deferred entry
    /// even if no batches have been deferred yet.
    #[tokio::test]
    async fn test_transactions_fin_before_any_batch() {
        use p2p::consensus::HeightAndRound;
        use p2p_proto::consensus::TransactionsFin;
        use pathfinder_common::prelude::*;
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

        // Create and commit parent block (height 1) so height 2 won't be deferred
        {
            let mut db_conn = storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();
            let parent_header = BlockHeader::builder()
                .number(BlockNumber::new_or_panic(1))
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

        let mut validator_stage = ValidatorTransactionBatchStage::<BlockExecutor>::new(
            chain_id,
            block_info,
            storage.clone(),
        )
        .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(2, 1);
        let mut deferred_executions: std::collections::HashMap<HeightAndRound, DeferredExecution> =
            std::collections::HashMap::new();

        // Initially, no execution and no deferred entry
        assert!(
            !batch_execution_manager.is_executing(&height_and_round),
            "Execution should not have started initially"
        );
        assert!(
            !deferred_executions.contains_key(&height_and_round),
            "No deferred entry should exist initially"
        );

        // Step 1: TransactionsFin arrives when execution hasn't started yet
        // (Note: With P2P message ordering guarantees, TransactionsFin will always
        // arrive after all TransactionBatches, but execution may not have started
        // if batches were deferred. This test simulates the case where TransactionsFin
        // arrives before execution starts, e.g., because batches were deferred.)
        let transactions_fin = TransactionsFin {
            executed_transaction_count: 5,
        };

        // Simulate the fix: create deferred entry and store TransactionsFin
        let deferred = deferred_executions.entry(height_and_round).or_default();
        deferred.transactions_fin = Some(transactions_fin);

        // Verify TransactionsFin was stored
        assert!(
            deferred_executions
                .get(&height_and_round)
                .and_then(|d| d.transactions_fin.as_ref())
                .is_some(),
            "TransactionsFin should be stored in deferred entry"
        );

        // Step 2: TransactionBatch arrives and executes
        let transactions = create_transaction_batch(0, 5, chain_id);
        let mut db_conn = storage.connection().unwrap();
        let db_tx = db_conn.transaction().unwrap();
        batch_execution_manager
            .process_batch_with_deferral::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                transactions,
                &mut validator_stage,
                &db_tx,
                &mut deferred_executions,
            )
            .expect("Failed to process batch");

        // Verify execution has started
        assert!(
            batch_execution_manager.is_executing(&height_and_round),
            "Execution should have started after batch execution"
        );

        // Verify TransactionsFin was processed (marked as processed)
        assert!(
            batch_execution_manager.is_transactions_fin_processed(&height_and_round),
            "TransactionsFin should be processed after batch execution"
        );

        // Verify validator state matches TransactionsFin count
        assert_eq!(
            validator_stage.transaction_count(),
            5,
            "Validator should have 5 transactions matching TransactionsFin count"
        );
    }

    /// Test deferral and immediate execution of transaction batches.
    /// A few things are covered here:
    /// - deferral when parent not committed,
    /// - immediate execution when parent committed
    /// - deferred batch execution
    /// - multiple batches with mixed deferral
    #[tokio::test]
    async fn test_deferral_and_execution() {
        use p2p::consensus::HeightAndRound;
        use pathfinder_common::ChainId;
        use pathfinder_storage::StorageBuilder;

        use crate::consensus::inner::test_helpers::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let block_info = create_test_block_info(1);

        let mut validator_stage = ValidatorTransactionBatchStage::<BlockExecutor>::new(
            chain_id,
            block_info,
            storage.clone(),
        )
        .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(2, 1);
        let mut deferred_executions: std::collections::HashMap<HeightAndRound, DeferredExecution> =
            std::collections::HashMap::new();

        // Test 1: Deferral when parent not committed
        {
            let mut db_conn = storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();
            let transactions = create_transaction_batch(0, 3, chain_id);

            batch_execution_manager
                .process_batch_with_deferral::<BlockExecutor, ProdTransactionMapper>(
                    height_and_round,
                    transactions,
                    &mut validator_stage,
                    &db_tx,
                    &mut deferred_executions,
                )
                .expect("Failed to process batch");

            // Verify deferral: transactions stored, execution NOT started
            assert!(
                !batch_execution_manager.is_executing(&height_and_round),
                "Execution should NOT have started when parent not committed"
            );
            assert!(
                deferred_executions
                    .get(&height_and_round)
                    .map(|d| d.transactions.len())
                    .unwrap_or(0)
                    == 3,
                "Deferred transactions should be stored"
            );
            assert_eq!(
                validator_stage.transaction_count(),
                0,
                "No transactions should be executed when deferred"
            );
        }

        // Test 2: Commit parent block and execute deferred batch
        // Create parent block at height 1 (required for height 2 to execute)
        create_committed_parent_block(&storage, 1).expect("Failed to create parent block");

        {
            let mut db_conn = storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();
            let transactions = create_transaction_batch(3, 2, chain_id);

            batch_execution_manager
                .process_batch_with_deferral::<BlockExecutor, ProdTransactionMapper>(
                    height_and_round,
                    transactions,
                    &mut validator_stage,
                    &db_tx,
                    &mut deferred_executions,
                )
                .expect("Failed to process batch");

            // Verify execution: deferred + new transactions executed, execution started
            assert!(
                batch_execution_manager.is_executing(&height_and_round),
                "Execution should have started after parent committed"
            );
            assert!(
                !deferred_executions.contains_key(&height_and_round),
                "Deferred entry should be removed after execution"
            );
            assert_eq!(
                validator_stage.transaction_count(),
                5,
                "All transactions (3 deferred + 2 new) should be executed"
            );
        }

        // Test 3: Multiple batches with immediate execution (parent already committed)
        let height_and_round_2 = HeightAndRound::new(3, 1);
        let mut validator_stage_2 = ValidatorTransactionBatchStage::<BlockExecutor>::new(
            chain_id,
            create_test_block_info(2),
            storage.clone(),
        )
        .expect("Failed to create validator stage");

        create_committed_parent_block(&storage, 2).expect("Failed to create parent block");

        {
            let mut db_conn = storage.connection().unwrap();
            let db_tx = db_conn.transaction().unwrap();

            // Execute multiple batches
            for i in 0..3 {
                let transactions = create_transaction_batch(i * 2, 2, chain_id);
                batch_execution_manager
                    .process_batch_with_deferral::<BlockExecutor, ProdTransactionMapper>(
                        height_and_round_2,
                        transactions,
                        &mut validator_stage_2,
                        &db_tx,
                        &mut deferred_executions,
                    )
                    .expect("Failed to process batch");
            }

            assert!(
                batch_execution_manager.is_executing(&height_and_round_2),
                "Execution should have started"
            );
            assert_eq!(
                validator_stage_2.transaction_count(),
                6,
                "All batches should be executed immediately"
            );
        }
    }

    /// Test TransactionsFin processing with rollback support.
    #[tokio::test]
    async fn test_transactions_fin_rollback() {
        use p2p::consensus::HeightAndRound;
        use p2p_proto::consensus::TransactionsFin;
        use pathfinder_common::ChainId;
        use pathfinder_storage::StorageBuilder;

        use crate::consensus::inner::test_helpers::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let block_info = create_test_block_info(1);

        let mut validator_stage = ValidatorTransactionBatchStage::<BlockExecutor>::new(
            chain_id,
            block_info,
            storage.clone(),
        )
        .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(2, 1);

        // Execute multiple batches: 3 + 7 + 4 = 14 transactions total
        let batch1 = create_transaction_batch(0, 3, chain_id);
        let batch2 = create_transaction_batch(3, 7, chain_id);
        let batch3 = create_transaction_batch(10, 4, chain_id);

        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                batch1,
                &mut validator_stage,
            )
            .expect("Failed to execute batch 1");
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                batch2,
                &mut validator_stage,
            )
            .expect("Failed to execute batch 2");
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                batch3,
                &mut validator_stage,
            )
            .expect("Failed to execute batch 3");

        assert_eq!(
            validator_stage.transaction_count(),
            14,
            "Should have 14 transactions before TransactionsFin"
        );

        // Test 1: Normal case - no rollback (TransactionsFin matches current count)
        {
            let transactions_fin = TransactionsFin {
                executed_transaction_count: 14,
            };

            batch_execution_manager
                .process_transactions_fin::<BlockExecutor, ProdTransactionMapper>(
                    height_and_round,
                    transactions_fin,
                    &mut validator_stage,
                )
                .expect("Failed to process TransactionsFin");

            assert!(
                batch_execution_manager.is_transactions_fin_processed(&height_and_round),
                "TransactionsFin should be marked as processed"
            );
            assert_eq!(
                validator_stage.transaction_count(),
                14,
                "Transaction count should remain 14 (no rollback)"
            );
        }

        // Test 2: Rollback case - TransactionsFin indicates fewer transactions
        // Re-execute batches to get back to 14 transactions
        let storage_2 = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let mut validator_stage_2 = ValidatorTransactionBatchStage::<BlockExecutor>::new(
            chain_id,
            create_test_block_info(1),
            storage_2,
        )
        .expect("Failed to create validator stage");

        let batch1_2 = create_transaction_batch(0, 3, chain_id);
        let batch2_2 = create_transaction_batch(3, 7, chain_id);
        let batch3_2 = create_transaction_batch(10, 4, chain_id);

        let height_and_round_2 = HeightAndRound::new(3, 1);
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round_2,
                batch1_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 1");
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round_2,
                batch2_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 2");
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round_2,
                batch3_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 3");

        let transactions_fin_rollback = TransactionsFin {
            executed_transaction_count: 7, // Rollback from 14 to 7
        };

        batch_execution_manager
            .process_transactions_fin::<BlockExecutor, ProdTransactionMapper>(
                height_and_round_2,
                transactions_fin_rollback,
                &mut validator_stage_2,
            )
            .expect("Failed to process TransactionsFin with rollback");

        assert!(
            batch_execution_manager.is_transactions_fin_processed(&height_and_round_2),
            "TransactionsFin should be marked as processed after rollback"
        );
        assert_eq!(
            validator_stage_2.transaction_count(),
            7,
            "Transaction count should be rolled back to 7 (matching TransactionsFin count)"
        );
    }

    /// Test empty batch handling.
    #[tokio::test]
    async fn test_empty_batch() {
        use p2p::consensus::HeightAndRound;
        use p2p_proto::consensus::TransactionsFin;
        use pathfinder_common::ChainId;
        use pathfinder_storage::StorageBuilder;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let block_info = create_test_block_info(1);

        let mut validator_stage =
            ValidatorTransactionBatchStage::<BlockExecutor>::new(chain_id, block_info, storage)
                .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new();
        let height_and_round = HeightAndRound::new(2, 1);

        // Empty batch still marks execution as started
        batch_execution_manager
            .execute_batch::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                vec![],
                &mut validator_stage,
            )
            .expect("Failed to execute empty batch");

        assert!(
            batch_execution_manager.is_executing(&height_and_round),
            "Execution should be marked as started even for empty batch"
        );
        assert_eq!(
            validator_stage.transaction_count(),
            0,
            "No transactions should be executed"
        );

        // TransactionsFin can be processed after empty batch
        let transactions_fin = TransactionsFin {
            executed_transaction_count: 0,
        };

        batch_execution_manager
            .process_transactions_fin::<BlockExecutor, ProdTransactionMapper>(
                height_and_round,
                transactions_fin,
                &mut validator_stage,
            )
            .expect("Failed to process TransactionsFin after empty batch");

        assert!(
            batch_execution_manager.is_transactions_fin_processed(&height_and_round),
            "TransactionsFin should be processed after empty batch"
        );
    }
}
