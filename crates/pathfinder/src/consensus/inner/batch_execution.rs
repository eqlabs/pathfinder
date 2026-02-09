//! Batch execution manager with rollback support for ExecutedTransactionCount
//!
//! This module provides functionality to handle optimistic execution of
//! transaction batches with the ability to rollback when
//! ExecutedTransactionCount indicates fewer transactions were actually executed
//! by the proposer.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use p2p::consensus::HeightAndRound;
use p2p_proto::consensus as proto_consensus;
use pathfinder_common::{BlockId, BlockNumber};
use pathfinder_storage::{Storage, Transaction};

use crate::consensus::ProposalHandlingError;
use crate::gas_price::L1GasPriceProvider;
use crate::validator::{
    TransactionExt,
    ValidatorStage,
    ValidatorTransactionBatchStage,
    ValidatorWorkerPool,
};

/// Manages batch execution with rollback support for ExecutedTransactionCount
#[derive(Clone)]
pub struct BatchExecutionManager {
    /// Tracks which proposals (height/round) have started execution.
    /// An entry exists here if at least one batch has been executed (not
    /// deferred).
    executing: HashSet<HeightAndRound>,
    /// Tracks which proposals (height/round) have had ExecutedTransactionCount
    /// processed. An entry exists here if ExecutedTransactionCount has been
    /// successfully processed for this height/round.
    executed_transaction_count_processed: HashSet<HeightAndRound>,
    /// Tracks which proposals (height/round) had their execution started from
    /// replay.
    replayed_execution: HashSet<HeightAndRound>,
    /// Gas price provider for block info validation.
    gas_price_provider: Option<L1GasPriceProvider>,
    /// Worker pool for concurrent execution.
    worker_pool: ValidatorWorkerPool,
}

impl BatchExecutionManager {
    /// Create a new batch execution manager
    pub fn new(
        gas_price_provider: Option<L1GasPriceProvider>,
        worker_pool: ValidatorWorkerPool,
    ) -> Self {
        Self {
            executing: HashSet::new(),
            executed_transaction_count_processed: HashSet::new(),
            replayed_execution: HashSet::new(),
            gas_price_provider,
            worker_pool,
        }
    }

    /// Check if execution has started for the given height and round
    ///
    /// Returns `true` if at least one batch has been executed (not deferred)
    /// for this height/round.
    pub fn is_executing(&self, height_and_round: &HeightAndRound) -> bool {
        self.executing.contains(height_and_round)
    }

    /// Check if ExecutedTransactionCount has been processed for the given
    /// height and round
    ///
    /// Returns `true` if ExecutedTransactionCount has been successfully
    /// processed for this height/round.
    pub fn is_executed_transaction_count_processed(
        &self,
        height_and_round: &HeightAndRound,
    ) -> bool {
        self.executed_transaction_count_processed
            .contains(height_and_round)
    }

    /// Check if ProposalFin should be deferred for the given height and round
    ///
    /// ProposalFin should be deferred if execution has started but
    /// ExecutedTransactionCount hasn't been processed yet. This ensures that we
    /// don't finalize a proposal before we know the final transaction count.
    ///
    /// Note: This is in its own method to prevent drift with tests.
    pub fn should_defer_proposal_fin(&self, height_and_round: &HeightAndRound) -> bool {
        // Don't defer if ANY round at this height was replayed!
        // ExecutedTransactionCount may have never been persisted before the
        // crash. This handles the case where the network moved to a new round
        // while we were restarting.
        let height = height_and_round.height();
        if self
            .replayed_execution
            .iter()
            .any(|hr| hr.height() == height)
        {
            return false;
        }
        self.is_executing(height_and_round)
            && !self.is_executed_transaction_count_processed(height_and_round)
    }

    /// Process a transaction batch with deferral support
    ///
    /// This is the main method that should be used by the P2P task
    pub fn process_batch_with_deferral<T: TransactionExt>(
        &mut self,
        height_and_round: HeightAndRound,
        transactions: Vec<proto_consensus::Transaction>,
        validator_stage: ValidatorStage,
        main_db: Storage,
        deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
        is_replayed: bool,
    ) -> Result<ValidatorStage, ProposalHandlingError> {
        let mut main_db_conn = main_db
            .connection()
            .context("Creating database connection for batch execution with deferral")
            .map_err(ProposalHandlingError::Fatal)?;
        let main_db_tx = main_db_conn
            .transaction()
            .context("Creating database transaction for batch execution with deferral")
            .map_err(ProposalHandlingError::Fatal)?;
        // Check if execution should be deferred
        if should_defer_execution(height_and_round, &main_db_tx)? {
            tracing::debug!(
                "🖧  ⚙️ transaction batch execution for height and round {height_and_round} is \
                 deferred"
            );
            assert!(
                deferred_executions
                    .get(&height_and_round)
                    .is_some_and(|dex| dex.block_info.is_some()),
                "If TransactionBatch execution is deferred, a BlockInfo must have been added too \
                 (because it arrives first according to message order)"
            );

            // Defer execution - add to deferred_executions
            deferred_executions
                .entry(height_and_round)
                .or_default()
                .transactions
                .extend(transactions);
            return Ok(validator_stage);
        }

        let deferred = deferred_executions.remove(&height_and_round);

        // Execute any previously deferred transactions first
        let deferred_txns_len = deferred.as_ref().map_or(0, |d| d.transactions.len());
        let deferred_executed_transaction_count =
            deferred.as_ref().and_then(|d| d.executed_transaction_count);

        let mut all_transactions = transactions;
        let mut validator = if let Some(DeferredExecution {
            transactions: mut deferred_txns,
            block_info: deferred_block_info,
            ..
        }) = deferred
        {
            // Deferred transactions arrived first, so they should be executed first.
            // Prepend them to the new transactions.
            deferred_txns.extend(all_transactions);
            all_transactions = deferred_txns;
            if let Some(block_info) = deferred_block_info {
                validator_stage
                    .try_into_block_info_stage()
                    .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
                    .validate_block_info(
                        block_info,
                        main_db.clone(),
                        self.gas_price_provider.clone(),
                        None, // TODO: Add L1ToFriValidator when oracle is available
                        self.worker_pool.clone(),
                    )
                    .map(Box::new)?
            } else {
                validator_stage
                    .try_into_transaction_batch_stage()
                    .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
            }
        } else {
            validator_stage
                .try_into_transaction_batch_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
        };

        // Execute the batch
        validator.execute_batch::<T>(all_transactions)?;

        // Mark that execution has started for this height/round
        self.executing.insert(height_and_round);

        if is_replayed {
            self.replayed_execution.insert(height_and_round);
        }

        tracing::debug!(
            "Transaction batch execution for height and round {height_and_round} is complete, \
             additionally {deferred_txns_len} previously deferred transactions were executed",
        );

        // If ExecutedTransactionCount was deferred (arrived before execution started,
        // e.g., because batches were deferred), process it now that execution
        // has started.
        // Assuming message ordering is guaranteed...
        //   (see p2p::consensus::handle_incoming_proposal_message)
        // ...if ExecutedTransactionCount is deferred, all batches are also in the
        // deferred entry, so we can safely process ExecutedTransactionCount
        // here.
        if let Some(executed_txn_count) = deferred_executed_transaction_count {
            tracing::debug!(
                "Processing deferred ExecutedTransactionCount for {height_and_round} after batch \
                 execution started"
            );
            self.process_executed_transaction_count::<T>(
                height_and_round,
                executed_txn_count,
                &mut validator,
            )?;
        }

        Ok(ValidatorStage::TransactionBatch(validator))
    }

    /// Execute a batch of transactions and track execution state
    ///
    /// This is a simpler variant that doesn't handle deferral - used when we
    /// know execution should proceed immediately (e.g., when executing
    /// previously deferred transactions after the parent block is
    /// committed).
    pub fn execute_batch<T: TransactionExt>(
        &mut self,
        height_and_round: HeightAndRound,
        transactions: Vec<proto_consensus::Transaction>,
        validator: &mut ValidatorTransactionBatchStage,
    ) -> Result<(), ProposalHandlingError> {
        // Mark that execution has started for this height/round, even if batch is
        // empty. This is necessary because ExecutedTransactionCount may arrive later
        // and requires execution to have started.
        self.executing.insert(height_and_round);

        if transactions.is_empty() {
            tracing::debug!(
                "Empty transaction batch for height and round {height_and_round} - execution \
                 marked as started"
            );
            return Ok(());
        }

        // Execute the batch
        validator.execute_batch::<T>(transactions)?;

        tracing::debug!(
            "Transaction batch execution for height and round {height_and_round} is complete"
        );

        Ok(())
    }

    /// Process ExecutedTransactionCount message
    ///
    /// Processes ExecutedTransactionCount immediately with rollback support.
    /// Assumes execution has already started (at least one batch executed).
    /// If transactions are deferred, deferral should be handled by the
    /// caller before calling this function.
    pub fn process_executed_transaction_count<T: TransactionExt>(
        &mut self,
        height_and_round: HeightAndRound,
        executed_transaction_count: u64,
        validator: &mut ValidatorTransactionBatchStage,
    ) -> Result<(), ProposalHandlingError> {
        // Verify that execution has started (at least one batch was executed, not
        // deferred)
        if !self.executing.contains(&height_and_round) {
            return Err(ProposalHandlingError::Fatal(anyhow::anyhow!(
                "No execution state found for {height_and_round}. Execution should have started \
                 before processing ExecutedTransactionCount."
            )));
        }

        let target_transaction_count = executed_transaction_count as usize;
        let current_transaction_count = validator.transaction_count();

        tracing::debug!(
            "Processing ExecutedTransactionCount for {height_and_round}: \
             target={target_transaction_count}, current={current_transaction_count}"
        );

        if target_transaction_count < current_transaction_count {
            tracing::info!(
                "Rolling back {height_and_round} from {} to {} transactions",
                current_transaction_count,
                target_transaction_count
            );
            validator.rollback_to_transaction::<T>(target_transaction_count)?;
        } else if target_transaction_count > current_transaction_count {
            // This shouldn't happen with proper message ordering and no protocol errors.
            // Ordering is guaranteed by p2p::consensus::handle_incoming_proposal_message.
            // ExecutedTransactionCount should arrive after all TransactionBatches, so we
            // should have at least as many transactions as
            // ExecutedTransactionCount indicates.
            tracing::warn!(
                "ExecutedTransactionCount for {height_and_round} indicates {} transactions, but \
                 we only have {} transactions. This may indicate a protocol violation or missing \
                 batches.",
                target_transaction_count,
                current_transaction_count
            );
        }

        let final_transaction_count = validator.transaction_count();
        tracing::info!(
            "Finalized {height_and_round} with {final_transaction_count} executed transactions"
        );

        // Mark ExecutedTransactionCount as processed for this height/round
        self.executed_transaction_count_processed
            .insert(height_and_round);

        Ok(())
    }

    /// Clean up completed executions
    pub fn cleanup(&mut self, height_and_round: &HeightAndRound) {
        let had_execution = self.executing.remove(height_and_round);
        let had_transactions_fin = self
            .executed_transaction_count_processed
            .remove(height_and_round);
        let had_replayed = self.replayed_execution.remove(height_and_round);
        if had_execution || had_transactions_fin || had_replayed {
            tracing::debug!("Cleaned up execution state for {height_and_round}");
        }
    }
}

/// Represents transactions received from the network that are waiting for
/// previous block to be committed before they can be executed. Also holds
/// optional proposal commitment and proposer address in case that the entire
/// proposal has been received. May also store ExecutedTransactionCount if it
/// arrives while transactions are deferred.
#[derive(Debug, Clone, Default)]
pub struct DeferredExecution {
    pub block_info: Option<proto_consensus::BlockInfo>,
    pub transactions: Vec<proto_consensus::Transaction>,
    pub commitment: Option<ProposalCommitmentWithOrigin>,
    pub executed_transaction_count: Option<u64>,
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
    main_db_tx: &Transaction<'_>,
) -> Result<bool, ProposalHandlingError> {
    let parent_block = height_and_round.height().checked_sub(1);
    let defer = if let Some(parent_block) = parent_block {
        let parent_block = BlockNumber::new(parent_block)
            .context("Block number is larger than i64::MAX")
            .map_err(ProposalHandlingError::Fatal)?;
        let parent_block = BlockId::Number(parent_block);
        let parent_committed = main_db_tx
            .block_exists(parent_block)
            .map_err(ProposalHandlingError::Fatal)?;
        !parent_committed
    } else {
        false
    };
    Ok(defer)
}

#[cfg(test)]
mod tests {
    use pathfinder_common::ContractAddress;
    use pathfinder_crypto::Felt;
    use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};

    use super::*;
    use crate::consensus::inner::dummy_proposal::create_test_proposal_init;
    use crate::validator::{ProdTransactionMapper, ValidatorBlockInfoStage};

    /// Creates a worker pool for tests.
    fn create_test_worker_pool() -> ValidatorWorkerPool {
        ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get()
    }

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
    /// ExecutedTransactionCount processing. This verifies the tracking methods
    /// that are used by defer_or_execute_proposal_fin to determine whether
    /// ProposalFin should be deferred.
    #[tokio::test]
    async fn test_execution_state_tracking() {
        use p2p::consensus::HeightAndRound;
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

        use crate::consensus::inner::dummy_proposal::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let worker_pool = create_test_worker_pool();

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
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage, worker_pool.clone())
                .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool);
        let height_and_round = HeightAndRound::new(2, 1);

        // Initially, execution should not have started
        assert!(
            !batch_execution_manager.is_executing(&height_and_round),
            "Execution should not have started initially"
        );
        assert!(
            !batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
            "ExecutedTransactionCount should not be processed initially"
        );

        // Execute a batch to start execution
        let transactions = create_transaction_batch(0, 0, 5, chain_id);
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(
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

        // Verify ExecutedTransactionCount has NOT been processed yet
        assert!(
            !batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
            "ExecutedTransactionCount should not be processed yet"
        );

        // Verify that ProposalFin should be deferred
        assert!(
            batch_execution_manager.should_defer_proposal_fin(&height_and_round),
            "ProposalFin should be deferred when execution started but ExecutedTransactionCount \
             not processed"
        );

        // Now process ExecutedTransactionCount
        let executed_transaction_count = 5;
        batch_execution_manager
            .process_executed_transaction_count::<ProdTransactionMapper>(
                height_and_round,
                executed_transaction_count,
                &mut validator_stage,
            )
            .expect("Failed to process ExecutedTransactionCount");

        // Verify ExecutedTransactionCount is now marked as processed
        assert!(
            batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
            "ExecutedTransactionCount should be marked as processed after process_transactions_fin"
        );

        // Now ProposalFin should NOT be deferred
        assert!(
            !batch_execution_manager.should_defer_proposal_fin(&height_and_round),
            "ProposalFin should NOT be deferred after ExecutedTransactionCount is processed"
        );
    }

    /// Test that ExecutedTransactionCount arriving before any TransactionBatch
    /// is handled gracefully. ExecutedTransactionCount should be stored in
    /// deferred entry even if no batches have been deferred yet.
    #[tokio::test]
    async fn test_executed_transaction_count_before_any_batch() {
        use p2p::consensus::HeightAndRound;
        use pathfinder_common::prelude::*;
        use pathfinder_common::{BlockNumber, BlockTimestamp, ChainId, SequencerAddress};
        use pathfinder_storage::StorageBuilder;

        use crate::consensus::inner::dummy_proposal::create_transaction_batch;

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

        let height_and_round = HeightAndRound::new(2, 1);
        let proposer_address = p2p_proto::common::Address(Felt::from_hex_str("0x456").unwrap());
        let proposal_init = proto_consensus::ProposalInit {
            height: height_and_round.height(),
            round: height_and_round.round(),
            valid_round: None,
            proposer: proposer_address,
        };
        let proposal_block_info = proto_consensus::BlockInfo {
            height: height_and_round.height(),
            timestamp: 2000,
            builder: proposer_address,
            l1_da_mode: p2p_proto::common::L1DataAvailabilityMode::Calldata,
            l2_gas_price_fri: 0,
            l1_gas_price_wei: 0,
            l1_data_gas_price_wei: 0,
            eth_to_fri_rate: 0,
        };

        let worker_pool = create_test_worker_pool();
        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool);
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

        // Step 1: ExecutedTransactionCount arrives when execution hasn't started yet
        // (Note: With P2P message ordering guarantees, ExecutedTransactionCount will
        // always arrive after all TransactionBatches, but execution may not have
        // started if batches were deferred. This test simulates the case where
        // ExecutedTransactionCount arrives before execution starts, e.g., because
        // batches were deferred).
        let executed_transaction_count = 5;

        // Simulate the fix: create deferred entry and store ExecutedTransactionCount.
        // Also store BlockInfo because it should have arrived before any
        // batches or ExecutedTransactionCount (according to message ordering).
        let deferred = deferred_executions.entry(height_and_round).or_default();
        deferred.block_info = Some(proposal_block_info);
        deferred.executed_transaction_count = Some(executed_transaction_count);

        // Verify BlockInfo was stored
        assert!(
            deferred_executions
                .get(&height_and_round)
                .is_some_and(|d| d.block_info.is_some()),
            "BlockInfo should be stored in deferred entry"
        );
        // Verify ExecutedTransactionCount was stored
        assert!(
            deferred_executions
                .get(&height_and_round)
                .and_then(|d| d.executed_transaction_count.as_ref())
                .is_some(),
            "ExecutedTransactionCount should be stored in deferred entry"
        );

        let validator_stage = ValidatorBlockInfoStage::new(chain_id, proposal_init)
            .map(ValidatorStage::BlockInfo)
            .expect("Failed to create validator stage");

        // Step 2: TransactionBatch arrives and executes
        let transactions = create_transaction_batch(0, 0, 5, chain_id);
        let next_stage = batch_execution_manager
            .process_batch_with_deferral::<ProdTransactionMapper>(
                height_and_round,
                transactions,
                validator_stage,
                storage.clone(),
                &mut deferred_executions,
                false,
            )
            .expect("Failed to process batch");

        // Verify execution has started
        assert!(
            batch_execution_manager.is_executing(&height_and_round),
            "Execution should have started after batch execution"
        );

        // Verify ExecutedTransactionCount was processed (marked as processed)
        assert!(
            batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
            "ExecutedTransactionCount should be processed after batch execution"
        );

        // Verify validator state matches ExecutedTransactionCount count
        assert!(
            matches!(
                next_stage,
                ValidatorStage::TransactionBatch(stage) if stage.transaction_count() == 5
            ),
            "Validator should have 5 transactions matching ExecutedTransactionCount"
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

        use crate::consensus::inner::dummy_proposal::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let worker_pool = create_test_worker_pool();

        let height_and_round = HeightAndRound::new(2, 1);
        let proposer_address = ContractAddress::new_or_panic(Felt::from_hex_str("0x456").unwrap());
        let (proposal_init, proposal_block_info) = create_test_proposal_init(
            chain_id,
            height_and_round.height(),
            height_and_round.round(),
            proposer_address,
        );
        let validator_stage = ValidatorBlockInfoStage::new(chain_id, proposal_init)
            .map(ValidatorStage::BlockInfo)
            .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool.clone());
        let mut deferred_executions: std::collections::HashMap<HeightAndRound, DeferredExecution> =
            std::collections::HashMap::new();
        deferred_executions
            .entry(height_and_round)
            .or_default()
            .block_info = Some(proposal_block_info);

        // Test 1: Deferral when parent not committed
        let next_stage = {
            let transactions = create_transaction_batch(0, 0, 3, chain_id);

            let next_stage = batch_execution_manager
                .process_batch_with_deferral::<ProdTransactionMapper>(
                    height_and_round,
                    transactions,
                    validator_stage,
                    storage.clone(),
                    &mut deferred_executions,
                    false,
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
            assert!(
                matches!(
                    next_stage,
                    ValidatorStage::BlockInfo(ref block_info) if block_info.proposal_height() == height_and_round.height()
                ),
                "Validator stage should remain at BlockInfo stage after deferral"
            );

            next_stage
        };

        // Test 2: Commit parent block and execute deferred batch
        // Create parent block at height 1 (required for height 2 to execute)
        create_committed_parent_block(&storage, 1).expect("Failed to create parent block");

        {
            let transactions = create_transaction_batch(0, 3, 2, chain_id);

            let next_stage = batch_execution_manager
                .process_batch_with_deferral::<ProdTransactionMapper>(
                    height_and_round,
                    transactions,
                    next_stage,
                    storage.clone(),
                    &mut deferred_executions,
                    false,
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
            assert!(
                matches!(next_stage, ValidatorStage::TransactionBatch(ref stage) if stage.transaction_count() == 5),
                "Validator should transition to next stage and transactions (3 deferred + 2 new) \
                 should be executed"
            );
        }

        // Test 3: Multiple batches with immediate execution (parent already committed)
        // Create a new worker pool for the second validator to avoid potential issues
        // with the blockifier's ConcurrentTransactionExecutor and shared worker pools.
        let worker_pool_2 = create_test_worker_pool();
        let height_and_round_2 = HeightAndRound::new(3, 1);
        let validator_stage_2 = ValidatorTransactionBatchStage::new(
            chain_id,
            create_test_block_info(2),
            storage.clone(),
            worker_pool_2,
        )
        .map(Box::new)
        .map(ValidatorStage::TransactionBatch)
        .expect("Failed to create validator stage");

        create_committed_parent_block(&storage, 2).expect("Failed to create parent block");

        {
            let mut next_stage = validator_stage_2;
            // Execute multiple batches
            for i in 0..3 {
                let transactions = create_transaction_batch(0, i * 2, 2, chain_id);
                next_stage = batch_execution_manager
                    .process_batch_with_deferral::<ProdTransactionMapper>(
                        height_and_round_2,
                        transactions,
                        next_stage,
                        storage.clone(),
                        &mut deferred_executions,
                        false,
                    )
                    .expect("Failed to process batch");
            }

            assert!(
                batch_execution_manager.is_executing(&height_and_round_2),
                "Execution should have started"
            );
            assert!(
                matches!(next_stage, ValidatorStage::TransactionBatch(stage) if stage.transaction_count() == 6),
                "All batches should be executed immediately"
            );
        }
    }

    /// Test ExecutedTransactionCount processing with rollback support.
    #[tokio::test]
    async fn test_executed_transaction_count_rollback() {
        use p2p::consensus::HeightAndRound;
        use pathfinder_common::ChainId;
        use pathfinder_storage::StorageBuilder;

        use crate::consensus::inner::dummy_proposal::create_transaction_batch;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let worker_pool = create_test_worker_pool();
        let block_info = create_test_block_info(1);

        let mut validator_stage = ValidatorTransactionBatchStage::new(
            chain_id,
            block_info,
            storage.clone(),
            worker_pool.clone(),
        )
        .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool);
        let height_and_round = HeightAndRound::new(2, 1);

        // Execute multiple batches: 3 + 7 + 4 = 14 transactions total
        let batch1 = create_transaction_batch(0, 0, 3, chain_id);
        let batch2 = create_transaction_batch(0, 3, 7, chain_id);
        let batch3 = create_transaction_batch(0, 10, 4, chain_id);

        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(height_and_round, batch1, &mut validator_stage)
            .expect("Failed to execute batch 1");
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(height_and_round, batch2, &mut validator_stage)
            .expect("Failed to execute batch 2");
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(height_and_round, batch3, &mut validator_stage)
            .expect("Failed to execute batch 3");

        assert_eq!(
            validator_stage.transaction_count(),
            14,
            "Should have 14 transactions before ExecutedTransactionCount"
        );

        // Test 1: Normal case - no rollback (ExecutedTransactionCount matches current
        // count)
        {
            let executed_transaction_count = 14;

            batch_execution_manager
                .process_executed_transaction_count::<ProdTransactionMapper>(
                    height_and_round,
                    executed_transaction_count,
                    &mut validator_stage,
                )
                .expect("Failed to process ExecutedTransactionCount");

            assert!(
                batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
                "ExecutedTransactionCount should be marked as processed"
            );
            assert_eq!(
                validator_stage.transaction_count(),
                14,
                "Transaction count should remain 14 (no rollback)"
            );
        }

        // Test 2: Rollback case - ExecutedTransactionCount indicates fewer transactions
        // Create a new worker pool for the second validator to avoid issues with
        // blockifier's ConcurrentTransactionExecutor and shared worker pools.
        let worker_pool_2 = create_test_worker_pool();

        // Re-execute batches to get back to 14 transactions
        let storage_2 = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let mut validator_stage_2 = ValidatorTransactionBatchStage::new(
            chain_id,
            create_test_block_info(1),
            storage_2,
            worker_pool_2,
        )
        .expect("Failed to create validator stage");

        let batch1_2 = create_transaction_batch(0, 0, 3, chain_id);
        let batch2_2 = create_transaction_batch(0, 3, 7, chain_id);
        let batch3_2 = create_transaction_batch(0, 10, 4, chain_id);

        let height_and_round_2 = HeightAndRound::new(3, 1);
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(
                height_and_round_2,
                batch1_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 1");
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(
                height_and_round_2,
                batch2_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 2");
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(
                height_and_round_2,
                batch3_2,
                &mut validator_stage_2,
            )
            .expect("Failed to execute batch 3");

        let executed_transaction_count = 7; // Rollback from 14 to 7

        batch_execution_manager
            .process_executed_transaction_count::<ProdTransactionMapper>(
                height_and_round_2,
                executed_transaction_count,
                &mut validator_stage_2,
            )
            .expect("Failed to process ExecutedTransactionCount with rollback");

        assert!(
            batch_execution_manager.is_executed_transaction_count_processed(&height_and_round_2),
            "ExecutedTransactionCount should be marked as processed after rollback"
        );
        assert_eq!(
            validator_stage_2.transaction_count(),
            7,
            "Transaction count should be rolled back to 7 (matching ExecutedTransactionCount)"
        );
    }

    /// Test empty batch handling.
    #[tokio::test]
    async fn test_empty_batch() {
        use p2p::consensus::HeightAndRound;
        use pathfinder_common::ChainId;
        use pathfinder_storage::StorageBuilder;

        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let worker_pool = create_test_worker_pool();
        let block_info = create_test_block_info(1);

        let mut validator_stage =
            ValidatorTransactionBatchStage::new(chain_id, block_info, storage, worker_pool.clone())
                .expect("Failed to create validator stage");

        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool);
        let height_and_round = HeightAndRound::new(2, 1);

        // Empty batch still marks execution as started
        batch_execution_manager
            .execute_batch::<ProdTransactionMapper>(height_and_round, vec![], &mut validator_stage)
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

        // ExecutedTransactionCount can be processed after empty batch
        let executed_transaction_count = 0;

        batch_execution_manager
            .process_executed_transaction_count::<ProdTransactionMapper>(
                height_and_round,
                executed_transaction_count,
                &mut validator_stage,
            )
            .expect("Failed to process ExecutedTransactionCount after empty batch");

        assert!(
            batch_execution_manager.is_executed_transaction_count_processed(&height_and_round),
            "ExecutedTransactionCount should be processed after empty batch"
        );
    }
}
