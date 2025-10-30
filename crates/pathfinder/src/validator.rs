use std::str::FromStr;
use std::time::Instant;

use anyhow::Context;
use p2p::sync::client::conv::TryFromDto;
use p2p_proto::class::Cairo1Class;
use p2p_proto::consensus::{BlockInfo, ProposalInit, TransactionVariant as ConsensusVariant};
use p2p_proto::sync::transaction::{DeclareV3WithoutClass, TransactionVariant as SyncVariant};
use p2p_proto::transaction::DeclareV3WithClass;
use pathfinder_common::class_definition::{SelectorAndFunctionIndex, SierraEntryPoints};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    class_definition,
    BlockHash,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    ChainId,
    EntryPoint,
    EventCommitment,
    L1DataAvailabilityMode,
    ProposalCommitment,
    ReceiptCommitment,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    TransactionCommitment,
    TransactionHash,
};
use pathfinder_executor::types::{to_starknet_api_transaction, BlockInfoPriceConverter};
use pathfinder_executor::{BlockExecutor, ClassInfo, IntoStarkFelt};
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_rpc::context::{ETH_FEE_TOKEN_ADDRESS, STRK_FEE_TOKEN_ADDRESS};
use pathfinder_storage::{Storage, Transaction as DbTransaction};
use rayon::prelude::*;
use tracing::debug;

use crate::state::block_hash::{
    self,
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
};

pub fn new(
    chain_id: ChainId,
    proposal_init: ProposalInit,
) -> anyhow::Result<ValidatorBlockInfoStage> {
    ValidatorBlockInfoStage::new(chain_id, proposal_init)
}

/// Validates the basic block metadata and proposal information before any
/// transaction processing.
#[derive(Debug)]
pub struct ValidatorBlockInfoStage {
    chain_id: ChainId,
    proposal_height: BlockNumber,
}

impl ValidatorBlockInfoStage {
    pub fn new(
        chain_id: ChainId,
        proposal_init: ProposalInit,
    ) -> anyhow::Result<ValidatorBlockInfoStage> {
        // TODO(validator) how can we validate the proposal init?
        Ok(ValidatorBlockInfoStage {
            chain_id,
            proposal_height: BlockNumber::new(proposal_init.block_number)
                .context("ProposalInit height exceeds i64::MAX")?,
        })
    }

    pub fn validate_consensus_block_info(
        self,
        block_info: BlockInfo,
        storage: Storage,
    ) -> anyhow::Result<ValidatorTransactionBatchStage> {
        let _span = tracing::debug_span!(
            "Validator::validate_block_info",
            height = %block_info.block_number,
            timestamp = %block_info.timestamp,
            builder = %block_info.builder.0,
        )
        .entered();

        let Self {
            chain_id,
            proposal_height,
        } = self;

        anyhow::ensure!(
            proposal_height == block_info.block_number,
            "ProposalInit height does not match BlockInfo height: {} != {}",
            proposal_height,
            block_info.block_number,
        );

        // TODO(validator) validate block info (timestamp, gas prices)

        let BlockInfo {
            block_number,
            timestamp,
            builder,
            l1_da_mode,
            l2_gas_price_fri,
            l1_gas_price_wei,
            l1_data_gas_price_wei,
            eth_to_strk_rate,
        } = block_info;

        let block_info = pathfinder_executor::types::BlockInfo::try_from_proposal(
            block_number,
            timestamp,
            SequencerAddress(builder.0),
            match l1_da_mode {
                p2p_proto::common::L1DataAvailabilityMode::Blob => L1DataAvailabilityMode::Blob,
                p2p_proto::common::L1DataAvailabilityMode::Calldata => {
                    L1DataAvailabilityMode::Calldata
                }
            },
            BlockInfoPriceConverter::consensus(
                l2_gas_price_fri,
                l1_gas_price_wei,
                l1_data_gas_price_wei,
                eth_to_strk_rate,
            ),
            StarknetVersion::new(0, 14, 0, 0), /* TODO(validator) should probably come from
                                                * somewhere... */
        )
        .context("Creating internal BlockInfo representation")?;

        Ok(ValidatorTransactionBatchStage {
            chain_id,
            block_info,
            expected_block_header: None,
            block_executor: LazyBlockExecutor::new(chain_id, block_info, storage.clone()),
            transactions: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            batch_executors: Vec::new(),
            batch_sizes: Vec::new(),
            batch_p2p_transactions: Vec::new(),
            storage,
        })
    }
}

/// Executes transactions and manages the block execution state.
pub struct ValidatorTransactionBatchStage {
    chain_id: ChainId,
    block_info: pathfinder_executor::types::BlockInfo,
    expected_block_header: Option<BlockHeader>,
    block_executor: LazyBlockExecutor,
    transactions: Vec<Transaction>,
    receipts: Vec<Receipt>,
    events: Vec<Vec<Event>>,
    /// Per-batch executors for fine-grained rollback
    batch_executors: Vec<BlockExecutor>,
    /// Size of each batch (for proper rollback calculations)
    batch_sizes: Vec<usize>,
    /// Original p2p transactions per batch (for partial execution)
    batch_p2p_transactions: Vec<Vec<p2p_proto::consensus::Transaction>>,
    /// Storage for creating new connections
    storage: Storage,
}

enum LazyBlockExecutor {
    /// This variant holds the data necessary to initialize the `BlockExecutor`
    /// on first use.
    Uninitialized {
        chain_id: ChainId,
        block_info: Box<pathfinder_executor::types::BlockInfo>,
        storage: Storage,
    },
    /// This variant is used to temporarily take ownership of the
    /// `chain_id`, `block_info` and `storage` fields while initializing
    /// the `BlockExecutor` and occurs only briefly in
    /// [`get_or_init()`](Self::get_or_init).
    Initializing,
    /// This variant holds the initialized `BlockExecutor` and keeps the storage
    /// reference for potential restoration.
    Initialized { executor: Box<BlockExecutor> },
}

impl LazyBlockExecutor {
    fn new(
        chain_id: ChainId,
        block_info: pathfinder_executor::types::BlockInfo,
        storage: Storage,
    ) -> Self {
        LazyBlockExecutor::Uninitialized {
            chain_id,
            block_info: Box::new(block_info),
            storage,
        }
    }

    fn get_or_init(&mut self) -> anyhow::Result<&mut BlockExecutor> {
        if let LazyBlockExecutor::Initialized { executor, .. } = self {
            Ok(executor)
        } else {
            let this = std::mem::replace(self, Self::Initializing);
            let LazyBlockExecutor::Uninitialized {
                chain_id,
                block_info,
                storage,
            } = this
            else {
                panic!("Unexpected state in LazyBlockExecutor");
            };

            let db_conn = storage.connection().context("Create database connection")?;
            let be = BlockExecutor::new(
                chain_id,
                *block_info,
                ETH_FEE_TOKEN_ADDRESS,
                STRK_FEE_TOKEN_ADDRESS,
                db_conn,
            )
            .context("Creating BlockExecutor")?;
            *self = LazyBlockExecutor::Initialized {
                executor: Box::new(be),
            };
            let LazyBlockExecutor::Initialized { executor, .. } = self else {
                unreachable!("Block executor is initialized");
            };
            Ok(executor)
        }
    }

    /// Takes the initialized [`BlockExecutor`], invoking
    /// [`get_or_init()`](Self::get_or_init) if necessary.
    fn take(mut self) -> anyhow::Result<Box<BlockExecutor>> {
        self.get_or_init()?;
        let LazyBlockExecutor::Initialized { executor, .. } = self else {
            unreachable!("Block executor is initialized");
        };
        Ok(executor)
    }
}

impl ValidatorTransactionBatchStage {
    /// Create a new ValidatorTransactionBatchStage
    pub fn new(
        chain_id: ChainId,
        block_info: pathfinder_executor::types::BlockInfo,
        storage: Storage,
    ) -> anyhow::Result<Self> {
        Ok(ValidatorTransactionBatchStage {
            chain_id,
            block_info,
            expected_block_header: None,
            block_executor: LazyBlockExecutor::new(chain_id, block_info, storage.clone()),
            transactions: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            batch_executors: Vec::new(),
            batch_sizes: Vec::new(),
            batch_p2p_transactions: Vec::new(),
            storage,
        })
    }

    pub fn has_proposal_commitment(&self) -> bool {
        self.expected_block_header.is_some()
    }

    /// Get the current number of executed transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Execute a batch of transactions, creating a new executor with chained
    /// initial state
    pub fn execute_batch(
        &mut self,
        transactions: Vec<p2p_proto::consensus::Transaction>,
    ) -> anyhow::Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        let batch_size = transactions.len();
        let batch_index = self.batch_executors.len();

        tracing::debug!(
            "Executing batch {} with {} transactions",
            batch_index,
            batch_size
        );

        // Convert transactions to executor format
        let txns = transactions
            .iter()
            .map(|t| try_map_transaction(t.clone()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (common_txns, executor_txns): (Vec<_>, Vec<_>) = txns.into_iter().unzip();

        // Verify transaction hashes
        let txn_hashes = common_txns
            .par_iter()
            .map(|t| {
                if t.verify_hash(self.chain_id) {
                    Ok(t.hash)
                } else {
                    Err(anyhow::anyhow!(
                        "Transaction hash mismatch, expected: {}",
                        t.hash
                    ))
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .context("Verifying transaction hashes")?;

        // Create a new executor for this batch with chaining support
        let mut batch_executor = if self.batch_executors.is_empty() {
            // First batch - start from initial state
            BlockExecutor::new(
                self.chain_id,
                self.block_info,
                ETH_FEE_TOKEN_ADDRESS,
                STRK_FEE_TOKEN_ADDRESS,
                self.storage
                    .connection()
                    .context("Creating database connection")?,
            )?
        } else {
            // Subsequent batches - chain from previous batch's final state
            let last_executor = self
                .batch_executors
                .last()
                .context("Should have previous executor for chaining")?;
            let previous_state = last_executor.get_final_state()?;
            BlockExecutor::new_with_initial_state(
                self.chain_id,
                self.block_info,
                ETH_FEE_TOKEN_ADDRESS,
                STRK_FEE_TOKEN_ADDRESS,
                self.storage
                    .connection()
                    .context("Creating database connection")?,
                previous_state,
            )?
        };

        // Set the correct transaction index
        batch_executor.set_transaction_index(self.transactions.len());

        // Execute the batch transactions in the NEW executor
        let (receipts, events): (Vec<_>, Vec<_>) =
            batch_executor.execute(executor_txns)?.into_iter().unzip();

        // Convert receipts to common format with correct sequential transaction indices
        let base_transaction_index = self.transactions.len();
        let receipts: Vec<Receipt> = receipts
            .into_iter()
            .zip(txn_hashes)
            .enumerate()
            .map(|(batch_idx, (receipt, hash))| Receipt {
                transaction_hash: hash,
                actual_fee: receipt.actual_fee,
                execution_resources: receipt.execution_resources,
                l2_to_l1_messages: receipt.l2_to_l1_messages,
                execution_status: receipt.execution_status,
                transaction_index: pathfinder_common::TransactionIndex::new(
                    (base_transaction_index + batch_idx) as u64,
                )
                .expect("Transaction index should be valid"),
            })
            .collect();

        // Store the executor, batch size, and original p2p transactions for potential
        // rollback
        self.batch_executors.push(batch_executor);
        self.batch_sizes.push(batch_size);
        self.batch_p2p_transactions.push(transactions);

        // Update our state
        self.transactions.extend(common_txns);
        self.receipts.extend(receipts);
        self.events.extend(events);

        // Validate consistency after each batch execution
        self.validate_batch_consistency()?;

        tracing::debug!(
            "Executed batch {} with {} transactions, total transactions: {}",
            batch_index,
            batch_size,
            self.transactions.len()
        );

        Ok(())
    }

    /// Rollback to the state after a specific batch (discard later batches)
    pub fn rollback_to_batch(&mut self, target_batch: usize) -> anyhow::Result<()> {
        if target_batch >= self.batch_executors.len() {
            return Err(anyhow::anyhow!(
                "Target batch {} exceeds available batches {}",
                target_batch,
                self.batch_executors.len()
            ));
        }

        // Calculate how many transactions to keep based on the target batch
        // Sum up the sizes of all batches up to and including the target batch
        let transactions_to_keep: usize = self.batch_sizes.iter().take(target_batch + 1).sum();

        // Truncate all vectors to match the target batch
        self.transactions.truncate(transactions_to_keep);
        self.receipts.truncate(transactions_to_keep);
        self.events.truncate(transactions_to_keep);
        self.batch_executors.truncate(target_batch + 1);
        self.batch_sizes.truncate(target_batch + 1);
        self.batch_p2p_transactions.truncate(target_batch + 1);

        // Validate consistency after rollback
        self.validate_batch_consistency()?;

        tracing::debug!(
            "Rolled back to batch {} - kept {} transactions, {} receipts, {} events",
            target_batch,
            self.transactions.len(),
            self.receipts.len(),
            self.events.len()
        );

        Ok(())
    }

    /// Rollback to a specific transaction count
    pub fn rollback_to_transaction(
        &mut self,
        target_transaction_count: usize,
    ) -> anyhow::Result<()> {
        let target_batch = self.find_batch_containing_transaction(target_transaction_count)?;

        let cumulative_size_up_to_batch: usize = self.batch_sizes.iter().take(target_batch).sum();
        let transactions_in_target_batch = target_transaction_count - cumulative_size_up_to_batch;

        // If the target transaction count is equal to the batch size, rollback to the
        // batch
        if transactions_in_target_batch == self.batch_sizes[target_batch] {
            self.rollback_to_batch(target_batch)
        } else {
            // If the target batch is the first batch, re-execute the partial batch
            if target_batch == 0 {
                // Store the original transactions before clearing state
                let original_p2p_transactions = self.batch_p2p_transactions[0].clone();

                // Clear all state first since we're starting from scratch
                self.transactions.clear();
                self.receipts.clear();
                self.events.clear();
                self.batch_executors.clear();
                self.batch_sizes.clear();
                self.batch_p2p_transactions.clear();

                // Execute the partial batch
                let partial_transactions =
                    &original_p2p_transactions[..transactions_in_target_batch + 1];
                self.execute_batch(partial_transactions.to_vec())?;
            } else {
                // Store the original p2p transactions before rollback
                let original_p2p_transactions = self.batch_p2p_transactions[target_batch].clone();

                // Rollback to the previous batch
                self.rollback_to_batch(target_batch - 1)?;

                // Execute the partial batch that's left
                let partial_transactions =
                    &original_p2p_transactions[..transactions_in_target_batch + 1];
                self.execute_batch(partial_transactions.to_vec())?;
            }

            Ok(())
        }
    }

    fn find_batch_containing_transaction(&self, target_count: usize) -> anyhow::Result<usize> {
        let mut cumulative_size = 0;
        for (batch_idx, &batch_size) in self.batch_sizes.iter().enumerate() {
            if cumulative_size + batch_size > target_count {
                return Ok(batch_idx);
            }
            cumulative_size += batch_size;
        }
        Err(anyhow::anyhow!(
            "Transaction count {} exceeds total transactions {}",
            target_count,
            self.transactions.len()
        ))
    }

    /// Finalize with the current state (up to the last executed transaction)
    pub fn finalize(&mut self) -> anyhow::Result<Option<pathfinder_executor::types::StateDiff>> {
        if self.batch_executors.is_empty() {
            return Ok(None);
        }

        // Take the last batch executor and finalize it
        let last_executor = self.batch_executors.pop().unwrap();
        let state_diff = last_executor.finalize()?;

        Ok(Some(state_diff))
    }

    /// Get the number of batch executors
    pub fn batch_executor_count(&self) -> usize {
        self.batch_executors.len()
    }

    /// Get the number of receipts
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Get the number of events
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get a reference to the receipts (for testing)
    #[cfg(test)]
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Validate that batch tracking vectors are consistent
    fn validate_batch_consistency(&self) -> anyhow::Result<()> {
        if self.batch_executors.len() != self.batch_sizes.len() {
            return Err(anyhow::anyhow!(
                "Batch consistency error: {} executors but {} batch sizes",
                self.batch_executors.len(),
                self.batch_sizes.len()
            ));
        }

        // Validate that the sum of batch sizes matches the total transaction count
        let total_batch_transactions: usize = self.batch_sizes.iter().sum();
        if total_batch_transactions != self.transactions.len() {
            return Err(anyhow::anyhow!(
                "Batch size mismatch: batch sizes sum to {} but we have {} transactions",
                total_batch_transactions,
                self.transactions.len()
            ));
        }

        // Validate that batch sizes are non-zero
        for (i, &size) in self.batch_sizes.iter().enumerate() {
            if size == 0 {
                return Err(anyhow::anyhow!("Invalid batch size: batch {i} has size 0"));
            }
        }

        Ok(())
    }

    /// Validate that the validator state is consistent
    pub fn validate_state_consistency(&self) -> anyhow::Result<()> {
        // Validate that receipts and events match transaction count
        if self.receipts.len() != self.transactions.len() {
            return Err(anyhow::anyhow!(
                "State inconsistency: {} receipts but {} transactions",
                self.receipts.len(),
                self.transactions.len()
            ));
        }

        if self.events.len() != self.transactions.len() {
            return Err(anyhow::anyhow!(
                "State inconsistency: {} event arrays but {} transactions",
                self.events.len(),
                self.transactions.len()
            ));
        }

        // Validate that BlockExecutor is in a valid state
        // After restoration, it should be either Uninitialized (clean) or Initialized
        // (clean)
        if matches!(self.block_executor, LazyBlockExecutor::Initializing) {
            return Err(anyhow::anyhow!(
                "BlockExecutor is in invalid initializing state"
            ));
        }

        Ok(())
    }

    pub fn record_proposal_commitment(
        &mut self,
        proposal_commitment: p2p_proto::consensus::ProposalCommitment,
    ) -> anyhow::Result<()> {
        let expected_block_header = BlockHeader {
            hash: BlockHash::ZERO,        // UNUSED
            parent_hash: BlockHash::ZERO, // UNUSED
            number: BlockNumber::new(proposal_commitment.block_number)
                .context("ProposalCommitment block number exceeds i64::MAX")?,
            timestamp: BlockTimestamp::new(proposal_commitment.timestamp)
                .context("ProposalCommitment timestamp exceeds i64::MAX")?,
            // TODO prices should be validated against proposal_commitment values
            eth_l1_gas_price: self.block_info.eth_l1_gas_price,
            strk_l1_gas_price: self.block_info.strk_l1_gas_price,
            eth_l1_data_gas_price: self.block_info.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.block_info.strk_l1_data_gas_price,
            eth_l2_gas_price: self.block_info.eth_l2_gas_price,
            strk_l2_gas_price: self.block_info.strk_l2_gas_price,
            sequencer_address: SequencerAddress(proposal_commitment.builder.0),
            starknet_version: StarknetVersion::from_str(&proposal_commitment.protocol_version)?,
            event_commitment: EventCommitment(proposal_commitment.event_commitment.0),
            state_commitment: StateCommitment::ZERO, // UNUSED
            transaction_commitment: TransactionCommitment(
                proposal_commitment.transaction_commitment.0,
            ),
            transaction_count: 0, // TODO validate concatenated_counts
            event_count: 0,       // TODO validate concatenated_counts
            l1_da_mode: match proposal_commitment.l1_da_mode {
                p2p_proto::common::L1DataAvailabilityMode::Blob => L1DataAvailabilityMode::Blob,
                p2p_proto::common::L1DataAvailabilityMode::Calldata => {
                    L1DataAvailabilityMode::Calldata
                }
            },
            receipt_commitment: ReceiptCommitment(proposal_commitment.receipt_commitment.0),
            state_diff_commitment: StateDiffCommitment(proposal_commitment.state_diff_commitment.0),
            state_diff_length: 0, // TODO validate concatenated_counts
        };
        self.expected_block_header = Some(expected_block_header);
        Ok(())
    }

    /// Finalizes the block, producing a header with all commitments except
    /// the state commitment and block hash, which are computed in the last
    /// stage. Also verifies that the computed proposal commitment matches the
    /// expected one.
    pub fn consensus_finalize(
        self,
        expected_proposal_commitment: ProposalCommitment,
    ) -> anyhow::Result<ValidatorFinalizeStage> {
        let next_stage = self.consensus_finalize0()?;
        let actual_proposal_commitment = next_stage.header.state_diff_commitment;

        if actual_proposal_commitment.0 == expected_proposal_commitment.0 {
            Ok(next_stage)
        } else {
            Err(anyhow::anyhow!(
                "expected {expected_proposal_commitment}, actual {actual_proposal_commitment}"
            ))
        }
    }

    /// Finalizes the block, producing a header with all commitments except
    /// the state commitment and block hash, which are computed in the last
    /// stage.
    pub(crate) fn consensus_finalize0(self) -> anyhow::Result<ValidatorFinalizeStage> {
        let Self {
            block_info,
            expected_block_header,
            block_executor,
            transactions,
            receipts,
            events,
            ..
        } = self;

        let _span = tracing::debug_span!(
            "Validator::consensus_finalize",
            height = %block_info.number,
            num_transactions = %transactions.len(),
        )
        .entered();

        let start = Instant::now();

        let state_diff = block_executor.take()?.finalize()?;

        let transaction_commitment =
            calculate_transaction_commitment(&transactions, block_info.starknet_version)?;
        let receipt_commitment = calculate_receipt_commitment(&receipts)?;
        let events_ref_by_txn = events
            .iter()
            .zip(transactions.iter().map(|t| t.hash))
            .map(|(e, h)| (h, e.as_slice()))
            .collect::<Vec<_>>();
        let event_commitment =
            calculate_event_commitment(&events_ref_by_txn, block_info.starknet_version)?;

        let state_update = StateUpdateData::from(state_diff);
        let state_diff_commitment = state_update.compute_state_diff_commitment();

        let header = BlockHeader {
            // Computed in ValidatorFinalizeStage::finalize()
            hash: BlockHash::ZERO,
            parent_hash: BlockHash::ZERO,
            number: self.block_info.number,
            timestamp: self.block_info.timestamp,
            eth_l1_gas_price: self.block_info.eth_l1_gas_price,
            strk_l1_gas_price: self.block_info.strk_l1_gas_price,
            eth_l1_data_gas_price: self.block_info.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.block_info.strk_l1_data_gas_price,
            eth_l2_gas_price: self.block_info.eth_l2_gas_price,
            strk_l2_gas_price: self.block_info.strk_l2_gas_price,
            sequencer_address: self.block_info.sequencer_address,
            starknet_version: self.block_info.starknet_version,
            event_commitment,
            // Computed in ValidatorFinalizeStage::finalize()
            state_commitment: StateCommitment::ZERO,
            transaction_commitment,
            transaction_count: 0, // TODO validate concatenated_counts
            event_count: 0,       // TODO validate concatenated_counts
            l1_da_mode: self.block_info.l1_da_mode,
            receipt_commitment,
            state_diff_commitment,
            state_diff_length: 0, // TODO validate concatenated_counts
        };

        debug!(
            "Block {} finalized in {} ms",
            self.block_info.number,
            start.elapsed().as_millis()
        );

        if let Some(expected_header) = expected_block_header {
            if header != expected_header {
                anyhow::bail!("expected {expected_header:?}, actual {header:?}");
            }
        }

        Ok(ValidatorFinalizeStage {
            header,
            state_update,
            transactions,
            receipts: receipts.clone(),
            events,
        })
    }
}

/// Finalizes the block by computing commitments and updating the database.
pub struct ValidatorFinalizeStage {
    header: BlockHeader,
    state_update: StateUpdateData,
    transactions: Vec<Transaction>,
    receipts: Vec<Receipt>,
    events: Vec<Vec<Event>>,
}

#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub header: BlockHeader,
    pub state_update: StateUpdateData,
    pub transactions_and_receipts: Vec<(Transaction, Receipt)>,
    pub events: Vec<Vec<Event>>,
}

impl ValidatorFinalizeStage {
    /// Updates the tries, computes the state commitment and block hash.
    ///
    /// ### Performance
    ///
    /// This function performs database operations and is computationally
    /// and IO intensive.
    pub fn finalize(
        self,
        db_tx: DbTransaction<'_>,
        storage: Storage,
    ) -> anyhow::Result<FinalizedBlock> {
        #[cfg(debug_assertions)]
        const VERIFY_HASHES: bool = true;
        #[cfg(not(debug_assertions))]
        const VERIFY_HASHES: bool = false;

        let Self {
            mut header,
            state_update,
            transactions,
            receipts,
            events,
        } = self;

        let _span = tracing::debug_span!(
            "Validator::finalize",
            height = %header.number,
            num_transactions = %header.transaction_count,
        )
        .entered();

        let start = Instant::now();

        if let Some(parent_number) = header.number.parent() {
            header.parent_hash = db_tx.block_hash(parent_number.into())?.unwrap_or_default();
        } else {
            // Parent block hash for the genesis block is zero by definition.
            header.parent_hash = BlockHash::ZERO;
        }

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_tx,
            (&state_update).into(),
            VERIFY_HASHES,
            header.number,
            storage.clone(),
        )?;

        db_tx.commit().context("Committing database transaction")?;

        debug!(
            "Block {} tries updated in {} ms",
            header.number,
            start.elapsed().as_millis()
        );

        let start = Instant::now();
        header.state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);

        header.hash = block_hash::compute_final_hash(&header);

        debug!(
            "Block {} state commitment and block hash computed in {} ms",
            header.number,
            start.elapsed().as_millis()
        );

        let transactions_and_receipts = transactions.into_iter().zip(receipts).collect::<Vec<_>>();

        Ok(FinalizedBlock {
            header,
            state_update,
            transactions_and_receipts,
            events,
        })
    }
}

pub enum ValidatorStage {
    BlockInfo(ValidatorBlockInfoStage),
    TransactionBatch(Box<ValidatorTransactionBatchStage>),
    Finalize(Box<ValidatorFinalizeStage>),
}

impl ValidatorStage {
    pub fn try_into_block_info_stage(self) -> anyhow::Result<ValidatorBlockInfoStage> {
        match self {
            ValidatorStage::BlockInfo(stage) => Ok(stage),
            _ => anyhow::bail!("Expected block info stage, got {}", self.variant_name()),
        }
    }

    pub fn try_into_transaction_batch_stage(
        self,
    ) -> anyhow::Result<Box<ValidatorTransactionBatchStage>> {
        match self {
            ValidatorStage::TransactionBatch(stage) => Ok(stage),
            _ => anyhow::bail!(
                "Expected transaction batch stage, got {}",
                self.variant_name()
            ),
        }
    }

    pub fn try_into_finalize_stage(self) -> anyhow::Result<Box<ValidatorFinalizeStage>> {
        match self {
            ValidatorStage::Finalize(stage) => Ok(stage),
            _ => anyhow::bail!("Expected finalize stage, got {}", self.variant_name()),
        }
    }

    fn variant_name(&self) -> &'static str {
        match self {
            ValidatorStage::BlockInfo(_) => "BlockInfo",
            ValidatorStage::TransactionBatch(_) => "TransactionBatch",
            ValidatorStage::Finalize(_) => "Finalize",
        }
    }
}

/// Maps consensus transaction to a pair of:
/// - common transaction, which is used for verifying the transaction hash
/// - executor transaction, which is used for executing the transaction
fn try_map_transaction(
    transaction: p2p_proto::consensus::Transaction,
) -> anyhow::Result<(
    pathfinder_common::transaction::Transaction,
    pathfinder_executor::Transaction,
)> {
    let p2p_proto::consensus::Transaction {
        txn,
        transaction_hash,
    } = transaction;
    let (variant, class_info) = match txn {
        ConsensusVariant::DeclareV3(DeclareV3WithClass { common, class }) => (
            SyncVariant::DeclareV3(DeclareV3WithoutClass {
                common,
                class_hash: Default::default(),
            }),
            Some(class_info(class)?),
        ),
        ConsensusVariant::DeployAccountV3(v) => (SyncVariant::DeployAccountV3(v), None),
        ConsensusVariant::InvokeV3(v) => (SyncVariant::InvokeV3(v), None),
        ConsensusVariant::L1HandlerV0(v) => (SyncVariant::L1HandlerV0(v), None),
    };

    let common_txn_variant = TransactionVariant::try_from_dto(variant)?;

    let deployed_address = deployed_address(&common_txn_variant);

    // TODO(validator) why 10^12?
    let paid_fee_on_l1 = match &common_txn_variant {
        TransactionVariant::L1Handler(_) => {
            Some(starknet_api::transaction::fields::Fee(1_000_000_000_000))
        }
        _ => None,
    };

    let api_txn = to_starknet_api_transaction(common_txn_variant.clone())?;
    let tx_hash = starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt());
    let executor_txn = pathfinder_executor::Transaction::from_api(
        api_txn,
        tx_hash,
        class_info,
        paid_fee_on_l1,
        deployed_address,
        pathfinder_executor::AccountTransactionExecutionFlags::default(),
    )?;
    let common_txn = pathfinder_common::transaction::Transaction {
        hash: TransactionHash(transaction_hash.0),
        variant: common_txn_variant,
    };

    Ok((common_txn, executor_txn))
}

fn class_info(class: Cairo1Class) -> anyhow::Result<ClassInfo> {
    let Cairo1Class {
        abi,
        entry_points,
        program,
        contract_class_version,
    } = class;

    let abi_length = abi.len();
    let sierra_program_length = program.len();
    let sierra_version =
        starknet_api::contract_class::SierraVersion::from_str(&contract_class_version)
            .context("Getting sierra version")?;

    let class_definition = class_definition::Sierra {
        abi: abi.into(),
        sierra_program: program,
        contract_class_version: contract_class_version.into(),
        entry_points_by_type: SierraEntryPoints {
            constructor: entry_points
                .constructors
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
            external: entry_points
                .externals
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
            l1_handler: entry_points
                .l1_handlers
                .into_iter()
                .map(|x| SelectorAndFunctionIndex {
                    selector: EntryPoint(x.selector),
                    function_idx: x.index,
                })
                .collect(),
        },
    };
    // TODO(validator) this is suboptimal, the same surplus serialization happens in
    // the broadcasted transactions case
    let class_definition =
        serde_json::to_vec(&class_definition).context("Serializing Sierra class definition")?;
    // TODO(validator) compile_to_casm should also accept a deserialized class
    // definition
    let casm_contract_definition = pathfinder_compiler::compile_to_casm(&class_definition)
        .context("Compiling Sierra class definition to CASM")?;

    let casm_contract_definition = pathfinder_executor::parse_casm_definition(
        casm_contract_definition,
        sierra_version.clone(),
    )
    .context("Parsing CASM contract definition")?;
    let ci = ClassInfo::new(
        &casm_contract_definition,
        sierra_program_length,
        abi_length,
        sierra_version,
    )?;
    Ok(ci)
}

fn deployed_address(txnv: &TransactionVariant) -> Option<starknet_api::core::ContractAddress> {
    match txnv {
        TransactionVariant::DeployAccountV3(t) => Some(starknet_api::core::ContractAddress(
            starknet_api::core::PatriciaKey::try_from(t.contract_address.get().into_starkfelt())
                .expect("No contract address overflow expected"),
        )),
        TransactionVariant::DeclareV3(_)
        | TransactionVariant::InvokeV3(_)
        | TransactionVariant::L1Handler(_) => None,
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_)
        | TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_) => {
            unreachable!("Proposal parts don't carry older transaction versions: {txnv:?}")
        }
    }
}
