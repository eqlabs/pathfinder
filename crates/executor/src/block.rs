use anyhow::Context;
use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use blockifier::state::cached_state::StateChanges;
use pathfinder_common::{ChainId, ClassHash, ContractAddress, TransactionHash, TransactionIndex};

use crate::execution_state::{create_executor, PathfinderExecutionState, PathfinderExecutor};
use crate::transaction::{execute_transaction, ExecutionBehaviorOnRevert};
use crate::types::{
    to_receipt_and_events,
    to_state_diff,
    transaction_declared_deprecated_class,
    transaction_type,
    BlockInfo,
    Receipt,
    StateDiff,
};
use crate::{ExecutionState, IntoFelt, Transaction, TransactionExecutionError};

/// Executes transactions from a single block. Produces transactions receipts,
/// events, and the final state diff for the entire block.
pub struct BlockExecutor<'a> {
    executor: PathfinderExecutor<'a>,
    initial_state: PathfinderExecutionState<'a>,
    declared_deprecated_classes: Vec<ClassHash>,
    next_txn_idx: usize,
}

type ReceiptAndEvents = (Receipt, Vec<pathfinder_common::event::Event>);

impl<'a> BlockExecutor<'a> {
    pub fn new(
        chain_id: ChainId,
        block_info: BlockInfo,
        eth_fee_address: ContractAddress,
        strk_fee_address: ContractAddress,
        db_tx: pathfinder_storage::Transaction<'a>,
    ) -> anyhow::Result<Self> {
        let execution_state = ExecutionState::validation(
            chain_id,
            block_info,
            None,
            Default::default(),
            eth_fee_address,
            strk_fee_address,
            None,
        );
        let executor = create_executor(db_tx, execution_state)?;
        let initial_state = executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .clone();

        Ok(Self {
            executor,
            initial_state,
            declared_deprecated_classes: Vec::new(),
            next_txn_idx: 0,
        })
    }

    /// Evecute a batch of transactions in the current block.
    pub fn execute(
        &mut self,
        txns: Vec<Transaction>,
    ) -> Result<Vec<ReceiptAndEvents>, TransactionExecutionError> {
        let start_tx_index = self.next_txn_idx;
        self.next_txn_idx += txns.len();
        let block_number = self.executor.block_context.block_info().block_number;
        let receipts_events = txns
            .into_iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                let tx_index = start_tx_index + tx_index;
                let _span = tracing::debug_span!(
                    "BlockExecutor::execute",
                    block_number = %block_number,
                    transaction_hash = %TransactionHash(Transaction::tx_hash(&tx).0.into_felt()),
                    transaction_index = %tx_index
                )
                .entered();

                let tx_type = transaction_type(&tx);
                if let Some(class) = transaction_declared_deprecated_class(&tx) {
                    self.declared_deprecated_classes.push(class)
                }
                let gas_vector_computation_mode =
                    crate::transaction::gas_vector_computation_mode(&tx);

                // TODO use executor::execute_txs instead (concurrency can then be enabled via
                // configuration)
                let ((tx_info, _), _) = execute_transaction(
                    &tx,
                    tx_index,
                    &mut self.executor,
                    ExecutionBehaviorOnRevert::Continue,
                )?;

                tracing::trace!(
                    "Transaction execution finished, actual_fee: {}, actual_resources: {:?}",
                    tx_info.receipt.fee.0,
                    tx_info.receipt.resources
                );

                to_receipt_and_events(
                    tx_type,
                    TransactionIndex::new(tx_index.try_into().expect("ptr size is 64bits"))
                        .context("tx_index < i64::MAX")?,
                    tx_info,
                    self.executor.block_context.versioned_constants(),
                    &gas_vector_computation_mode,
                )
                .map_err(TransactionExecutionError::Custom)
            })
            .collect::<Result<Vec<_>, TransactionExecutionError>>()?;
        Ok(receipts_events)
    }

    /// Finalizes block execution and returns the state diff for the block.
    pub fn finalize(self) -> anyhow::Result<StateDiff> {
        let Self {
            mut executor,
            initial_state,
            declared_deprecated_classes,
            ..
        } = self;

        executor.finalize()?;

        let mut state = executor.block_state.expect(BLOCK_STATE_ACCESS_ERR);
        let StateChanges { state_maps, .. } = state.to_state_diff()?;
        let diff = to_state_diff(
            state_maps,
            initial_state,
            declared_deprecated_classes.into_iter(),
        )?;
        Ok(diff)
    }
}
