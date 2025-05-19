use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::{ChainId, ContractAddress, TransactionHash};

use crate::execution_state::{create_executor, PathfinderExecutor};
use crate::simulate::{to_trace, transaction_declared_deprecated_class, transaction_type};
use crate::transaction::{execute_transaction, ExecutionBehaviorOnRevert};
use crate::types::{BlockInfo, FeeEstimate, StateDiff, TransactionSimulation};
use crate::{ExecutionState, IntoFelt, Transaction};

struct Validator<'a> {
    executor: PathfinderExecutor<'a>,
    next_txn_idx: usize,
}

impl<'a> Validator<'a> {
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

        Ok(Self {
            executor,
            next_txn_idx: 0,
        })
    }

    pub fn execute(&mut self, txns: Vec<Transaction>) -> Vec<(Receipt, Vec<Event>)>{
        let state_before_batch = self.executor
        .block_state
        .as_ref()
        .expect(BLOCK_STATE_ACCESS_ERR)
        .clone();
    let start_tx_index = self.next_txn_idx;
    self.next_txn_idx += txns.len();
    let block_number = self.executor.block_context.block_info().block_number;

    txns
        .into_iter()
        .enumerate()
        .map(|(tx_index, mut tx)| {
            let tx_index = start_tx_index + tx_index;
            let _span = tracing::debug_span!(
                "Validator::execute",
                block_number = %block_number,
                transaction_hash = %TransactionHash(Transaction::tx_hash(&tx).0.into_felt()),
                transaction_index = %tx_index
            )
            .entered();

            let tx_type = transaction_type(&tx);
            let tx_declared_deprecated_class_hash = transaction_declared_deprecated_class(&tx);
            let gas_vector_computation_mode = crate::transaction::gas_vector_computation_mode(&tx);

            let ((tx_info, state_maps), gas_limit) = 
                execute_transaction(&tx, tx_index, &mut self.executor, ExecutionBehaviorOnRevert::Continue)?;

            tracing::trace!(actual_fee=%tx_info.receipt.fee.0, actual_resources=?tx_info.receipt.resources, "Transaction execution finished");

            Ok(TransactionSimulation {
                fee_estimation: FeeEstimate::from_tx_and_gas_vector(
                    &tx,
                    &gas_limit,
                    &gas_vector_computation_mode,
                    &self.executor.block_context,
                ),
                trace: to_trace(
                    tx_type,
                    tx_info,
                    // TODO we're using the final state diff from the executor because we need the storage for the special system contracts too
                    StateDiff::default(),
                    self.executor.block_context.versioned_constants(),
                    &gas_vector_computation_mode,
                ),
            })
        })
        .collect::<Result<Vec<_>, _>>().map(|x| (x, next_start_idx))
    }

    pub fn finalize() {
        todo!()
    }
}
