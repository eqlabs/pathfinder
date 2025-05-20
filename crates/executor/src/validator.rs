use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use blockifier::state::cached_state::StateChanges;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::{ChainId, ClassHash, ContractAddress, TransactionHash};

use crate::execution_state::{create_executor, PathfinderExecutionState, PathfinderExecutor};
use crate::simulate::{
    to_state_diff,
    to_trace,
    transaction_declared_deprecated_class,
    transaction_type,
};
use crate::transaction::{execute_transaction, ExecutionBehaviorOnRevert};
use crate::types::{BlockInfo, FeeEstimate, StateDiff, TransactionSimulation};
use crate::{ExecutionState, IntoFelt, Transaction, TransactionExecutionError};

pub struct Validator<'a> {
    executor: PathfinderExecutor<'a>,
    initial_state: PathfinderExecutionState<'a>,
    declared_deprecated_classes: Vec<ClassHash>,
    next_txn_idx: usize,
}

type ReceiptAndEvents = (Receipt, Vec<pathfinder_common::event::Event>);

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

    pub fn execute(
        &mut self,
        txns: Vec<Transaction>,
    ) -> Result<Vec<ReceiptAndEvents>, TransactionExecutionError> {
        let start_tx_index = self.next_txn_idx;
        self.next_txn_idx += txns.len();
        let block_number = self.executor.block_context.block_info().block_number;
        let sims = txns
            .into_iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                let tx_index = start_tx_index + tx_index;
                let _span = tracing::debug_span!(
                    "Validator::execute",
                    block_number = %block_number,
                    transaction_hash = %TransactionHash(Transaction::tx_hash(&tx).0.into_felt()),
                    transaction_index = %tx_index
                )
                .entered();

                let tx_type = transaction_type(&tx);
                transaction_declared_deprecated_class(&tx)
                    .map(|class| self.declared_deprecated_classes.push(class));
                let gas_vector_computation_mode =
                    crate::transaction::gas_vector_computation_mode(&tx);

                let ((tx_info, _), gas_limit) = execute_transaction(
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

                // TODO FIXME The following blows up rustfmt
                //tracing::trace!(actual_fee=%tx_info.receipt.fee.0,
                // actual_resources=?tx_info.receipt.resources, "Transaction execution
                // finished");

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
                        // TODO we're using the final state diff from the executor because we
                        // need the storage for the special system contracts too
                        StateDiff::default(),
                        self.executor.block_context.versioned_constants(),
                        &gas_vector_computation_mode,
                    ),
                })
            })
            .collect::<Result<Vec<_>, TransactionExecutionError>>()?;
        sims.into_iter()
            .map(|sim| ReceiptAndEvents::try_from(sim).map_err(TransactionExecutionError::Custom))
            .collect::<Result<_, _>>()
    }

    pub fn finalize(self) -> anyhow::Result<StateDiff> {
        let Self {
            executor,
            initial_state,
            declared_deprecated_classes,
            ..
        } = self;

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
