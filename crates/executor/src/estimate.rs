use blockifier::blockifier::transaction_executor::BLOCK_STATE_ACCESS_ERR;
use blockifier::transaction::objects::HasRelatedFeeType;
use blockifier::transaction::transaction_execution::Transaction;
use pathfinder_common::TransactionHash;
use starknet_api::block::FeeType;
use starknet_api::execution_resources::GasVector;
use starknet_api::transaction::fields::GasVectorComputationMode;
use util::percentage::Percentage;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::types::FeeEstimate;
use crate::execution_state::create_executor;
use crate::transaction::{
    execute_transaction,
    find_l2_gas_limit_and_execute_transaction,
    l2_gas_accounting_enabled,
    ExecutionBehaviorOnRevert,
};
use crate::IntoFelt;

pub fn estimate(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    epsilon: Percentage,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let block_number = execution_state.header.number;
    let mut tx_executor = create_executor(db_tx, execution_state)?;

    transactions
        .into_iter()
        .enumerate()
        .map(|(tx_index, mut tx)| {
            let _span = tracing::debug_span!(
                "estimate",
                block_number = %block_number,
                transaction_hash = %TransactionHash(Transaction::tx_hash(&tx).0.into_felt()),
                transaction_index = %tx_index
            )
            .entered();

            let gas_vector_computation_mode = super::transaction::gas_vector_computation_mode(&tx);
            let ((tx_info, _), gas_limit) = if l2_gas_accounting_enabled(
                &tx,
                tx_executor
                    .block_state
                    .as_ref()
                    .expect(BLOCK_STATE_ACCESS_ERR),
                &tx_executor.block_context,
                &gas_vector_computation_mode,
            )? {
                find_l2_gas_limit_and_execute_transaction(
                    &mut tx,
                    tx_index,
                    &mut tx_executor,
                    ExecutionBehaviorOnRevert::Fail,
                    epsilon,
                )?
            } else {
                execute_transaction(
                    &tx,
                    tx_index,
                    &mut tx_executor,
                    ExecutionBehaviorOnRevert::Fail,
                )?
            };

            tracing::trace!(
                actual_fee = %tx_info.receipt.fee.0,
                actual_resources = ?tx_info.receipt.resources,
                "Transaction estimation finished"
            );

            Ok(FeeEstimate::from_tx_and_gas_vector(
                &tx,
                &gas_limit,
                &gas_vector_computation_mode,
                &tx_executor.block_context,
            ))
        })
        .collect()
}

impl FeeEstimate {
    pub(crate) fn from_tx_and_gas_vector(
        transaction: &Transaction,
        gas_vector: &GasVector,
        gas_vector_computation_mode: &GasVectorComputationMode,
        block_context: &blockifier::context::BlockContext,
    ) -> Self {
        let fee_type = fee_type(transaction);
        let minimal_gas_vector = match transaction {
            Transaction::Account(account_transaction) => {
                Some(blockifier::fee::gas_usage::estimate_minimal_gas_vector(
                    block_context,
                    account_transaction,
                    gas_vector_computation_mode,
                ))
            }
            Transaction::L1Handler(_) => None,
        };

        FeeEstimate::from_gas_vector_and_gas_price(
            gas_vector,
            block_context.block_info(),
            fee_type,
            &minimal_gas_vector,
        )
    }
}

pub fn fee_type(transaction: &Transaction) -> FeeType {
    match transaction {
        Transaction::Account(tx) => tx.fee_type(),
        Transaction::L1Handler(tx) => tx.fee_type(),
    }
}
