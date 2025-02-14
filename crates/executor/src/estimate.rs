use blockifier::transaction::objects::TransactionExecutionInfo;
use blockifier::transaction::transaction_execution::Transaction;
use starknet_api::transaction::fields::GasVectorComputationMode;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::transaction::transaction_hash;
use super::types::FeeEstimate;
use crate::transaction::{
    execute_transaction,
    find_l2_gas_limit_and_execute_transaction,
    l2_gas_accounting_enabled,
};

pub fn estimate(
    execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    transactions
        .into_iter()
        .enumerate()
        .map(|(tx_index, mut tx)| {
            let _span = tracing::debug_span!(
                "estimate",
                block_number = %block_number,
                transaction_hash = %transaction_hash(&tx),
                transaction_index = %tx_index
            )
            .entered();

            let gas_vector_computation_mode = super::transaction::gas_vector_computation_mode(&tx);
            let tx_info = if l2_gas_accounting_enabled(
                &tx,
                &state,
                &block_context,
                &gas_vector_computation_mode,
            )? {
                find_l2_gas_limit_and_execute_transaction(
                    &mut tx,
                    tx_index,
                    &mut state,
                    &block_context,
                )?
            } else {
                execute_transaction(&tx, tx_index, &mut state, &block_context)?
            };

            tracing::trace!(
                actual_fee = %tx_info.receipt.fee.0,
                actual_resources = ?tx_info.receipt.resources,
                "Transaction estimation finished"
            );

            if let Some(revert_error) = tx_info.revert_error {
                let revert_string = revert_error.to_string();
                tracing::debug!(revert_error=%revert_string, "Transaction reverted");

                Err(TransactionExecutionError::ExecutionError {
                    transaction_index: tx_index,
                    error: revert_string,
                    error_stack: revert_error.into(),
                })
            } else {
                Ok(FeeEstimate::from_tx_and_tx_info(
                    &tx,
                    &tx_info,
                    &gas_vector_computation_mode,
                    &block_context,
                ))
            }
        })
        .collect()
}

impl FeeEstimate {
    pub(crate) fn from_tx_and_tx_info(
        transaction: &Transaction,
        tx_info: &TransactionExecutionInfo,
        gas_vector_computation_mode: &GasVectorComputationMode,
        block_context: &blockifier::context::BlockContext,
    ) -> Self {
        let fee_type = super::transaction::fee_type(transaction);
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

        FeeEstimate::from_tx_info_and_gas_price(
            tx_info,
            block_context.block_info(),
            fee_type,
            &minimal_gas_vector,
        )
    }
}
