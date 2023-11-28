use super::{
    error::TransactionExecutionError, execution_state::ExecutionState, types::FeeEstimate,
};

use blockifier::{
    transaction::transaction_execution::Transaction,
    transaction::transactions::ExecutableTransaction,
};
use primitive_types::U256;

pub fn estimate(
    mut execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let gas_price: U256 = execution_state.header.eth_l1_gas_price.0.into();
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("estimate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let fee_type = &super::transaction::fee_type(&transaction);

        let tx_info = transaction
            .execute(&mut state, &block_context, false, true)
            .and_then(|mut tx_info| {
                if tx_info.actual_fee.0 == 0 {
                    // fee is not calculated by default for L1 handler transactions and if max_fee is zero, we have to do that explicitly
                    tx_info.actual_fee = blockifier::fee::fee_utils::calculate_tx_fee(
                        &tx_info.actual_resources,
                        &block_context,
                        fee_type,
                    )?;
                }

                Ok(tx_info)
            });

        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = tx_info.revert_error {
                    tracing::debug!(%revert_error, "Transaction reverted");
                    return Err(TransactionExecutionError::ExecutionError {
                        transaction_index: transaction_idx,
                        error: revert_error,
                    });
                }

                tracing::trace!(actual_fee=%tx_info.actual_fee.0, actual_resources=?tx_info.actual_resources, "Transaction estimation finished");

                fees.push(FeeEstimate {
                    gas_consumed: U256::from(tx_info.actual_fee.0) / gas_price.max(1.into()),
                    gas_price,
                    overall_fee: tx_info.actual_fee.0.into(),
                });
            }
            Err(error) => {
                tracing::debug!(%error, %transaction_idx, "Transaction estimation failed");
                return Err(TransactionExecutionError::ExecutionError {
                    transaction_index: transaction_idx,
                    error: error.to_string(),
                });
            }
        }
    }
    Ok(fees)
}
