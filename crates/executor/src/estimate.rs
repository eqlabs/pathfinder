use super::{error::CallError, execution_state::ExecutionState, types::FeeEstimate};

use blockifier::{
    transaction::transaction_execution::Transaction,
    transaction::transactions::ExecutableTransaction,
};
use primitive_types::U256;

pub fn estimate(
    mut execution_state: ExecutionState,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, CallError> {
    let gas_price = execution_state.gas_price;
    let block_number = execution_state.block_number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("estimate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let tx_info = match transaction {
            Transaction::AccountTransaction(transaction) => {
                transaction.execute(&mut state, &block_context)
            }
            Transaction::L1HandlerTransaction(transaction) => transaction
                .execute(&mut state, &block_context)
                .and_then(|mut tx_info| {
                    // fee is not calculated by default for L1 handler transactions, we have to do that explicitly
                    tx_info.actual_fee = blockifier::fee::fee_utils::calculate_tx_fee(
                        &tx_info.actual_resources,
                        &block_context,
                    )?;
                    Ok(tx_info)
                }),
        };

        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = tx_info.revert_error {
                    tracing::info!(%revert_error, "Transaction reverted");
                    return Err(CallError::Reverted(revert_error));
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
                return Err(error.into());
            }
        }
    }
    Ok(fees)
}
