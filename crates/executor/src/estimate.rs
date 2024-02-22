use crate::types::PriceUnit;

use super::{
    error::TransactionExecutionError, execution_state::ExecutionState, types::FeeEstimate,
};

use blockifier::{
    transaction::transaction_execution::Transaction,
    transaction::transactions::ExecutableTransaction,
};

pub fn estimate(
    mut execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
    skip_validate: bool,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("estimate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let fee_type = &super::transaction::fee_type(&transaction);

        let gas_price = block_context
            .block_info()
            .gas_prices
            .get_gas_price_by_fee_type(fee_type)
            .get();
        let data_gas_price = block_context
            .block_info()
            .gas_prices
            .get_data_gas_price_by_fee_type(fee_type)
            .get();
        let unit = match fee_type {
            blockifier::transaction::objects::FeeType::Strk => PriceUnit::Fri,
            blockifier::transaction::objects::FeeType::Eth => PriceUnit::Wei,
        };

        let tx_info = transaction
            .execute(&mut state, &block_context, false, !skip_validate)
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

                fees.push(FeeEstimate::from_tx_info_and_gas_price(
                    &tx_info,
                    gas_price,
                    data_gas_price,
                    unit,
                ));
            }
            Err(error) => {
                tracing::debug!(%error, %transaction_idx, "Transaction estimation failed");
                return Err(TransactionExecutionError::new(transaction_idx, error));
            }
        }
    }
    Ok(fees)
}
