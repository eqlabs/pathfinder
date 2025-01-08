use blockifier::transaction::transaction_execution::Transaction;
use blockifier::transaction::transactions::ExecutableTransaction;
use starknet_api::transaction::fields::GasVectorComputationMode;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::types::FeeEstimate;

pub fn estimate(
    execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, TransactionExecutionError> {
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("estimate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let fee_type = super::transaction::fee_type(&transaction);
        let minimal_l1_gas_amount_vector = match &transaction {
            Transaction::Account(account_transaction) => {
                Some(blockifier::fee::gas_usage::estimate_minimal_gas_vector(
                    &block_context,
                    account_transaction,
                    &GasVectorComputationMode::All,
                ))
            }
            Transaction::L1Handler(_) => None,
        };
        let tx_info: Result<
            blockifier::transaction::objects::TransactionExecutionInfo,
            blockifier::transaction::errors::TransactionExecutionError,
        > = transaction.execute(&mut state, &block_context);

        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = tx_info.revert_error {
                    let revert_string = revert_error.to_string();
                    tracing::debug!(revert_error=%revert_string, "Transaction reverted");
                    return Err(TransactionExecutionError::ExecutionError {
                        transaction_index: transaction_idx,
                        error: revert_string,
                        // TODO: is ErrorStack available?
                        error_stack: Default::default(),
                    });
                }

                tracing::trace!(actual_fee=%tx_info.receipt.fee.0, actual_resources=?tx_info.receipt.resources, "Transaction estimation finished");

                fees.push(FeeEstimate::from_tx_info_and_gas_price(
                    &tx_info,
                    block_context.block_info(),
                    fee_type,
                    &minimal_l1_gas_amount_vector,
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
