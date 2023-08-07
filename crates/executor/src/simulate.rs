use blockifier::{
    transaction::transaction_execution::Transaction,
    transaction::{errors::TransactionExecutionError, transactions::ExecutableTransaction},
};
use primitive_types::U256;

use crate::types::{
    DeclareTransactionTrace, DeployAccountTransactionTrace, InvokeTransactionTrace,
    L1HandlerTransactionTrace,
};

use super::{
    error::CallError,
    execution_state::ExecutionState,
    types::{FeeEstimate, TransactionSimulation, TransactionTrace},
};

pub fn simulate(
    mut execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    skip_validate: bool,
    skip_fee_charge: bool,
) -> Result<Vec<TransactionSimulation>, CallError> {
    let gas_price = execution_state.gas_price;
    let block_number = execution_state.block_number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut simulations = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("simulate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let transaction_type = transaction_type(&transaction);

        let tx_info = match transaction {
            Transaction::AccountTransaction(transaction) => transaction
                .execute(&mut state, &block_context)
                .and_then(|mut tx_info| {
                    // skipping fee charge in .execute() means that the fee isn't calculated either, do that explicitly
                    if skip_fee_charge {
                        tx_info.actual_fee = blockifier::fee::fee_utils::calculate_tx_fee(
                            &tx_info.actual_resources,
                            &block_context,
                        )?
                    };
                    Ok(tx_info)
                }),
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

                tracing::trace!(actual_fee=%tx_info.actual_fee.0, actual_resources=?tx_info.actual_resources, "Transaction simulation finished");

                simulations.push(TransactionSimulation {
                    fee_estimation: FeeEstimate {
                        gas_consumed: U256::from(tx_info.actual_fee.0) / gas_price.max(1.into()),
                        gas_price,
                        overall_fee: tx_info.actual_fee.0.into(),
                    },
                    trace: to_trace(transaction_type, tx_info)?,
                });
            }
            Err(error) => {
                tracing::debug!(%error, %transaction_idx, "Transaction simulation failed");
                return Err(error.into());
            }
        }
    }
    Ok(simulations)
}

enum TransactionType {
    Declare,
    DeployAccount,
    Invoke,
    L1Handler,
}

fn transaction_type(transaction: &Transaction) -> TransactionType {
    match transaction {
        Transaction::AccountTransaction(tx) => match tx {
            blockifier::transaction::account_transaction::AccountTransaction::Declare(_) => {
                TransactionType::Declare
            }
            blockifier::transaction::account_transaction::AccountTransaction::DeployAccount(_) => {
                TransactionType::DeployAccount
            }
            blockifier::transaction::account_transaction::AccountTransaction::Invoke(_) => {
                TransactionType::Invoke
            }
        },
        Transaction::L1HandlerTransaction(_) => TransactionType::L1Handler,
    }
}

fn to_trace(
    transaction_type: TransactionType,
    execution_info: blockifier::transaction::objects::TransactionExecutionInfo,
) -> Result<TransactionTrace, TransactionExecutionError> {
    tracing::warn!(?execution_info, "Transforming trace");
    let validate_invocation = execution_info
        .validate_call_info
        .map(TryInto::try_into)
        .transpose()?;
    let function_invocation = execution_info
        .execute_call_info
        .map(TryInto::try_into)
        .transpose()?;
    let fee_transfer_invocation = execution_info
        .fee_transfer_call_info
        .map(TryInto::try_into)
        .transpose()?;

    let trace = match transaction_type {
        TransactionType::Declare => TransactionTrace::Declare(DeclareTransactionTrace {
            validate_invocation,
            fee_transfer_invocation,
        }),
        TransactionType::DeployAccount => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                validate_invocation,
                constructor_invocation: function_invocation,
                fee_transfer_invocation,
            })
        }
        TransactionType::Invoke => TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation,
            execute_invocation: function_invocation,
            fee_transfer_invocation,
        }),
        TransactionType::L1Handler => TransactionTrace::L1Handler(L1HandlerTransactionTrace {
            function_invocation,
        }),
    };

    Ok(trace)
}
