use primitive_types::U256;

use starknet_in_rust::transaction::error::TransactionError;
use starknet_in_rust::transaction::Transaction;

use crate::cairo::starknet_rs::types::{
    DeclareTransactionTrace, DeployAccountTransactionTrace, InvokeTransactionTrace,
    L1HandlerTransactionTrace,
};
use crate::v02::types::request::BroadcastedTransaction;

use super::transaction::map_broadcasted_transaction;
use super::types::{FeeEstimate, TransactionSimulation, TransactionTrace};
use super::{error::CallError, ExecutionState};

pub fn simulate(
    mut execution_state: ExecutionState,
    transactions: Vec<BroadcastedTransaction>,
    skip_validate: bool,
) -> Result<Vec<TransactionSimulation>, CallError> {
    let gas_price = execution_state.gas_price;
    let block_number = execution_state.block_number;

    let transactions = transactions
        .into_iter()
        .map(|tx| map_broadcasted_transaction(tx, execution_state.chain_id))
        .collect::<Result<Vec<_>, TransactionError>>()?;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut simulations = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.iter().enumerate() {
        let span = tracing::debug_span!("execute", transaction_hash=%super::transaction::transaction_hash(transaction), %block_number);
        let _enter = span.enter();

        let transaction_for_simulation =
            transaction.create_for_simulation(skip_validate, false, true);
        let tx_info = transaction_for_simulation.execute(&mut state, &block_context, 1_000_000);
        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = tx_info.revert_error {
                    tracing::info!(%revert_error, "Transaction reverted");
                    return Err(CallError::Reverted(revert_error));
                }

                tracing::trace!(actual_fee=%tx_info.actual_fee, "Transaction simulation finished");
                simulations.push(TransactionSimulation {
                    fee_estimation: FeeEstimate {
                        gas_consumed: U256::from(tx_info.actual_fee)
                            / std::cmp::max(1.into(), gas_price),
                        gas_price,
                        overall_fee: tx_info.actual_fee.into(),
                    },
                    trace: to_trace(transaction, tx_info)?,
                });
            }
            Err(error) => {
                tracing::error!(%error, %transaction_idx, "Transaction simulation failed");
                return Err(error.into());
            }
        }
    }
    Ok(simulations)
}

fn to_trace(
    transaction: &Transaction,
    execution_info: starknet_in_rust::execution::TransactionExecutionInfo,
) -> Result<TransactionTrace, TransactionError> {
    tracing::warn!(?execution_info, "Transforming trace");
    let validate_invocation = execution_info
        .validate_info
        .map(TryInto::try_into)
        .transpose()?;
    let function_invocation = execution_info
        .call_info
        .map(TryInto::try_into)
        .transpose()?;
    let fee_transfer_invocation = execution_info
        .fee_transfer_info
        .map(TryInto::try_into)
        .transpose()?;

    let trace = match transaction {
        Transaction::Declare(_) | Transaction::DeclareV2(_) => {
            TransactionTrace::Declare(DeclareTransactionTrace {
                validate_invocation,
                fee_transfer_invocation,
            })
        }
        Transaction::Deploy(_) => {
            panic!("Internal error, no deploy transactions are possible here")
        }
        Transaction::DeployAccount(_) => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                validate_invocation,
                constructor_invocation: function_invocation,
                fee_transfer_invocation,
            })
        }
        Transaction::InvokeFunction(_) => TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation,
            execute_invocation: function_invocation,
            fee_transfer_invocation,
        }),
        Transaction::L1Handler(_) => TransactionTrace::L1Handler(L1HandlerTransactionTrace {
            function_invocation,
        }),
    };

    Ok(trace)
}
