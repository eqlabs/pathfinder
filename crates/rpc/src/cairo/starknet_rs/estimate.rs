use pathfinder_common::EthereumAddress;
use primitive_types::U256;

use stark_hash::Felt;

use starknet_in_rust::transaction::error::TransactionError;
use starknet_in_rust::transaction::fee::calculate_tx_fee;
use starknet_in_rust::transaction::{L1Handler, Transaction};

use crate::v02::method::call::FunctionCall;
use crate::v02::types::request::BroadcastedTransaction;

use super::felt::IntoFelt252;
use super::transaction::{map_broadcasted_transaction, map_gateway_transaction};
use super::types::FeeEstimate;
use super::{error::CallError, ExecutionState};

pub fn estimate_fee(
    execution_state: ExecutionState,
    transactions: Vec<BroadcastedTransaction>,
) -> Result<Vec<FeeEstimate>, CallError> {
    let transactions = transactions
        .into_iter()
        .map(|tx| map_broadcasted_transaction(tx, execution_state.chain_id))
        .collect::<Result<Vec<_>, TransactionError>>()?;

    estimate_fee_impl(execution_state, transactions)
}

pub fn estimate_fee_for_gateway_transactions(
    mut execution_state: ExecutionState,
    transactions: Vec<starknet_gateway_types::reply::transaction::Transaction>,
) -> anyhow::Result<Vec<FeeEstimate>> {
    let db_tx = execution_state.connection.transaction()?;

    let transactions = transactions
        .into_iter()
        .map(|tx| map_gateway_transaction(tx, execution_state.chain_id, &db_tx))
        .collect::<Result<Vec<_>, _>>()?;

    drop(db_tx);

    let result = estimate_fee_impl(execution_state, transactions)
        .map_err(|e| anyhow::anyhow!("Estimate fee failed: {:?}", e))?;

    Ok(result)
}

pub fn estimate_message_fee(
    execution_state: ExecutionState,
    message: FunctionCall,
    sender_address: EthereumAddress,
) -> Result<FeeEstimate, CallError> {
    // prepend sender address to calldata
    let sender_address =
        Felt::from_be_slice(sender_address.0.as_bytes()).expect("Ethereum address is 160 bits");
    let calldata = std::iter::once(pathfinder_common::CallParam(sender_address))
        .chain(message.calldata.into_iter())
        .map(|p| p.0.into_felt252())
        .collect();

    let transaction = L1Handler::new(
        starknet_in_rust::utils::Address(message.contract_address.get().into_felt252()),
        message.entry_point_selector.0.into_felt252(),
        calldata,
        0.into(),
        execution_state.chain_id.0.into_felt252(),
        None,
    )?;
    let transaction = Transaction::L1Handler(transaction);

    let mut result = estimate_fee_impl(execution_state, vec![transaction])?;

    if result.len() != 1 {
        return Err(
            anyhow::anyhow!("Internal error: expected exactly one fee estimation result").into(),
        );
    }

    let result = result.pop().unwrap();

    Ok(result)
}

fn estimate_fee_impl(
    mut execution_state: ExecutionState,
    transactions: Vec<Transaction>,
) -> Result<Vec<FeeEstimate>, CallError> {
    let gas_price = execution_state.gas_price;
    let block_number = execution_state.block_number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut fees = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.iter().enumerate() {
        let span = tracing::debug_span!("execute", transaction_hash=%super::transaction::transaction_hash(transaction), %block_number, %transaction_idx);
        let _enter = span.enter();

        let transaction_for_simulation =
            transaction.create_for_simulation(false, false, true, false, false);
        let tx_info = transaction_for_simulation.execute(&mut state, &block_context, 100_000_000);

        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = tx_info.revert_error {
                    tracing::info!(%revert_error, "Transaction reverted");
                    return Err(CallError::Reverted(revert_error));
                }

                tracing::trace!(actual_fee=%tx_info.actual_fee, actual_resources=?tx_info.actual_resources, "Transaction estimation finished");
                // L1Handler transactions don't normally calculate the fee -- we have to do that after execution.
                let actual_fee = match transaction {
                    Transaction::L1Handler(_) => calculate_tx_fee(
                        &tx_info.actual_resources,
                        gas_price.as_u128(),
                        &block_context,
                    )?,
                    _ => tx_info.actual_fee,
                };

                fees.push(FeeEstimate {
                    gas_consumed: U256::from(actual_fee) / gas_price.max(1.into()),
                    gas_price,
                    overall_fee: actual_fee.into(),
                });
            }
            Err(error) => {
                tracing::error!(%error, %transaction_idx, "Transaction estimation failed");
                return Err(error.into());
            }
        }

        state.cache_mut().update_initial_values();
    }
    Ok(fees)
}
