use std::collections::HashMap;

use anyhow::Context;
use blockifier::{
    state::{
        cached_state::{CachedState, CommitmentStateDiff},
        state_api::State,
    },
    transaction::transaction_execution::Transaction,
    transaction::{errors::TransactionExecutionError, transactions::ExecutableTransaction},
};
use pathfinder_common::{
    CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress, StorageValue,
    TransactionHash,
};
use primitive_types::U256;
use stark_hash::Felt;
use starknet_gateway_types::reply::state_update::{
    DeclaredSierraClass, DeployedContract, StateDiff, StorageDiff,
};

use crate::{
    transaction::transaction_hash,
    types::{
        DeclareTransactionTrace, DeployAccountTransactionTrace, ExecuteInvocation,
        InvokeTransactionTrace, L1HandlerTransactionTrace,
    },
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

        let mut tx_state = CachedState::<_>::create_transactional(&mut state);
        let tx_info = transaction
            .execute(
                &mut tx_state,
                &block_context,
                !skip_fee_charge,
                !skip_validate,
            )
            .and_then(|mut tx_info| {
                // skipping fee charge in .execute() means that the fee isn't calculated, do that explicitly
                // some other cases, like having max_fee=0 also lead to not calculating fees
                if tx_info.actual_fee.0 == 0 {
                    tx_info.actual_fee = blockifier::fee::fee_utils::calculate_tx_fee(
                        &tx_info.actual_resources,
                        &block_context,
                    )?
                };
                Ok(tx_info)
            });
        let state_diff = map_state_diff(tx_state.to_state_diff())
            .context("simulate transaction: map state diff")?;
        tx_state.commit();

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
                    trace: to_trace(transaction_type, tx_info, state_diff)?,
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

pub fn trace_one(
    mut execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    target_transaction_hash: TransactionHash,
    charge_fee: bool,
    validate: bool,
) -> Result<TransactionTrace, CallError> {
    let (mut state, block_context) = execution_state.starknet_state()?;

    for tx in transactions {
        let hash = transaction_hash(&tx);
        let tx_type = transaction_type(&tx);

        let mut tx_state = CachedState::<_>::create_transactional(&mut state);
        let tx_info = tx.execute(&mut tx_state, &block_context, charge_fee, validate)?;
        let state_diff = map_state_diff(tx_state.to_state_diff())
            .context("simulate transaction: map state diff")?;
        tx_state.commit();

        let trace = to_trace(tx_type, tx_info, state_diff)?;
        if hash == target_transaction_hash {
            return Ok(trace);
        }
    }

    Err(CallError::Internal(anyhow::anyhow!(
        "Transaction hash not found: {}",
        target_transaction_hash
    )))
}

pub fn trace_all(
    mut execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    charge_fee: bool,
    validate: bool,
) -> Result<Vec<(TransactionHash, TransactionTrace)>, CallError> {
    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut ret = Vec::with_capacity(transactions.len());
    for tx in transactions {
        let hash = transaction_hash(&tx);
        let tx_type = transaction_type(&tx);

        let mut tx_state = CachedState::<_>::create_transactional(&mut state);
        let tx_info = tx.execute(&mut tx_state, &block_context, charge_fee, validate)?;
        let state_diff = map_state_diff(tx_state.to_state_diff())
            .context("simulate transaction: map state diff")?;
        tx_state.commit();

        let trace = to_trace(tx_type, tx_info, state_diff)?;
        ret.push((hash, trace));
    }

    Ok(ret)
}

fn map_state_diff(state_diff: CommitmentStateDiff) -> anyhow::Result<StateDiff> {
    Ok(StateDiff {
        storage_diffs: state_diff
            .storage_updates
            .into_iter()
            .map(|(addess, updates)| {
                let address =
                    ContractAddress::new_or_panic(Felt::from_be_slice(addess.0.key().bytes())?);
                let updates = updates
                    .into_iter()
                    .map(|(key, val)| {
                        let key =
                            StorageAddress::new_or_panic(Felt::from_be_slice(key.0.key().bytes())?);
                        let value = StorageValue(Felt::from_be_slice(val.bytes())?);
                        Ok(StorageDiff { key, value })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok::<(pathfinder_common::ContractAddress, Vec<StorageDiff>), anyhow::Error>((
                    address, updates,
                ))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?,
        deployed_contracts: state_diff
            .address_to_class_hash
            .into_iter()
            .map(|(address, class_hash)| {
                let address =
                    ContractAddress::new_or_panic(Felt::from_be_slice(address.0.key().bytes())?);
                let class_hash = ClassHash(Felt::from_be_slice(class_hash.0.bytes())?);
                Ok(DeployedContract {
                    address,
                    class_hash,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        old_declared_contracts: Default::default(),
        declared_classes: state_diff
            .class_hash_to_compiled_class_hash
            .into_iter()
            .map(|(class_hash, compiled_chass_hash)| {
                let class_hash = SierraHash(Felt::from_be_slice(class_hash.0.bytes())?);
                let compiled_class_hash =
                    CasmHash(Felt::from_be_slice(compiled_chass_hash.0.bytes())?);
                Ok(DeclaredSierraClass {
                    class_hash,
                    compiled_class_hash,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        nonces: state_diff
            .address_to_nonce
            .into_iter()
            .map(|(address, nonce)| {
                let address =
                    ContractAddress::new_or_panic(Felt::from_be_slice(address.0.key().bytes())?);
                let nonce = ContractNonce(Felt::from_be_slice(nonce.0.bytes())?);
                Ok((address, nonce))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?,
        replaced_classes: Default::default(),
    })
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
    state_diff: StateDiff,
) -> Result<TransactionTrace, TransactionExecutionError> {
    tracing::trace!(?execution_info, "Transforming trace");

    let validate_invocation = execution_info
        .validate_call_info
        .map(TryInto::try_into)
        .transpose()?;
    let maybe_function_invocation = execution_info
        .execute_call_info
        .map(TryInto::try_into)
        .transpose();
    let fee_transfer_invocation = execution_info
        .fee_transfer_call_info
        .map(TryInto::try_into)
        .transpose()?;

    let trace = match transaction_type {
        TransactionType::Declare => TransactionTrace::Declare(DeclareTransactionTrace {
            validate_invocation,
            fee_transfer_invocation,
            state_diff: Some(state_diff),
        }),
        TransactionType::DeployAccount => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                validate_invocation,
                constructor_invocation: maybe_function_invocation?,
                fee_transfer_invocation,
                state_diff: Some(state_diff),
            })
        }
        TransactionType::Invoke => TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation,
            execute_invocation: if let Some(reason) = execution_info.revert_error {
                ExecuteInvocation::RevertedReason(reason)
            } else {
                ExecuteInvocation::FunctionInvocation(maybe_function_invocation?)
            },
            fee_transfer_invocation,
            state_diff: Some(state_diff),
        }),
        TransactionType::L1Handler => TransactionTrace::L1Handler(L1HandlerTransactionTrace {
            function_invocation: maybe_function_invocation?,
        }),
    };

    Ok(trace)
}
