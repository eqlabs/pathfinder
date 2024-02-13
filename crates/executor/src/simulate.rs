use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use blockifier::{
    state::{cached_state::CachedState, errors::StateError, state_api::State},
    transaction::transaction_execution::Transaction,
    transaction::transactions::ExecutableTransaction,
};
use cached::{Cached, SizedCache};
use pathfinder_common::{
    BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress,
    StorageValue, TransactionHash,
};
use primitive_types::U256;

use crate::{
    transaction::transaction_hash,
    types::{
        DeclareTransactionTrace, DeclaredSierraClass, DeployAccountTransactionTrace,
        DeployedContract, ExecuteInvocation, InvokeTransactionTrace, L1HandlerTransactionTrace,
        PriceUnit, ReplacedClass, StateDiff, StorageDiff,
    },
    IntoFelt,
};

use super::{
    error::TransactionExecutionError,
    execution_state::ExecutionState,
    types::{FeeEstimate, TransactionSimulation, TransactionTrace},
};

#[derive(Debug, Clone)]
enum CacheItem {
    Inflight(tokio::sync::broadcast::Sender<Traces>),
    Cached(Traces),
}

#[derive(Debug, Clone)]
pub struct TraceCache(Arc<Mutex<SizedCache<BlockHash, CacheItem>>>);

type Traces = Vec<(TransactionHash, TransactionTrace)>;

impl Default for TraceCache {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(SizedCache::with_size(128))))
    }
}

pub fn simulate(
    mut execution_state: ExecutionState<'_>,
    transactions: Vec<Transaction>,
    skip_validate: bool,
    skip_fee_charge: bool,
) -> Result<Vec<TransactionSimulation>, TransactionExecutionError> {
    let block_number = execution_state.header.number;

    let (mut state, block_context) = execution_state.starknet_state()?;

    let mut simulations = Vec::with_capacity(transactions.len());
    for (transaction_idx, transaction) in transactions.into_iter().enumerate() {
        let _span = tracing::debug_span!("simulate", transaction_hash=%super::transaction::transaction_hash(&transaction), %block_number, %transaction_idx).entered();

        let transaction_type = transaction_type(&transaction);
        let transaction_declared_deprecated_class_hash =
            transaction_declared_deprecated_class(&transaction);
        let fee_type = &super::transaction::fee_type(&transaction);
        let gas_price: U256 = block_context.gas_prices.get_by_fee_type(fee_type).into();
        let unit = match fee_type {
            blockifier::transaction::objects::FeeType::Strk => PriceUnit::Fri,
            blockifier::transaction::objects::FeeType::Eth => PriceUnit::Wei,
        };

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
                        fee_type,
                    )?
                };
                Ok(tx_info)
            });
        let state_diff = to_state_diff(&mut tx_state, transaction_declared_deprecated_class_hash)?;
        tx_state.commit();

        match tx_info {
            Ok(tx_info) => {
                if let Some(revert_error) = &tx_info.revert_error {
                    tracing::trace!(%revert_error, "Transaction reverted");
                }

                tracing::trace!(actual_fee=%tx_info.actual_fee.0, actual_resources=?tx_info.actual_resources, "Transaction simulation finished");

                simulations.push(TransactionSimulation {
                    fee_estimation: FeeEstimate {
                        gas_consumed: U256::from(tx_info.actual_fee.0) / gas_price.max(1.into()),
                        gas_price,
                        overall_fee: tx_info.actual_fee.0.into(),
                        unit,
                    },
                    trace: to_trace(transaction_type, tx_info, state_diff),
                });
            }
            Err(error) => {
                tracing::debug!(%error, %transaction_idx, "Transaction simulation failed");
                return Err(TransactionExecutionError::new(transaction_idx, error));
            }
        }
    }
    Ok(simulations)
}

pub fn trace(
    mut execution_state: ExecutionState<'_>,
    cache: TraceCache,
    block_hash: BlockHash,
    transactions: Vec<Transaction>,
    charge_fee: bool,
    validate: bool,
) -> Result<Vec<(TransactionHash, TransactionTrace)>, TransactionExecutionError> {
    let (mut state, block_context) = execution_state.starknet_state()?;

    let sender = {
        let mut cache = cache.0.lock().unwrap();
        match cache.cache_get(&block_hash) {
            Some(CacheItem::Cached(cached)) => {
                tracing::trace!(block=%block_hash, "trace cache hit");
                return Ok(cached.clone());
            }
            Some(CacheItem::Inflight(receiver)) => {
                tracing::trace!(block=%block_hash, "trace already inflight");
                let mut receiver = receiver.subscribe();
                drop(cache);

                let trace = receiver
                    .blocking_recv()
                    .context("Waiting for inflight trace")?;
                return Ok(trace);
            }
            None => {
                tracing::trace!(block=%block_hash, "trace cache miss");
                let (sender, _receiver) = tokio::sync::broadcast::channel(1);
                cache.cache_set(block_hash, CacheItem::Inflight(sender.clone()));
                sender
            }
        }
    };

    tracing::trace!(block=%block_hash, "trace cache miss");
    let mut traces = Vec::with_capacity(transactions.len());
    for (transaction_idx, tx) in transactions.into_iter().enumerate() {
        let hash = transaction_hash(&tx);
        let _span = tracing::debug_span!("simulate", transaction_hash=%super::transaction::transaction_hash(&tx), %transaction_idx).entered();

        let tx_type = transaction_type(&tx);
        let tx_declared_deprecated_class_hash = transaction_declared_deprecated_class(&tx);

        let mut tx_state = CachedState::<_>::create_transactional(&mut state);
        let tx_info = tx
            .execute(&mut tx_state, &block_context, charge_fee, validate)
            .map_err(|e| TransactionExecutionError::ExecutionError {
                transaction_index: transaction_idx,
                error: e.to_string(),
            })?;
        let state_diff = to_state_diff(&mut tx_state, tx_declared_deprecated_class_hash)?;
        tx_state.commit();

        let trace = to_trace(tx_type, tx_info, state_diff);
        traces.push((hash, trace));
    }

    let _ = sender.send(traces.clone());

    cache
        .0
        .lock()
        .unwrap()
        .cache_set(block_hash, CacheItem::Cached(traces.clone()));
    Ok(traces)
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

fn transaction_declared_deprecated_class(transaction: &Transaction) -> Option<ClassHash> {
    match transaction {
        Transaction::AccountTransaction(
            blockifier::transaction::account_transaction::AccountTransaction::Declare(tx),
        ) => match tx.tx() {
            starknet_api::transaction::DeclareTransaction::V0(_)
            | starknet_api::transaction::DeclareTransaction::V1(_) => {
                Some(ClassHash(tx.class_hash().0.into_felt()))
            }
            starknet_api::transaction::DeclareTransaction::V2(_)
            | starknet_api::transaction::DeclareTransaction::V3(_) => None,
        },
        _ => None,
    }
}

fn to_state_diff<S: blockifier::state::state_api::StateReader>(
    state: &mut blockifier::state::cached_state::CachedState<S>,
    old_declared_contract: Option<ClassHash>,
) -> Result<StateDiff, StateError> {
    let state_diff = state.to_state_diff();

    let mut deployed_contracts = Vec::new();
    let mut replaced_classes = Vec::new();

    // We need to check the previous class hash for a contract to decide if it's a deployed
    // contract or a replaced class.
    for (address, class_hash) in state_diff.address_to_class_hash {
        let previous_class_hash = state.state.get_class_hash_at(address)?;

        if previous_class_hash.0.into_felt().is_zero() {
            deployed_contracts.push(DeployedContract {
                address: ContractAddress::new_or_panic(address.0.key().into_felt()),
                class_hash: ClassHash(class_hash.0.into_felt()),
            });
        } else {
            replaced_classes.push(ReplacedClass {
                contract_address: ContractAddress::new_or_panic(address.0.key().into_felt()),
                class_hash: ClassHash(class_hash.0.into_felt()),
            });
        }
    }

    Ok(StateDiff {
        storage_diffs: state_diff
            .storage_updates
            .into_iter()
            .map(|(address, diffs)| {
                // Output the storage updates in key order
                let diffs: BTreeMap<StorageAddress, StorageValue> = diffs
                    .into_iter()
                    .map(|(key, value)| {
                        (
                            StorageAddress::new_or_panic(key.0.key().into_felt()),
                            StorageValue(value.into_felt()),
                        )
                    })
                    .collect();
                (
                    ContractAddress::new_or_panic(address.0.key().into_felt()),
                    diffs
                        .into_iter()
                        .map(|(key, value)| StorageDiff { key, value })
                        .collect(),
                )
            })
            .collect(),
        deployed_contracts,
        // This info is not present in the state diff, so we need to pass it separately.
        deprecated_declared_classes: old_declared_contract.into_iter().collect(),
        declared_classes: state_diff
            .class_hash_to_compiled_class_hash
            .into_iter()
            .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
                class_hash: SierraHash(class_hash.0.into_felt()),
                compiled_class_hash: CasmHash(compiled_class_hash.0.into_felt()),
            })
            .collect(),
        nonces: state_diff
            .address_to_nonce
            .into_iter()
            .map(|(address, nonce)| {
                (
                    ContractAddress::new_or_panic(address.0.key().into_felt()),
                    ContractNonce(nonce.0.into_felt()),
                )
            })
            .collect(),
        replaced_classes,
    })
}

fn to_trace(
    transaction_type: TransactionType,
    execution_info: blockifier::transaction::objects::TransactionExecutionInfo,
    state_diff: StateDiff,
) -> TransactionTrace {
    let validate_invocation = execution_info.validate_call_info.map(Into::into);
    let maybe_function_invocation = execution_info.execute_call_info.map(Into::into);
    let fee_transfer_invocation = execution_info.fee_transfer_call_info.map(Into::into);

    match transaction_type {
        TransactionType::Declare => TransactionTrace::Declare(DeclareTransactionTrace {
            validate_invocation,
            fee_transfer_invocation,
            state_diff,
        }),
        TransactionType::DeployAccount => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                validate_invocation,
                constructor_invocation: maybe_function_invocation,
                fee_transfer_invocation,
                state_diff,
            })
        }
        TransactionType::Invoke => TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation,
            execute_invocation: if let Some(reason) = execution_info.revert_error {
                ExecuteInvocation::RevertedReason(reason)
            } else {
                ExecuteInvocation::FunctionInvocation(maybe_function_invocation)
            },
            fee_transfer_invocation,
            state_diff,
        }),
        TransactionType::L1Handler => TransactionTrace::L1Handler(L1HandlerTransactionTrace {
            function_invocation: maybe_function_invocation,
            state_diff,
        }),
    }
}
