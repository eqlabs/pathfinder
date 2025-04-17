use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use blockifier::blockifier::transaction_executor::{
    TransactionExecutorError,
    BLOCK_STATE_ACCESS_ERR,
};
use blockifier::state::cached_state::StateMaps;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::transaction_execution::Transaction;
use blockifier::versioned_constants::VersionedConstants;
use cached::{Cached, SizedCache};
use pathfinder_common::prelude::*;
use starknet_api::transaction::fields::GasVectorComputationMode;
use util::percentage::Percentage;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::types::{TransactionSimulation, TransactionTrace};
use crate::error_stack::ErrorStack;
use crate::execution_state::{create_executor, PathfinderExecutionState};
use crate::transaction::{
    execute_transaction,
    find_l2_gas_limit_and_execute_transaction,
    l2_gas_accounting_enabled,
    ExecutionBehaviorOnRevert,
};
use crate::types::{
    DataAvailabilityResources,
    DeclareTransactionTrace,
    DeclaredSierraClass,
    DeployAccountTransactionTrace,
    DeployedContract,
    ExecuteInvocation,
    ExecutionResources,
    FeeEstimate,
    FunctionInvocation,
    InvokeTransactionTrace,
    L1HandlerTransactionTrace,
    ReplacedClass,
    StateDiff,
    StorageDiff,
};
use crate::IntoFelt;

#[derive(Debug)]
enum CacheItem {
    Inflight(tokio::sync::broadcast::Receiver<Result<Traces, TraceError>>),
    CachedOk(Traces),
    CachedErr(TraceError),
}

#[derive(Debug, Clone)]
enum TraceError {
    ExecutionError(ExecutionError),
    Internal(InternalError),
}

impl From<TraceError> for TransactionExecutionError {
    fn from(value: TraceError) -> Self {
        match value {
            TraceError::ExecutionError(execution_error) => Self::ExecutionError {
                transaction_index: execution_error.transaction_index,
                error: execution_error.error,
                error_stack: execution_error.error_stack,
            },
            TraceError::Internal(internal_error) => Self::Internal(anyhow::anyhow!(
                "Internal error: transaction index {}: {}",
                internal_error.transaction_index,
                internal_error.error
            )),
        }
    }
}

#[derive(Debug, Clone)]
struct ExecutionError {
    transaction_index: usize,
    error: String,
    error_stack: ErrorStack,
}

#[derive(Debug, Clone)]
struct InternalError {
    transaction_index: usize,
    error: String,
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
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    epsilon: Percentage,
) -> Result<Vec<TransactionSimulation>, TransactionExecutionError> {
    let block_number = execution_state.header.number;
    let mut tx_executor = create_executor(db_tx, execution_state)?;

    transactions
        .into_iter()
        .enumerate()
        .map(|(tx_index, mut tx)| {
            let _span = tracing::debug_span!(
                "simulate",
                block_number = %block_number,
                transaction_hash = %TransactionHash(Transaction::tx_hash(&tx).0.into_felt()),
                transaction_index = %tx_index
            )
            .entered();

            let tx_type = transaction_type(&tx);
            let tx_declared_deprecated_class_hash = transaction_declared_deprecated_class(&tx);
            let gas_vector_computation_mode = super::transaction::gas_vector_computation_mode(&tx);

            let initial_state = tx_executor
                .block_state
                .as_ref()
                .expect(BLOCK_STATE_ACCESS_ERR)
                .clone();
            let ((tx_info, state_maps), gas_limit) = if l2_gas_accounting_enabled(
                &tx,
                tx_executor.block_state.as_ref().expect(BLOCK_STATE_ACCESS_ERR),
                &tx_executor.block_context,
                &gas_vector_computation_mode,
            )? {
                find_l2_gas_limit_and_execute_transaction(
                    &mut tx,
                    tx_index,
                    &mut tx_executor,
                    ExecutionBehaviorOnRevert::Continue,
                    epsilon,
                )?
            } else {
                execute_transaction(&tx, tx_index, &mut tx_executor, ExecutionBehaviorOnRevert::Continue)?
            };
            let state_diff = to_state_diff(state_maps, initial_state, tx_declared_deprecated_class_hash)?;

            tracing::trace!(actual_fee=%tx_info.receipt.fee.0, actual_resources=?tx_info.receipt.resources, "Transaction simulation finished");

            Ok(TransactionSimulation {
                fee_estimation: FeeEstimate::from_tx_and_gas_vector(
                    &tx,
                    &gas_limit,
                    &gas_vector_computation_mode,
                    &tx_executor.block_context,
                ),
                trace: to_trace(
                    tx_type,
                    tx_info,
                    state_diff,
                    tx_executor.block_context.versioned_constants(),
                    &gas_vector_computation_mode,
                ),
            })
        })
        .collect()
}

pub fn trace(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    cache: TraceCache,
    block_hash: BlockHash,
    transactions: Vec<Transaction>,
) -> Result<Vec<(TransactionHash, TransactionTrace)>, TransactionExecutionError> {
    let mut tx_executor = create_executor(db_tx, execution_state)?;

    let sender = {
        let mut cache = cache.0.lock().unwrap();
        match cache.cache_get(&block_hash) {
            Some(CacheItem::CachedOk(cached)) => {
                tracing::trace!(block=%block_hash, "trace cache hit: ok");
                return Ok(cached.clone());
            }
            Some(CacheItem::CachedErr(e)) => {
                tracing::trace!(block=%block_hash, "trace cache hit: err");
                return Err(e.to_owned().into());
            }
            Some(CacheItem::Inflight(receiver)) => {
                tracing::trace!(block=%block_hash, "trace already inflight");
                let mut receiver = receiver.resubscribe();
                drop(cache);

                let trace = receiver.blocking_recv().context("Trace error")?;
                return trace.map_err(Into::into);
            }
            None => {
                tracing::trace!(block=%block_hash, "trace cache miss");
                let (sender, receiver) = tokio::sync::broadcast::channel(1);
                cache.cache_set(block_hash, CacheItem::Inflight(receiver));
                sender
            }
        }
    };

    let mut traces = Vec::with_capacity(transactions.len());
    for (transaction_idx, tx) in transactions.into_iter().enumerate() {
        let hash = TransactionHash(Transaction::tx_hash(&tx).0.into_felt());
        let _span =
            tracing::debug_span!("trace", transaction_hash=%hash, %transaction_idx).entered();

        let tx_type = transaction_type(&tx);
        let tx_declared_deprecated_class_hash = transaction_declared_deprecated_class(&tx);
        let gas_vector_computation_mode = super::transaction::gas_vector_computation_mode(&tx);

        let initial_state = tx_executor
            .block_state
            .as_ref()
            .expect(BLOCK_STATE_ACCESS_ERR)
            .clone();
        let (tx_info, state_maps) = match tx_executor.execute(&tx) {
            Ok(output) => output,
            Err(err) => {
                let error = match err {
                    TransactionExecutorError::TransactionExecutionError(err) => {
                        TraceError::ExecutionError(ExecutionError {
                            transaction_index: transaction_idx,
                            error: err.to_string(),
                            error_stack: err.into(),
                        })
                    }
                    _ => TraceError::Internal(InternalError {
                        transaction_index: transaction_idx,
                        error: err.to_string(),
                    }),
                };
                // Update the cache with the error. Lock the cache before sending to avoid
                // race conditions between senders and receivers.
                let mut cache = cache.0.lock().unwrap();
                let _ = sender.send(Err(error.clone()));
                cache.cache_set(block_hash, CacheItem::CachedErr(error.clone()));

                return Err(error.into());
            }
        };
        let state_diff =
            to_state_diff(state_maps, initial_state, tx_declared_deprecated_class_hash)
                .inspect_err(|_| {
                    // Remove the cache entry so it's no longer inflight.
                    let mut cache = cache.0.lock().unwrap();
                    cache.cache_remove(&block_hash);
                })?;

        tracing::trace!("Transaction tracing finished");

        let trace = to_trace(
            tx_type,
            tx_info,
            state_diff,
            tx_executor.block_context.versioned_constants(),
            &gas_vector_computation_mode,
        );
        traces.push((hash, trace));
    }

    // Lock the cache before sending to avoid race conditions between senders and
    // receivers.
    let mut cache = cache.0.lock().unwrap();
    let _ = sender.send(Ok(traces.clone()));
    cache.cache_set(block_hash, CacheItem::CachedOk(traces.clone()));
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
        Transaction::Account(tx) => match tx.tx {
            starknet_api::executable_transaction::AccountTransaction::Declare(_) => {
                TransactionType::Declare
            }
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(_) => {
                TransactionType::DeployAccount
            }
            starknet_api::executable_transaction::AccountTransaction::Invoke(_) => {
                TransactionType::Invoke
            }
        },
        Transaction::L1Handler(_) => TransactionType::L1Handler,
    }
}

fn transaction_declared_deprecated_class(transaction: &Transaction) -> Option<ClassHash> {
    match transaction {
        Transaction::Account(outer) => match &outer.tx {
            starknet_api::executable_transaction::AccountTransaction::Declare(inner) => {
                match inner.tx {
                    starknet_api::transaction::DeclareTransaction::V0(_)
                    | starknet_api::transaction::DeclareTransaction::V1(_) => {
                        Some(ClassHash(inner.class_hash().0.into_felt()))
                    }
                    starknet_api::transaction::DeclareTransaction::V2(_)
                    | starknet_api::transaction::DeclareTransaction::V3(_) => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn to_state_diff(
    state_maps: StateMaps,
    initial_state: PathfinderExecutionState<'_>,
    old_declared_contract: Option<ClassHash>,
) -> Result<StateDiff, StateError> {
    let mut deployed_contracts = Vec::new();
    let mut replaced_classes = Vec::new();

    // We need to check the previous class hash for a contract to decide if it's a
    // deployed contract or a replaced class.
    for (address, class_hash) in state_maps.class_hashes {
        let is_deployed = initial_state
            .get_class_hash_at(address)?
            .0
            .into_felt()
            .is_zero();
        if is_deployed {
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

    let mut storage_diffs: BTreeMap<_, _> = Default::default();
    for ((address, key), value) in state_maps.storage {
        storage_diffs
            .entry(ContractAddress::new_or_panic(address.0.key().into_felt()))
            .and_modify(|map: &mut BTreeMap<StorageAddress, StorageValue>| {
                map.insert(
                    StorageAddress::new_or_panic(key.0.key().into_felt()),
                    StorageValue(value.into_felt()),
                );
            })
            .or_insert_with(|| {
                let mut map = BTreeMap::new();
                map.insert(
                    StorageAddress::new_or_panic(key.0.key().into_felt()),
                    StorageValue(value.into_felt()),
                );
                map
            });
    }
    let storage_diffs: BTreeMap<_, Vec<StorageDiff>> = storage_diffs
        .into_iter()
        .map(|(address, diffs)| {
            (
                address,
                diffs
                    .into_iter()
                    .map(|(key, value)| StorageDiff { key, value })
                    .collect(),
            )
        })
        .collect();

    Ok(StateDiff {
        storage_diffs,
        deployed_contracts,
        // This info is not present in the state diff, so we need to pass it separately.
        deprecated_declared_classes: old_declared_contract.into_iter().collect(),
        declared_classes: state_maps
            .compiled_class_hashes
            .into_iter()
            .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
                class_hash: SierraHash(class_hash.0.into_felt()),
                compiled_class_hash: CasmHash(compiled_class_hash.0.into_felt()),
            })
            .collect(),
        nonces: state_maps
            .nonces
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
    versioned_constants: &VersionedConstants,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> TransactionTrace {
    let validate_invocation = execution_info.validate_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });
    let maybe_function_invocation = execution_info.execute_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });
    let fee_transfer_invocation = execution_info.fee_transfer_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });

    let computation_resources = validate_invocation
        .as_ref()
        .map(|i: &FunctionInvocation| i.computation_resources.clone())
        .unwrap_or_default()
        + maybe_function_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.computation_resources.clone())
            .unwrap_or_default()
        + fee_transfer_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.computation_resources.clone())
            .unwrap_or_default();
    let data_availability = DataAvailabilityResources {
        l1_gas: execution_info.receipt.da_gas.l1_gas.0.into(),
        l1_data_gas: execution_info.receipt.da_gas.l1_data_gas.0.into(),
    };
    let execution_resources = ExecutionResources {
        computation_resources,
        data_availability,
        l1_gas: execution_info.receipt.gas.l1_gas.0.into(),
        l1_data_gas: execution_info.receipt.gas.l1_data_gas.0.into(),
        l2_gas: execution_info.receipt.gas.l2_gas.0.into(),
    };

    match transaction_type {
        TransactionType::Declare => TransactionTrace::Declare(DeclareTransactionTrace {
            validate_invocation,
            fee_transfer_invocation,
            state_diff,
            execution_resources,
        }),
        TransactionType::DeployAccount => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                validate_invocation,
                constructor_invocation: maybe_function_invocation,
                fee_transfer_invocation,
                state_diff,
                execution_resources,
            })
        }
        TransactionType::Invoke => TransactionTrace::Invoke(InvokeTransactionTrace {
            validate_invocation,
            execute_invocation: if let Some(reason) = execution_info.revert_error {
                ExecuteInvocation::RevertedReason(reason.to_string())
            } else {
                ExecuteInvocation::FunctionInvocation(maybe_function_invocation)
            },
            fee_transfer_invocation,
            state_diff,
            execution_resources,
        }),
        TransactionType::L1Handler => TransactionTrace::L1Handler(L1HandlerTransactionTrace {
            function_invocation: maybe_function_invocation,
            state_diff,
            execution_resources,
        }),
    }
}
