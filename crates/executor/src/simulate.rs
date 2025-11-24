use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use blockifier::blockifier::transaction_executor::{
    TransactionExecutorError,
    BLOCK_STATE_ACCESS_ERR,
};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::transaction::transaction_execution::Transaction;
use cached::{Cached, SizedCache};
use pathfinder_common::prelude::*;
use starknet_api::transaction::fields::GasVectorComputationMode;
use util::percentage::Percentage;

use super::error::TransactionExecutionError;
use super::execution_state::ExecutionState;
use super::types::{TransactionSimulation, TransactionTrace};
use crate::error_stack::ErrorStack;
use crate::execution_state::create_executor;
use crate::state_reader::RcStorageAdapter;
use crate::transaction::{
    execute_transaction,
    find_l2_gas_limit_and_execute_transaction,
    l2_gas_accounting_enabled,
    ExecutionBehaviorOnRevert,
};
use crate::types::{
    to_execution_info,
    to_state_diff,
    transaction_declared_deprecated_class,
    transaction_type,
    DeclareTransactionTrace,
    DeployAccountTransactionTrace,
    FeeEstimate,
    InvokeTransactionTrace,
    L1HandlerTransactionTrace,
    StateDiff,
    TransactionExecutionInfo,
    TransactionType,
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

impl TraceCache {
    pub fn with_size(size: NonZeroUsize) -> Self {
        Self(Arc::new(Mutex::new(SizedCache::with_size(size.get()))))
    }
}

pub fn simulate(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    transactions: Vec<Transaction>,
    epsilon: Percentage,
) -> Result<Vec<TransactionSimulation>, TransactionExecutionError> {
    let block_number = execution_state.block_info.number;
    let mut tx_executor = create_executor(RcStorageAdapter::new(db_tx), execution_state)?;

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
            let state_diff = to_state_diff(state_maps, initial_state, tx_declared_deprecated_class_hash.into_iter())?;

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
    let mut tx_executor = create_executor(RcStorageAdapter::new(db_tx), execution_state)?;

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
        let state_diff = to_state_diff(
            state_maps,
            initial_state,
            tx_declared_deprecated_class_hash.into_iter(),
        )
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

pub(crate) fn to_trace(
    transaction_type: TransactionType,
    execution_info: blockifier::transaction::objects::TransactionExecutionInfo,
    state_diff: StateDiff,
    versioned_constants: &VersionedConstants,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> TransactionTrace {
    let execution_info = to_execution_info(
        transaction_type,
        execution_info,
        versioned_constants,
        gas_vector_computation_mode,
    );

    match execution_info {
        TransactionExecutionInfo::Declare(execution_info) => {
            TransactionTrace::Declare(DeclareTransactionTrace {
                execution_info,
                state_diff,
            })
        }
        crate::types::TransactionExecutionInfo::DeployAccount(execution_info) => {
            TransactionTrace::DeployAccount(DeployAccountTransactionTrace {
                execution_info,
                state_diff,
            })
        }
        crate::types::TransactionExecutionInfo::Invoke(execution_info) => {
            TransactionTrace::Invoke(InvokeTransactionTrace {
                execution_info,
                state_diff,
            })
        }
        crate::types::TransactionExecutionInfo::L1Handler(execution_info) => {
            TransactionTrace::L1Handler(L1HandlerTransactionTrace {
                execution_info,
                state_diff,
            })
        }
    }
}
