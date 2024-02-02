use std::sync::{Arc, Mutex};

use anyhow::Context;
use cached::{Cached, SizedCache};

use pathfinder_common::{BlockHash, ChainId};
use pathfinder_executor::{BlockTrace, ExecutionState, TransactionExecutionError};
use starknet_gateway_types::reply::transaction::Transaction;

use crate::{
    compose_executor_transaction,
    executor::VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY,
    PendingData,
};

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("Block not found")]
    BlockNotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("Transaction execution failed")]
    ExecutionError(TransactionExecutionError),
    #[error("Starknet version not supported")]
    VersionNotSupported(Vec<Transaction>),
}

#[derive(Debug, Clone)]
pub struct BlockTraceCache(Arc<Mutex<SizedCache<BlockHash, Arc<BlockTrace>>>>);

impl BlockTraceCache {
    pub fn new(size: usize) -> Self {
        Self(Arc::new(Mutex::new(SizedCache::with_size(size))))
    }
}

pub fn trace_block(
    cache: &BlockTraceCache,
    block: BlockHash,
    db: &pathfinder_storage::Transaction<'_>,
    chain_id: ChainId,
) -> Result<Arc<BlockTrace>, TraceError> {
    if let Some(cached) = cache.0.lock().unwrap().cache_get(&block).cloned() {
        tracing::trace!("Trace cache hit");
        return Ok(cached);
    } else {
        tracing::trace!("Trace cache miss");
    }

    let header = db
        .block_header(block.into())
        .context("Fetching block header")?
        .ok_or(TraceError::BlockNotFound)?;

    let transactions = db
        .transaction_data_for_block(block.into())
        .context("Fetching transactions for block")?
        .ok_or(TraceError::BlockNotFound)?
        .into_iter()
        .map(|(tx, _)| tx)
        .collect();

    let version = header
        .starknet_version
        .parse_as_semver()
        .context("Parsing starknet version")?
        .unwrap_or(semver::Version::new(0, 0, 0));
    if version < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY {
        return Err(TraceError::VersionNotSupported(transactions));
    }

    let transactions = transactions
        .into_iter()
        .map(|tx| compose_executor_transaction(&tx, db))
        .collect::<Result<_, _>>()
        .context("Mapping transactions")?;
    let state = ExecutionState::trace(&db, chain_id, header, None);
    // TODO: remove cache from execution trace.
    let traces =
        pathfinder_executor::trace(state, &Default::default(), block, transactions, true, true)
            .map_err(|e| TraceError::ExecutionError(e))?;
    let traces = Arc::new(traces);

    cache.0.lock().unwrap().cache_set(block, traces.clone());

    Ok(traces)
}

pub fn trace_pending_block(
    pending: PendingData,
    db: &pathfinder_storage::Transaction<'_>,
    chain_id: ChainId,
) -> Result<Arc<BlockTrace>, TraceError> {
    let header = pending.header();

    let version = header
        .starknet_version
        .parse_as_semver()
        .context("Parsing starknet version")?
        .unwrap_or(semver::Version::new(0, 0, 0));
    if version < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY {
        return Err(TraceError::VersionNotSupported(
            pending.block.transactions.clone(),
        ));
    }

    let transactions = pending
        .block
        .transactions
        .iter()
        .map(|tx| compose_executor_transaction(tx, db))
        .collect::<Result<_, _>>()
        .context("Mapping transactions")?;
    let state = ExecutionState::trace(&db, chain_id, header, None);
    // TODO: remove cache from execution trace.
    let traces = pathfinder_executor::trace(
        state,
        &Default::default(),
        Default::default(),
        transactions,
        true,
        true,
    )
    .map_err(|e| TraceError::ExecutionError(e))?;
    Ok(Arc::new(traces))
}
