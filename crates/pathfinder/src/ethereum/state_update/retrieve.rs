use std::collections::{HashMap, HashSet};

use anyhow::Context;
use web3::{
    futures::future::try_join_all,
    types::{FilterBuilder, Transaction, TransactionId, U256},
};

use crate::ethereum::{
    api::Web3EthApi,
    contract::{REGISTER_MEMORY_PAGE_FUNCTION, STATE_TRANSITION_FACT_EVENT},
    log::{
        get_logs, BackwardFetchError, BackwardLogFetcher, EitherMetaLog,
        MemoryPageFactContinuousLog, MemoryPagesHashesLog, StateTransitionFactLog, StateUpdateLog,
    },
    state_update::RetrieveStateUpdateError,
    Chain,
};

/// Retrieves the [StateTransitionFactLog] associated with the given [StateUpdateLog].
pub async fn retrieve_transition_fact(
    transport: &impl Web3EthApi,
    state_update: StateUpdateLog,
    chain: Chain,
) -> Result<StateTransitionFactLog, RetrieveStateUpdateError> {
    // StateTransitionFactLog and StateUpdateLog are always emitted
    // as pairs. So we query the same block.
    let addresses = crate::ethereum::contract::addresses(chain);
    let filter = FilterBuilder::default()
        .address(vec![addresses.core])
        .topics(
            Some(vec![STATE_TRANSITION_FACT_EVENT.signature()]),
            None,
            None,
            None,
        )
        .block_hash(state_update.origin.block.hash.0)
        .build();

    let logs = get_logs(transport, filter).await?;
    for log in logs {
        let log = StateTransitionFactLog::try_from(log)?;

        if log.origin.block == state_update.origin.block
            && log.origin.transaction == state_update.origin.transaction
        {
            return Ok(log);
        }
    }

    Err(RetrieveStateUpdateError::StateTransitionFactNotFound)
}

/// Retrieves the [MemoryPagesHashesLog] associated with the given [StateTransitionFactLog].
pub async fn retrieve_mempage_hashes(
    transport: &impl Web3EthApi,
    fact: StateTransitionFactLog,
    chain: Chain,
) -> Result<MemoryPagesHashesLog, RetrieveStateUpdateError> {
    let fact_hash = fact.fact_hash;

    let mut fetcher = BackwardLogFetcher::<StateTransitionFactLog, MemoryPagesHashesLog>::new(
        EitherMetaLog::Left(fact),
        chain,
    );

    loop {
        use RetrieveStateUpdateError::*;
        let logs = match fetcher.fetch(transport).await {
            Ok(logs) => logs,
            Err(BackwardFetchError::GenesisReached) => return Err(MemoryPageHashesNotFound),
            Err(BackwardFetchError::Reorg) => return Err(Reorg),
            Err(BackwardFetchError::Other(other)) => return Err(Other(other)),
        };

        for log in logs {
            if let EitherMetaLog::Right(mempage_hashes) = log {
                if fact_hash == mempage_hashes.hash {
                    return Ok(mempage_hashes);
                }
            }
        }
    }
}

/// Retrieves the list of [MemoryPageFactContinuousLog] associated with the given [MemoryPagesHashesLog].
pub async fn retrieve_memory_page_logs(
    transport: &impl Web3EthApi,
    mempage_hashes: MemoryPagesHashesLog,
    chain: Chain,
) -> Result<Vec<MemoryPageFactContinuousLog>, RetrieveStateUpdateError> {
    let hashes = mempage_hashes.mempage_hashes.clone();
    let mut required_hashes = hashes.iter().cloned().collect::<HashSet<_>>();
    let mut found_hashes = HashMap::with_capacity(hashes.len());

    let mut fetcher = BackwardLogFetcher::<MemoryPagesHashesLog, MemoryPageFactContinuousLog>::new(
        EitherMetaLog::Left(mempage_hashes),
        chain,
    );

    loop {
        use RetrieveStateUpdateError::*;
        let logs = match fetcher.fetch(transport).await {
            Ok(logs) => logs,
            Err(BackwardFetchError::GenesisReached) => return Err(MemoryPageLogNotFound),
            Err(BackwardFetchError::Reorg) => return Err(Reorg),
            Err(BackwardFetchError::Other(other)) => return Err(Other(other)),
        };

        for log in logs {
            if let EitherMetaLog::Right(mempage_log) = log {
                if required_hashes.remove(&mempage_log.hash) {
                    found_hashes.insert(mempage_log.hash, mempage_log);
                }
            }
        }

        if required_hashes.is_empty() {
            break;
        }
    }

    let mempages = hashes
        .into_iter()
        .map(|hash| {
            found_hashes
                .remove(&hash)
                .expect("All required memory pages should have been found")
        })
        .collect::<Vec<_>>();

    Ok(mempages)
}

/// Retrieves and parses the transaction data of the given [MemoryPageFactContinuousLog]'s.
///
/// These can be parsed into a [StateUpdate](crate::ethereum::state_update::StateUpdate).
pub async fn retrieve_mempage_transaction_data(
    transport: &impl Web3EthApi,
    mempages: Vec<MemoryPageFactContinuousLog>,
) -> Result<Vec<Vec<U256>>, RetrieveStateUpdateError> {
    let fut = mempages
        .iter()
        .map(|page| transport.transaction(TransactionId::Hash(page.origin.transaction.hash.0)))
        .collect::<Vec<_>>();

    let transactions = try_join_all(fut)
        .await
        .context("failed to retrieve memory page transactions")?;

    let mut data = Vec::with_capacity(mempages.len());

    for tx in transactions {
        let tx = tx.ok_or(RetrieveStateUpdateError::MemoryPageTransactionNotFound)?;
        data.push(decode_mempage_transaction(tx)?);
    }

    Ok(data)
}

fn decode_mempage_transaction(transaction: Transaction) -> anyhow::Result<Vec<U256>> {
    // The first 4 bytes of data represent the short-signature of the function.
    // These must exist in order to be valid. We should compare the signature as
    // well, but this requires web3 to bump ethabi to v15.
    anyhow::ensure!(
        transaction.input.0.len() >= 4,
        "memory page transaction input has incomplete signature"
    );

    // The mempage data is stored in 'values' (2nd token), which is an array of U256.
    //
    // The complete structure is defined in the mempage json ABI.
    // `decode_input` wants the raw data, excluding the short-signature.
    // The indexing is safe due to the `ensure` above.
    REGISTER_MEMORY_PAGE_FUNCTION
        .decode_input(&transaction.input.0[4..])
        .context("mempage input decoding failed")?
        .get(1)
        .cloned()
        .context("missing values array field")?
        .into_array()
        .context("values field could not be cast to an array")?
        .iter()
        .map(|t| {
            t.clone()
                .into_uint()
                .context("values element could not be cast to U256")
        })
        .collect()
}
