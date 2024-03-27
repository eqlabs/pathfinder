use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::PeerData;
use pathfinder_common::event::Event;
use pathfinder_common::{BlockNumber, EventCommitment, TransactionHash};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

use super::error::SyncError;

/// Returns the first block number whose events are missing in storage, counting from genesis
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        if let Some(highest) = db
            .highest_block_with_all_events_downloaded()
            .context("Querying highest block with events")?
        {
            Ok((highest < head).then_some(highest + 1))
        } else {
            Ok(Some(BlockNumber::GENESIS))
        }
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop_inclusive: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    const BATCH_SIZE: usize = 1000;

    async_stream::try_stream! {
    let mut batch = Vec::new();

    while start <= stop_inclusive {
        if let Some(counts) = batch.pop() {
            yield counts;
            continue;
        }

        let batch_size = NonZeroUsize::new(
            BATCH_SIZE.min(
                (stop_inclusive.get() - start.get() + 1)
                    .try_into()
                    .expect("ptr size is 64bits"),
            ),
        )
        .expect(">0");
        let storage = storage.clone();

        batch = tokio::task::spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().context("Creating database transaction")?;
            db.event_counts(start.into(), batch_size)
                .context("Querying event counts")
        })
        .await
        .context("Joining blocking task")??;

        if batch.is_empty() {
            Err(anyhow::anyhow!(
                "No event counts found for range: start {start}, batch_size (batch_size)"
            ))?;
            break;
        }

        start += batch.len().try_into().expect("ptr size is 64bits");
    }
    }
}

pub(super) async fn verify_commitment(
    events: PeerData<(BlockNumber, Vec<(TransactionHash, Vec<Event>)>)>,
    expected_commitment: EventCommitment,
) -> Result<PeerData<(BlockNumber, Vec<(TransactionHash, Vec<Event>)>)>, SyncError> {
    use crate::state::block_hash::calculate_event_commitment;
    let PeerData {
        peer,
        data: (block_number, transaction_events),
    } = events;
    let error = || SyncError::EventCommitmentMismatch(peer);
    let (commitment, transation_events) = tokio::task::spawn_blocking(move || {
        calculate_event_commitment(
            &transaction_events
                .iter()
                .map(|(_, events)| events.as_slice())
                .collect::<Vec<_>>(),
        )
        .map(|commitment| (commitment, transaction_events))
    })
    .await
    .map_err(|_| error())?
    .map_err(|_| error())?;

    if commitment == expected_commitment {
        Ok(PeerData::new(peer, (block_number, transation_events)))
    } else {
        Err(error())
    }
}

pub(super) async fn persist(
    storage: Storage,
    events: Vec<PeerData<(BlockNumber, Vec<(TransactionHash, Vec<Event>)>)>>,
) -> Result<BlockNumber, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;
        let tail = events.last().map(|x| x.data.0).ok_or(anyhow::anyhow!(
            "Verification results are empty, no block to persist"
        ))?;

        for (block_number, events_for_block) in events.into_iter().map(|x| x.data) {
            let block_hash = transaction
                .block_hash(block_number.into())
                .context("Getting block hash")?
                .ok_or(anyhow::anyhow!("Block hash not found"))?;

            todo!("Update event data")
        }

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
