use std::collections::HashMap;
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::peer_agnostic::EventsForBlockByTransaction;
use p2p::PeerData;
use pathfinder_common::event::Event;
use pathfinder_common::{BlockHeader, BlockNumber, TransactionHash};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

use super::error::SyncError;
use crate::state::block_hash::calculate_event_commitment;
use crate::sync::stream::ProcessStage;

/// Returns the first block number whose events are missing in storage, counting
/// from genesis
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
    events: PeerData<EventsForBlockByTransaction>,
    storage: Storage,
) -> Result<PeerData<EventsForBlockByTransaction>, SyncError> {
    let PeerData {
        peer,
        data: (block_number, events),
    } = events;
    let events = tokio::task::spawn_blocking(move || {
        let computed = calculate_event_commitment(&events.iter().flatten().collect::<Vec<_>>())
            .context("Calculating commitment")?;
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;
        let expected = transaction
            .block_header(block_number.into())
            .context("Querying block header")?
            .ok_or(anyhow::anyhow!("Block header not found"))?
            .event_commitment;
        if computed != expected {
            return Err(SyncError::EventCommitmentMismatch(peer));
        }
        Ok(events)
    })
    .await
    .context("Joining blocking task")??;

    Ok(PeerData::new(peer, (block_number, events)))
}

pub(super) async fn persist(
    storage: Storage,
    events: Vec<PeerData<EventsForBlockByTransaction>>,
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
            for (txn_idx, events_for_txn) in events_for_block.into_iter().enumerate() {
                transaction
                    .update_events(block_number, txn_idx, &events_for_txn)
                    .context("Updating events")?;
            }
        }
        transaction.commit()?;

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}

pub struct BlockEvents {
    pub header: BlockHeader,
    pub events: HashMap<TransactionHash, Vec<Event>>,
}
pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    type Input = BlockEvents;
    type Output = BlockEvents;

    fn map(&mut self, _input: Self::Input) -> Result<Self::Output, super::error::SyncError2> {
        todo!()
    }
}
