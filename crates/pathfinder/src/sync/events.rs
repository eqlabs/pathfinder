use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::types::EventsForBlockByTransaction;
use p2p::PeerData;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{
    BlockHeader,
    BlockNumber,
    EventCommitment,
    StarknetVersion,
    TransactionHash,
};
use pathfinder_storage::Storage;
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;

use super::error::SyncError;
use super::storage_adapters;
use crate::state::block_hash::calculate_event_commitment;
use crate::sync::error::SyncError2;
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

pub(super) fn get_counts(
    db: pathfinder_storage::Transaction<'_>,
    start: BlockNumber,
    batch_size: NonZeroUsize,
) -> anyhow::Result<VecDeque<usize>> {
    db.event_counts(start, batch_size)
        .context("Querying event counts")
}

pub(super) fn counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    storage_adapters::counts_stream(storage, start, stop, batch_size, get_counts)
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
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;
        let header = transaction
            .block_header(block_number.into())
            .context("Querying block header")?
            .context("Block header not found")?;
        let computed = calculate_event_commitment(
            &events
                .iter()
                .map(|(tx_hash, events)| (*tx_hash, events.as_slice()))
                .collect::<Vec<_>>(),
            header.starknet_version,
        )
        .context("Calculating commitment")?;
        if computed != header.event_commitment {
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
        let tail = events
            .last()
            .map(|x| x.data.0)
            .context("Verification results are empty, no block to persist")?;

        for (block_number, events_for_block) in events.into_iter().map(|x| x.data) {
            transaction
                .update_events(
                    block_number,
                    events_for_block
                        .into_iter()
                        .map(|(_, events)| events)
                        .collect(),
                )
                .context("Updating events")?;
        }
        transaction.commit().context("Committing db transaction")?;

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "Events::Verify";

    type Input = (
        EventCommitment,
        Vec<TransactionHash>,
        HashMap<TransactionHash, Vec<Event>>,
        StarknetVersion,
    );
    type Output = HashMap<TransactionHash, Vec<Event>>;

    fn map(
        &mut self,
        (event_commitment, transactions, mut events, version): Self::Input,
    ) -> Result<Self::Output, super::error::SyncError2> {
        let mut ordered_events = Vec::new();
        for tx_hash in &transactions {
            // Some transactions may not have events
            if let Some(events_for_tx) = events.get(tx_hash) {
                ordered_events.push((*tx_hash, events_for_tx.as_slice()));
            }
        }
        if ordered_events.len() != events.len() {
            return Err(SyncError2::EventsTransactionsMismatch);
        }
        let actual = calculate_event_commitment(&ordered_events, version)?;
        if actual != event_commitment {
            return Err(SyncError2::EventCommitmentMismatch);
        }
        Ok(events)
    }
}
