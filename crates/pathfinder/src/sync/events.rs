use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::types::EventsForBlockByTransaction;
use p2p::libp2p::PeerId;
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
use tokio_stream::wrappers::ReceiverStream;

use super::error::SyncError;
use super::storage_adapters;
use crate::state::block_hash::calculate_event_commitment;
use crate::sync::stream::ProcessStage;

/// Returns the first block number whose events are missing in storage, counting
/// from genesis
pub(super) fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    let next = storage
        .connection()?
        .transaction()?
        .next_block_without_events();

    Ok((next < head).then_some(next))
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

    let events = util::task::spawn_blocking(move |_| {
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
            header.starknet_version.max(StarknetVersion::V_0_13_2),
        )
        .context("Calculating commitment")?;
        if computed != header.event_commitment {
            tracing::debug!(%peer, %block_number, expected_commitment=%header.event_commitment, actual_commitment=%computed, "Event commitment mismatch");
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
    util::task::spawn_blocking(move |_| {
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
        peer: &PeerId,
        (event_commitment, transactions, mut events, version): Self::Input,
    ) -> Result<Self::Output, super::error::SyncError> {
        let mut ordered_events = Vec::new();
        for tx_hash in &transactions {
            // Some transactions may not have events
            if let Some(events_for_tx) = events.get(tx_hash) {
                ordered_events.push((*tx_hash, events_for_tx.as_slice()));
            }
        }
        if ordered_events.len() != events.len() {
            tracing::debug!(%peer, expected=%ordered_events.len(), actual=%events.len(), "Number of events received does not match expected number of events");
            return Err(SyncError::EventsTransactionsMismatch(*peer));
        }
        let actual =
            calculate_event_commitment(&ordered_events, version.max(StarknetVersion::V_0_13_2))?;
        if actual != event_commitment {
            tracing::debug!(%peer, expected=%event_commitment, actual=%actual, "Event commitment mismatch");
            return Err(SyncError::EventCommitmentMismatch(*peer));
        }
        Ok(events)
    }
}
