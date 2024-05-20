use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::PeerData;
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate, StateUpdateData};
use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, StateUpdate, StorageCommitment};
use pathfinder_merkle_tree::contract_state::{update_contract_state, ContractStateUpdateResult};
use pathfinder_merkle_tree::StorageCommitmentTree;
use pathfinder_storage::{Storage, TrieUpdate};
use tokio::task::spawn_blocking;

use crate::sync::error::SyncError;

/// Returns the first block number whose state update is missing, counting from
/// genesis or `None` if all class definitions up to `head` are present.
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let highest = db
            .highest_block_with_state_update()
            .context("Querying highest block with state update")?
            .unwrap_or_default();

        Ok((highest < head).then_some(highest + 1))
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn state_diff_lengths_stream(
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
                db.state_diff_lengths(start, batch_size)
                    .context("Querying state update counts")
            })
            .await
            .context("Joining blocking task")??;

            if batch.is_empty() {
                Err(anyhow::anyhow!(
                    "No state update counts found for range: start {start}, batch_size {batch_size}"
                ))?;
                break;
            }

            start += batch.len().try_into().expect("ptr size is 64bits");
        }
    }
}

pub(super) async fn verify_commitment(
    state_diff: PeerData<(BlockNumber, StateUpdateData)>,
    storage: Storage,
) -> Result<PeerData<(BlockNumber, StateUpdateData)>, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let block_number = state_diff.data.0;
        let (expected, _) = db
            .state_diff_commitment_and_length(block_number)
            .context("Querying state diff commitment and length")?
            .context("State diff commitment not found")?;

        let actual = state_diff.data.1.compute_state_diff_commitment();

        if actual != expected {
            return Err(SyncError::StateDiffCommitmentMismatch(state_diff.peer));
        }

        Ok(state_diff)
    })
    .await
    .context("Joining blocking task")?
}

pub(super) async fn persist(
    storage: Storage,
    state_diff: Vec<PeerData<(BlockNumber, StateUpdateData)>>,
) -> Result<BlockNumber, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        let tail = state_diff
            .last()
            .map(|x| x.data.0)
            .context("Verification results are empty, no block to persist")?;

        for (block_number, state_diff) in state_diff.into_iter().map(|x| x.data) {
            db.insert_state_update_data(block_number, &state_diff)
                .context("Inserting state update")?;
        }

        db.commit().context("Committing database transaction")?;

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
