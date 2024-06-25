use std::collections::VecDeque;
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::peer_agnostic::UnverifiedStateUpdateData;
use p2p::PeerData;
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate, StateUpdateData};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StateUpdate,
    StorageCommitment,
};
use pathfinder_merkle_tree::contract_state::{update_contract_state, ContractStateUpdateResult};
use pathfinder_merkle_tree::StorageCommitmentTree;
use pathfinder_storage::{Storage, TrieUpdate};
use tokio::task::spawn_blocking;

use crate::sync::error::{SyncError, SyncError2};
use crate::sync::stream::ProcessStage;

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
            .context("Querying highest block with state update")?;

        match highest {
            // No state updates at all, start from genesis
            None => Ok((head != BlockNumber::GENESIS).then_some(BlockNumber::GENESIS)),
            // Otherwise start from the next block
            Some(highest) => Ok((highest < head).then_some(highest + 1)),
        }
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn length_and_commitment_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<(usize, StateDiffCommitment)>> {
    const BATCH_SIZE: usize = 1000;

    async_stream::try_stream! {
        let mut batch = VecDeque::new();

        while start <= stop {
            if let Some(counts) = batch.pop_front() {
                yield counts;
                continue;
            }

            let batch_size = NonZeroUsize::new(
                BATCH_SIZE.min(
                    (stop.get() - start.get() + 1)
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
                db.state_diff_lengths_and_commitments(start, batch_size)
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

        while let Some(counts) = batch.pop_front() {
            yield counts;
        }
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "StateDiff::Verify";
    type Input = (UnverifiedStateUpdateData, StarknetVersion);
    type Output = StateUpdateData;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let (
            UnverifiedStateUpdateData {
                expected_commitment,
                state_diff,
            },
            version,
        ) = input;
        let actual = state_diff.compute_state_diff_commitment(version);

        if actual != expected_commitment {
            return Err(SyncError2::StateDiffCommitmentMismatch);
        }

        Ok(state_diff)
    }
}

pub struct Store {
    db: pathfinder_storage::Connection,
    current_block: BlockNumber,
}

impl Store {
    pub fn new(db: pathfinder_storage::Connection, start: BlockNumber) -> Self {
        Self {
            db,
            current_block: start,
        }
    }
}

impl ProcessStage for Store {
    const NAME: &'static str = "StateDiff::Persist";
    type Input = StateUpdateData;
    type Output = BlockNumber;

    fn map(&mut self, state_update: Self::Input) -> Result<Self::Output, SyncError2> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;

        let tail = self.current_block;

        db.insert_state_update_data(self.current_block, &state_update)
            .context("Inserting state update data")?;
        db.commit().context("Committing db transaction")?;

        self.current_block += 1;

        Ok(tail)
    }
}
