use std::collections::VecDeque;
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::PeerData;
use pathfinder_common::state_update::{self, ContractClassUpdate, ContractUpdate, StateUpdateData};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    ClassCommitment,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StateUpdate,
    StorageCommitment,
};
use pathfinder_merkle_tree::contract_state::{update_contract_state, ContractStateUpdateResult};
use pathfinder_merkle_tree::StorageCommitmentTree;
use pathfinder_storage::{Storage, TrieUpdate};
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;

use super::storage_adapters;
use crate::state::{update_starknet_state, StarknetStateUpdate};
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

pub(super) fn get_state_diff_lengths(
    db: pathfinder_storage::Transaction<'_>,
    start: BlockNumber,
    batch_size: NonZeroUsize,
) -> anyhow::Result<VecDeque<usize>> {
    db.state_diff_lengths(start, batch_size)
        .context("Querying state diff lengths")
}

pub(super) fn state_diff_length_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    storage_adapters::counts_stream(storage, start, stop, batch_size, get_state_diff_lengths)
}

pub struct FetchCommitmentFromDb<T> {
    db: pathfinder_storage::Connection,
    _marker: std::marker::PhantomData<T>,
}

impl<T> FetchCommitmentFromDb<T> {
    pub fn new(db: pathfinder_storage::Connection) -> Self {
        Self {
            db,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> ProcessStage for FetchCommitmentFromDb<T> {
    const NAME: &'static str = "StateDiff::FetchCommitmentFromDb";
    type Input = (T, BlockNumber);
    type Output = (T, StarknetVersion, StateDiffCommitment);

    fn map(&mut self, (data, block_number): Self::Input) -> Result<Self::Output, SyncError2> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;
        let version = db
            .block_version(block_number)
            .context("Fetching starknet version")?
            .ok_or(SyncError2::StarknetVersionNotFound)?;
        let commitment = db
            .state_diff_commitment(block_number)
            .context("Fetching state diff commitment")?
            .ok_or(SyncError2::StateDiffCommitmentNotFound)?;
        Ok((data, version, commitment))
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "StateDiff::Verify";
    type Input = (StateUpdateData, StarknetVersion, StateDiffCommitment);
    type Output = StateUpdateData;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let (state_diff, version, expected_commitment) = input;
        let actual = state_diff.compute_state_diff_commitment(version);

        if actual != expected_commitment {
            return Err(SyncError2::StateDiffCommitmentMismatch);
        }

        Ok(state_diff)
    }
}

pub struct UpdateStarknetState {
    pub storage: pathfinder_storage::Storage,
    pub connection: pathfinder_storage::Connection,
    pub current_block: BlockNumber,
    pub verify_tree_hashes: bool,
}

impl ProcessStage for UpdateStarknetState {
    type Input = StateUpdateData;
    type Output = BlockNumber;

    const NAME: &'static str = "StateDiff::UpdateStarknetState";

    fn map(&mut self, state_update: Self::Input) -> Result<Self::Output, SyncError2> {
        let mut db = self
            .connection
            .transaction()
            .context("Creating database transaction")?;

        let tail = self.current_block;

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db,
            StarknetStateUpdate {
                contract_updates: &state_update.contract_updates,
                system_contract_updates: &state_update.system_contract_updates,
                declared_sierra_classes: &state_update.declared_sierra_classes,
            },
            self.verify_tree_hashes,
            self.current_block,
            self.storage.clone(),
        )
        .context("Updating Starknet state")?;

        // Ensure that roots match.
        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
        let expected_state_commitment = db
            .state_commitment(self.current_block.into())
            .context("Querying state commitment")?
            .context("State commitment not found")?;
        if state_commitment != expected_state_commitment {
            return Err(SyncError2::StateRootMismatch);
        }

        db.update_storage_and_class_commitments(tail, storage_commitment, class_commitment)
            .context("Updating storage and class commitments")?;
        db.insert_state_update_data(self.current_block, &state_update)
            .context("Inserting state update data")?;
        db.commit().context("Committing db transaction")?;

        self.current_block += 1;

        Ok(tail)
    }
}
