use std::collections::VecDeque;
use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::types::UnverifiedStateUpdateData;
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

pub(super) fn length_and_commitment_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
) -> impl futures::Stream<Item = anyhow::Result<(usize, StateDiffCommitment)>> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let mut batch = VecDeque::new();

        while start <= stop {
            if let Some(counts) = batch.pop_front() {
                _ = tx.blocking_send(Ok(counts));
                continue;
            }

            let batch_size = batch_size.min(
                NonZeroUsize::new(
                    (stop.get() - start.get() + 1)
                        .try_into()
                        .expect("ptr size is 64bits"),
                )
                .expect(">0"),
            );
            let storage = storage.clone();

            let get = move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;
                let batch = db
                    .state_diff_lengths_and_commitments(start, batch_size)
                    .context("Querying state update counts")?;

                anyhow::ensure!(
                    !batch.is_empty(),
                    "No state update counts found: start {start}, batch_size {batch_size}"
                );

                Ok(batch)
            };

            batch = match get() {
                Ok(x) => x,
                Err(e) => {
                    _ = tx.blocking_send(Err(e));
                    return;
                }
            };

            start += batch.len().try_into().expect("ptr size is 64bits");
        }

        while let Some(counts) = batch.pop_front() {
            _ = tx.blocking_send(Ok(counts));
        }
    });

    ReceiverStream::new(rx)
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

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use pathfinder_common::{SignedBlockHeader, StateUpdate};
    use pathfinder_storage::fake::Block;

    use super::*;

    #[rstest::rstest]
    #[case::request_shorter_than_batch_size(1)]
    #[case::request_equal_to_batch_size(2)]
    #[case::request_longer_than_batch_size(3)]
    #[case::request_equal_to_db_size(5)]
    #[case::request_longer_than_db_size(6)]
    #[tokio::test]
    async fn length_and_commitment_stream(#[case] len: usize) {
        const DB_LEN: usize = 5;
        let ok_len = len.min(DB_LEN);
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();
        let expected = pathfinder_storage::fake::with_n_blocks(&storage, DB_LEN)
            .into_iter()
            .map(|b| {
                let Block {
                    header:
                        SignedBlockHeader {
                            header:
                                BlockHeader {
                                    state_diff_commitment,
                                    state_diff_length,
                                    ..
                                },
                            ..
                        },
                    ..
                } = b;
                (state_diff_length as usize, state_diff_commitment)
            })
            .collect::<Vec<_>>();
        let stream = super::length_and_commitment_stream(
            storage.clone(),
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + len as u64 - 1,
            NonZeroUsize::new(2).unwrap(),
        );

        let mut remainder = stream.collect::<Vec<_>>().await;

        let actual = remainder
            .drain(..ok_len)
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();

        assert_eq!(expected[..ok_len], actual);

        if len > DB_LEN {
            assert!(remainder.pop().unwrap().is_err());
        } else {
            assert!(remainder.is_empty());
        }
    }
}
