use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::state_update::{
    self,
    ContractClassUpdate,
    ContractUpdate,
    StateUpdateData,
    StateUpdateRef,
    SystemContractUpdate,
};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    CasmHash,
    ClassCommitment,
    ClassHash,
    ContractAddress,
    SierraHash,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StateUpdate,
    StorageCommitment,
};
use pathfinder_merkle_tree::contract_state::ContractStateUpdateResult;
use pathfinder_merkle_tree::StorageCommitmentTree;
use pathfinder_storage::{Storage, TrieUpdate};
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;

use super::storage_adapters;
use crate::state::update_starknet_state;
use crate::sync::error::SyncError;
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
    type Output = (T, BlockNumber, StateDiffCommitment);

    fn map(
        &mut self,
        _: &PeerId,
        (data, block_number): Self::Input,
    ) -> Result<Self::Output, SyncError> {
        let mut db = self
            .db
            .transaction()
            .context("Creating database transaction")?;
        let commitment = db
            .state_diff_commitment(block_number)
            .context("Fetching state diff commitment")?
            // This is a fatal error because the block header is already expected to be in the
            // database
            .context("State diff commitment not found")?;
        Ok((data, block_number, commitment))
    }
}

pub struct VerifyCommitment;

impl ProcessStage for VerifyCommitment {
    const NAME: &'static str = "StateDiff::VerifyCommitment";
    type Input = (StateUpdateData, BlockNumber, StateDiffCommitment);
    type Output = (StateUpdateData, BlockNumber);

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        let (state_diff, block_number, expected_commitment) = input;
        let actual_commitment = state_diff.compute_state_diff_commitment();

        if actual_commitment != expected_commitment {
            tracing::debug!(%peer, %block_number, %expected_commitment, %actual_commitment, "State diff commitment mismatch");
            return Err(SyncError::StateDiffCommitmentMismatch(*peer));
        }

        Ok((state_diff, block_number))
    }
}

mod multi_block {
    use std::collections::{HashMap, HashSet};

    use pathfinder_common::state_update::{
        ContractClassUpdate,
        ContractUpdateRef,
        StateUpdateRef,
        StorageRef,
        SystemContractUpdateRef,
    };
    use pathfinder_common::{
        CasmHash,
        ClassHash,
        ContractAddress,
        ContractNonce,
        SierraHash,
        StorageAddress,
        StorageValue,
    };

    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct StateUpdateData {
        pub contract_updates: HashMap<ContractAddress, ContractUpdate>,
        pub system_contract_updates: HashMap<ContractAddress, SystemContractUpdate>,
        pub declared_cairo_classes: HashSet<ClassHash>,
        pub declared_sierra_classes: HashMap<SierraHash, CasmHash>,
    }

    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct ContractUpdate {
        /// Duplicate storage addresses are possible because this update spans
        /// many blocks
        pub storage: Vec<(StorageAddress, StorageValue)>,
        /// The __last__ (ie. highest) in the batch of blocks
        pub class: Option<ContractClassUpdate>,
        /// The __last__ (ie. highest) in the batch of blocks
        pub nonce: Option<ContractNonce>,
    }

    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct SystemContractUpdate {
        /// Duplicate storage addresses are possible because this update spans
        /// many blocks
        pub storage: Vec<(StorageAddress, StorageValue)>,
    }

    impl<'a> From<&'a StateUpdateData> for StateUpdateRef<'a> {
        fn from(update: &'a StateUpdateData) -> Self {
            Self {
                contract_updates: update
                    .contract_updates
                    .iter()
                    .map(|(k, v)| {
                        (
                            k,
                            ContractUpdateRef {
                                storage: (&v.storage).into(),
                                class: &v.class,
                                nonce: &v.nonce,
                            },
                        )
                    })
                    .collect(),
                system_contract_updates: update
                    .system_contract_updates
                    .iter()
                    .map(|(k, v)| {
                        (
                            k,
                            SystemContractUpdateRef {
                                storage: (&v.storage).into(),
                            },
                        )
                    })
                    .collect(),
                declared_sierra_classes: &update.declared_sierra_classes,
            }
        }
    }
}

pub fn merge_state_updates(
    state_updates: Vec<PeerData<(StateUpdateData, BlockNumber)>>,
) -> PeerData<multi_block::StateUpdateData> {
    let mut merged = multi_block::StateUpdateData::default();
    let peer = state_updates.last().expect("Non empty").peer;

    state_updates
        .into_iter()
        .map(|PeerData { data: (sud, _), .. }| sud)
        .for_each(|x| {
            x.contract_updates.into_iter().for_each(|(k, v)| {
                let e = merged.contract_updates.entry(k).or_default();
                e.storage.extend(v.storage);
                e.nonce = v.nonce.or(e.nonce);
                e.class = v.class.or(e.class);
            });
            x.system_contract_updates.into_iter().for_each(|(k, v)| {
                let e = merged.system_contract_updates.entry(k).or_default();
                e.storage.extend(v.storage);
            });
            merged
                .declared_sierra_classes
                .extend(x.declared_sierra_classes);
            merged
                .declared_cairo_classes
                .extend(x.declared_cairo_classes);
        });

    PeerData::new(peer, merged)
}

pub async fn batch_update_starknet_state(
    storage: pathfinder_storage::Storage,
    verify_tree_hashes: bool,
    state_updates: Vec<PeerData<(StateUpdateData, BlockNumber)>>,
) -> Result<PeerData<BlockNumber>, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let tail = state_updates.last().expect("Non empty").data.1;

        for PeerData {
            data: (state_update, block_number),
            ..
        } in &state_updates
        {
            db.insert_state_update_data(*block_number, state_update)
                .context("Inserting state update data")?;
        }

        let PeerData { peer, data: merged } = merge_state_updates(state_updates);

        let state_update_ref: StateUpdateRef<'_> = (&merged).into();

        update_starknet_state_impl(
            &peer,
            db,
            state_update_ref,
            verify_tree_hashes,
            tail,
            storage,
        )?;

        Ok(PeerData::new(peer, tail))
    })
    .await
    .context("Joining blocking task")?
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

    fn map(&mut self, peer: &PeerId, state_update: Self::Input) -> Result<Self::Output, SyncError> {
        let mut db = self
            .connection
            .transaction()
            .context("Creating database transaction")?;

        let tail = self.current_block;

        db.insert_state_update_data(self.current_block, &state_update)
            .context("Inserting state update data")?;

        update_starknet_state_impl(
            peer,
            db,
            (&state_update).into(),
            self.verify_tree_hashes,
            tail,
            self.storage.clone(),
        )?;

        self.current_block += 1;

        Ok(tail)
    }
}

fn update_starknet_state_impl(
    peer: &PeerId,
    db: pathfinder_storage::Transaction<'_>,
    state_update_ref: StateUpdateRef<'_>,
    verify_tree_hashes: bool,
    tail: BlockNumber,
    storage: Storage,
) -> Result<(), SyncError> {
    let (storage_commitment, class_commitment) = update_starknet_state(
        &db,
        state_update_ref,
        verify_tree_hashes,
        tail,
        storage.clone(),
    )
    .context("Updating Starknet state")?;
    let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
    let expected_state_commitment = db
        .state_commitment(tail.into())
        .context("Querying state commitment")?
        .context("State commitment not found")?;
    if state_commitment != expected_state_commitment {
        tracing::debug!(
        %peer,
        %tail,
        actual_storage_commitment=%storage_commitment,
        actual_class_commitment=%class_commitment,
        actual_state_commitment=%state_commitment,
        %expected_state_commitment,
        "State root mismatch");
        return Err(SyncError::StateRootMismatch(*peer));
    }
    db.update_storage_and_class_commitments(tail, storage_commitment, class_commitment)
        .context("Updating storage and class commitments")?;
    db.commit().context("Committing db transaction")?;
    Ok(())
}
