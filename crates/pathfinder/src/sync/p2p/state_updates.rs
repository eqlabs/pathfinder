use std::collections::HashMap;

use anyhow::Context;
use p2p::PeerData;
use pathfinder_common::{
    state_update::ContractUpdates, BlockHash, BlockHeader, BlockNumber, StateUpdate,
    StorageCommitment,
};
use pathfinder_crypto::Felt;
use pathfinder_merkle_tree::{
    contract_state::{update_contract_state, ContractStateUpdateResult},
    StorageCommitmentTree,
};
use pathfinder_storage::{Node, Storage};
use tokio::task::spawn_blocking;

#[derive(Debug, thiserror::Error)]
pub(super) enum ContractDiffSyncError {
    #[error(transparent)]
    DatabaseOrComputeError(#[from] anyhow::Error),
    #[error("Storage commitment mismatch")]
    StorageCommitmentMismatch(PeerData<BlockNumber>),
}

/// Returns the first block number whose state update is missing in storage, counting from genesis
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
            .highest_state_update()
            .context("Querying highest state update")?
        {
            Ok((highest < head).then_some(highest + 1))
        } else {
            Ok(Some(BlockNumber::GENESIS))
        }
    })
    .await
    .context("Joining blocking task")?
}

#[derive(Debug)]
pub(super) struct VerificationOk {
    block_number: BlockNumber,
    block_hash: BlockHash,
    storage_commitment: StorageCommitment,
    contract_update_results: Vec<ContractStateUpdateResult>,
    trie_nodes: HashMap<Felt, Node>,
    contract_updates: ContractUpdates,
}

pub(super) async fn verify(
    storage: Storage,
    contract_updates: Vec<PeerData<(BlockNumber, ContractUpdates)>>,
    verify_trie_hashes: bool,
) -> Result<Vec<PeerData<VerificationOk>>, ContractDiffSyncError> {
    tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;

        contract_updates
            .into_par_iter()
            .map(|x| verify_one(storage.clone(), x, verify_trie_hashes))
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .context("Joining blocking task")?
}

fn verify_one(
    storage: Storage,
    contract_updates: PeerData<(BlockNumber, ContractUpdates)>,
    verify_hashes: bool,
) -> Result<PeerData<VerificationOk>, ContractDiffSyncError> {
    use rayon::prelude::*;

    let peer = contract_updates.peer;
    let block_number = contract_updates.data.0;
    let contract_updates = contract_updates.data.1;
    let mut connection = storage
        .connection()
        .context("Creating database connection")?;
    let transaction = connection
        .transaction()
        .context("Creating database transaction")?;

    let BlockHeader {
        hash: block_hash,
        storage_commitment,
        ..
    } = transaction
        .block_header(block_number.into())
        .context("getting block header")?
        .ok_or(anyhow::anyhow!("Block header not found"))?;

    let mut storage_commitment_tree = match block_number.parent() {
        Some(parent) => StorageCommitmentTree::load(&transaction, parent)
            .context("Loading storage commitment tree")?,
        None => StorageCommitmentTree::empty(&transaction),
    }
    .with_verify_hashes(verify_hashes);

    let (send, recv) = std::sync::mpsc::channel();

    // Apply contract storage updates to the storage commitment tree.
    rayon::scope(|s| {
        s.spawn(|_| {
            let result: Result<Vec<_>, _> = contract_updates
                .regular
                .par_iter()
                .map_init(
                    || storage.clone().connection(),
                    |connection, (contract_address, update)| {
                        let connection = match connection {
                            Ok(connection) => connection,
                            Err(e) => anyhow::bail!(
                                "Failed to create database connection in rayon thread: {}",
                                e
                            ),
                        };
                        let transaction = connection.transaction()?;
                        update_contract_state(
                            *contract_address,
                            &update.storage,
                            update.nonce,
                            update.class.as_ref().map(|x| x.class_hash()),
                            &transaction,
                            verify_hashes,
                            block_number,
                        )
                    },
                )
                .collect();
            let _ = send.send(result);
        })
    });

    let mut contract_update_results = recv.recv().context("Panic on rayon thread")??;

    for contract_update_result in contract_update_results.iter() {
        storage_commitment_tree
            .set(
                contract_update_result.contract_address,
                contract_update_result.state_hash,
            )
            .context("Updating storage commitment tree")?;
    }

    let (send, recv) = std::sync::mpsc::channel();

    // Apply system contract storage updates to the storage commitment tree.
    rayon::scope(|s| {
        s.spawn(|_| {
            let result: Result<Vec<_>, _> = contract_updates
                .system
                .par_iter()
                .map_init(
                    || storage.clone().connection(),
                    |connection, (contract_address, update)| {
                        let connection = match connection {
                            Ok(connection) => connection,
                            Err(e) => anyhow::bail!(
                                "Failed to create database connection in rayon thread: {}",
                                e
                            ),
                        };
                        let transaction = connection.transaction()?;
                        update_contract_state(
                            *contract_address,
                            &update.storage,
                            None,
                            None,
                            &transaction,
                            verify_hashes,
                            block_number,
                        )
                    },
                )
                .collect();

            let _ = send.send(result);
        })
    });

    let system_contract_update_results = recv.recv().context("Panic on rayon thread")??;

    for system_contract_update_result in system_contract_update_results.iter() {
        storage_commitment_tree
            .set(
                system_contract_update_result.contract_address,
                system_contract_update_result.state_hash,
            )
            .context("Updating storage commitment tree")?;
    }

    // Apply storage commitment tree changes.
    let (computed_storage_commitment, nodes) = storage_commitment_tree
        .commit()
        .context("Apply storage commitment tree updates")?;

    if storage_commitment != computed_storage_commitment {
        return Err(ContractDiffSyncError::StorageCommitmentMismatch(
            PeerData::new(peer, block_number),
        ));
    }

    contract_update_results.extend(system_contract_update_results);

    Ok(PeerData::new(
        peer,
        VerificationOk {
            block_number,
            block_hash,
            storage_commitment,
            contract_update_results,
            trie_nodes: nodes,
            contract_updates,
        },
    ))
}

pub(super) async fn persist(
    storage: Storage,
    verification_results: Vec<PeerData<VerificationOk>>,
) -> Result<BlockNumber, ContractDiffSyncError> {
    tokio::task::spawn_blocking(move || {
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;
        let tail = verification_results
            .last()
            .map(|x| x.data.block_number)
            .ok_or(anyhow::anyhow!(
                "Verification results are empty, no block to persist"
            ))?;

        for VerificationOk {
            block_number,
            block_hash,
            storage_commitment,
            contract_update_results,
            trie_nodes,
            contract_updates,
        } in verification_results.into_iter().map(|x| x.data)
        {
            for contract_update_result in contract_update_results {
                contract_update_result
                    .insert(block_number, &transaction)
                    .context("Persisting contract update result")?;
            }

            let root_idx = if !storage_commitment.0.is_zero() {
                let root_idx = transaction
                    .insert_storage_trie(storage_commitment, &trie_nodes)
                    .context("Persisting storage trie")?;

                Some(root_idx)
            } else {
                None
            };

            transaction
                .insert_storage_root(block_number, root_idx)
                .context("Inserting storage root index")?;

            let state_update = StateUpdate {
                block_hash,
                contract_updates: contract_updates.regular,
                system_contract_updates: contract_updates.system,
                ..Default::default()
            };

            transaction
                .insert_state_update(block_number, &state_update)
                .context("Inserting state update")?;
        }

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
