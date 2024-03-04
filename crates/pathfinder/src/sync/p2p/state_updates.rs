use anyhow::Context;
use p2p::PeerData;
use pathfinder_common::{
    state_update::ContractUpdates, BlockNumber, StateUpdate, StorageCommitment,
};
use pathfinder_merkle_tree::{contract_state::update_contract_state, StorageCommitmentTree};
use pathfinder_storage::{Storage, Transaction};
use tokio::task::spawn_blocking;

#[derive(Debug, thiserror::Error)]
pub(super) enum ContractDiffSyncError {
    #[error(transparent)]
    DatabaseOrComputeError(#[from] anyhow::Error),
    #[error("Storage commitment mismatch")]
    BadSignature(PeerData<BlockNumber>),
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

fn verify_then_persist_starknet_storage_update(
    transaction: &Transaction<'_>,
    storage_update: &ContractUpdates,
    verify_hashes: bool,
    block: BlockNumber,
    // we need this so that we can create extra read-only transactions for
    // parallel contract state updates
    storage: Storage,
) -> anyhow::Result<bool> {
    use rayon::prelude::*;

    let expected_storage_commitment = transaction
        .block_header(block.into())
        .context("getting block header")?
        .ok_or(anyhow::anyhow!("Block header not found"))?
        .storage_commitment;

    // 1. Compute the new storage commitment trie.

    let mut storage_commitment_tree = match block.parent() {
        Some(parent) => StorageCommitmentTree::load(transaction, parent)
            .context("Loading storage commitment tree")?,
        None => StorageCommitmentTree::empty(transaction),
    }
    .with_verify_hashes(verify_hashes);

    let (send, recv) = std::sync::mpsc::channel();

    // Apply contract storage updates to the storage commitment tree.
    rayon::scope(|s| {
        s.spawn(|_| {
            let result: Result<Vec<_>, _> = storage_update
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
                            block,
                        )
                    },
                )
                .collect();
            let _ = send.send(result);
        })
    });

    let contract_update_results = recv.recv().context("Panic on rayon thread")??;

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
            let result: Result<Vec<_>, _> = storage_update
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
                            block,
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

    // 2. Verify if the computed storage commitment matches the expected one.
    if expected_storage_commitment != computed_storage_commitment {
        anyhow::bail!(
            "storage commitment mismatch: computed {}, expected {}",
            computed_storage_commitment,
            expected_storage_commitment
        );
    }

    // 3. Persist the storage commitment tree changes.

    for contract_update_result in contract_update_results.into_iter() {
        contract_update_result
            .insert(block, transaction)
            .context("Persisting contract update result")?;
    }

    for system_contract_update_result in system_contract_update_results.into_iter() {
        system_contract_update_result
            .insert(block, transaction)
            .context("Persisting system contract update result")?;
    }

    let root_idx = if !computed_storage_commitment.0.is_zero() {
        let root_idx = transaction
            .insert_storage_trie(computed_storage_commitment, &nodes)
            .context("Persisting storage trie")?;

        Some(root_idx)
    } else {
        None
    };

    transaction
        .insert_storage_root(block, root_idx)
        .context("Inserting storage root index")?;

    Ok(true)
}
