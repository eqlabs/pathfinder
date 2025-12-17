use anyhow::Context;
use pathfinder_common::state_update::{StateUpdateError, StateUpdateRef};
use pathfinder_common::{BlockNumber, ClassCommitment, StorageCommitment};
use pathfinder_storage::{Storage, Transaction};

use crate::contract_state::update_contract_state;
use crate::{ClassCommitmentTree, StorageCommitmentTree};

pub fn update_starknet_state(
    transaction: &Transaction<'_>,
    state_update: StateUpdateRef<'_>,
    verify_hashes: bool,
    block: BlockNumber,
    // we need this so that we can create extra read-only transactions for
    // parallel contract state updates
    storage: Storage,
) -> Result<(StorageCommitment, ClassCommitment), StateUpdateError> {
    use rayon::prelude::*;

    let mut storage_commitment_tree = match block.parent() {
        Some(parent) => StorageCommitmentTree::load(transaction, parent)
            .context("Loading storage commitment tree")?,
        None => StorageCommitmentTree::empty(transaction),
    }
    .with_verify_hashes(verify_hashes);

    let (send, recv) = std::sync::mpsc::channel();

    rayon::scope(|s| {
        s.spawn(|_| {
            let result: Result<Vec<_>, _> = state_update
                .contract_updates
                .par_iter()
                .map_init(
                    || storage.clone().connection(),
                    |connection, (contract_address, update)| {
                        let connection = match connection {
                            Ok(connection) => connection,
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "Failed to create database connection in rayon thread: {e}"
                                )
                                .into())
                            }
                        };
                        let transaction = connection
                            .transaction()
                            .map_err(|e| StateUpdateError::StorageError(e.into()))?;
                        update_contract_state(
                            **contract_address,
                            update.storage,
                            *update.nonce,
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

    for contract_update_result in contract_update_results.into_iter() {
        storage_commitment_tree
            .set(
                contract_update_result.contract_address,
                contract_update_result.state_hash,
            )
            .context("Updating storage commitment tree")?;
        contract_update_result
            .insert(block, transaction)
            .context("Inserting contract update result")?;
    }

    for (contract, update) in state_update.system_contract_updates {
        let update_result = update_contract_state(
            *contract,
            update.storage,
            None,
            None,
            transaction,
            verify_hashes,
            block,
        )
        .context("Update system contract state")?;

        storage_commitment_tree
            .set(*contract, update_result.state_hash)
            .context("Updating system contract storage commitment tree")?;

        update_result
            .insert(block, transaction)
            .context("Persisting system contract trie updates")?;
    }

    // Apply storage commitment tree changes.
    let (storage_commitment, trie_update) = storage_commitment_tree
        .commit()
        .context("Apply storage commitment tree updates")?;

    let root_idx = transaction
        .insert_storage_trie(&trie_update, block)
        .context("Persisting storage trie")?;

    transaction
        .insert_storage_root(block, root_idx)
        .context("Inserting storage root index")?;

    // Add new Sierra classes to class commitment tree.
    let mut class_commitment_tree = match block.parent() {
        Some(parent) => ClassCommitmentTree::load(transaction, parent)
            .context("Loading class commitment tree")?,
        None => ClassCommitmentTree::empty(transaction),
    }
    .with_verify_hashes(verify_hashes);

    for (sierra, casm) in state_update
        .declared_sierra_classes
        .iter()
        .chain(state_update.migrated_compiled_classes.iter())
    {
        let leaf_hash = pathfinder_common::calculate_class_commitment_leaf_hash(*casm);

        transaction
            .insert_class_commitment_leaf(block, &leaf_hash, casm)
            .context("Adding class commitment leaf")?;

        class_commitment_tree
            .set(*sierra, leaf_hash)
            .context("Update class commitment tree")?;
    }

    // Apply all class commitment tree changes.
    let (class_commitment, trie_update) = class_commitment_tree
        .commit()
        .context("Apply class commitment tree updates")?;

    let class_root_idx = transaction
        .insert_class_trie(&trie_update, block)
        .context("Persisting class trie")?;

    transaction
        .insert_class_root(block, class_root_idx)
        .context("Inserting class root index")?;

    Ok((storage_commitment, class_commitment))
}
