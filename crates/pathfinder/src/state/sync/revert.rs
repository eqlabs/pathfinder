use anyhow::Context;
use pathfinder_common::{
    BlockHeader, BlockNumber, ClassCommitment, ClassCommitmentLeafHash, ContractStateHash,
    StorageCommitment,
};
use pathfinder_merkle_tree::{ClassCommitmentTree, StorageCommitmentTree};
use pathfinder_storage::Transaction;

/// Revert Starknet state by applying reverse-updates.
///
/// Computes the contract and Sierra class reverse-updates then applies those to the Merkle tries.
/// Returns an error if the commitments calculated after making the changes do not match the
/// commitments in the target block header.
pub fn revert_starknet_state(
    transaction: &Transaction<'_>,
    head: BlockNumber,
    target_block: BlockNumber,
    target_header: BlockHeader,
    force: bool,
) -> Result<(), anyhow::Error> {
    revert_contract_updates(
        transaction,
        head,
        target_block,
        target_header.storage_commitment,
        force,
    )?;
    revert_class_updates(
        transaction,
        head,
        target_block,
        target_header.class_commitment,
        force,
    )?;
    Ok(())
}

/// Revert all contract/global storage trie updates.
///
/// Fetches reverse updates from the database and updates all tries, returning the storage commitment
/// and the storage root node index.
fn revert_contract_updates(
    transaction: &Transaction<'_>,
    head: BlockNumber,
    target_block: BlockNumber,
    expected_storage_commitment: StorageCommitment,
    force: bool,
) -> anyhow::Result<()> {
    let state_root_exists = match transaction.storage_root_index(target_block)? {
        None => false,
        Some(root_idx) => transaction.storage_trie_node(root_idx)?.is_some(),
    };

    if force || !state_root_exists {
        let updates = transaction.reverse_contract_updates(head, target_block)?;

        let mut global_tree = StorageCommitmentTree::load(transaction, head)
            .context("Loading global storage tree")?;

        for (contract_address, contract_update) in updates {
            let state_hash = pathfinder_merkle_tree::contract_state::revert_contract_state(
                transaction,
                contract_address,
                head,
                target_block,
                contract_update,
            )?;

            let expected_contract_state_hash = transaction
                .contract_state_hash(target_block, contract_address)
                .context("Fetching expected contract state hash")?
                // non-existent contracts are mapped to a zero state hash
                .unwrap_or(ContractStateHash::ZERO);
            if expected_contract_state_hash != state_hash {
                anyhow::bail!(
                    "Contract state hash mismatch: address {} computed {} expected {}",
                    contract_address,
                    state_hash,
                    expected_contract_state_hash
                );
            }

            global_tree
                .set(contract_address, state_hash)
                .context("Updating contract state hash in global tree")?;
        }

        tracing::debug!("Applied reverse updates, committing global state tree");

        let (storage_commitment, nodes_added) = global_tree
            .commit()
            .context("Committing global state tree")?;

        if expected_storage_commitment != storage_commitment {
            anyhow::bail!(
                "Storage commitment mismatch: expected {}, calculated {}",
                expected_storage_commitment,
                storage_commitment
            );
        }

        let root_idx = if !storage_commitment.0.is_zero() {
            let root_idx = transaction
                .insert_storage_trie(storage_commitment, &nodes_added)
                .context("Persisting storage trie")?;

            Some(root_idx)
        } else {
            None
        };

        transaction
            .insert_or_update_storage_root(target_block, root_idx)
            .context("Inserting storage root index")?;
        tracing::debug!(%target_block, %storage_commitment, "Committed global state tree");
    } else {
        tracing::debug!(%target_block, "State tree root node exists");
    }
    Ok(())
}

/// Revert all class trie updates.
fn revert_class_updates(
    transaction: &Transaction<'_>,
    head: BlockNumber,
    target_block: BlockNumber,
    expected_class_commitment: ClassCommitment,
    force: bool,
) -> anyhow::Result<()> {
    let class_root_exists = match transaction.class_root_index(target_block)? {
        None => false,
        Some(root_idx) => transaction.class_trie_node(root_idx)?.is_some(),
    };

    if force || !class_root_exists {
        let updates = transaction.reverse_sierra_class_updates(head, target_block)?;

        let mut class_tree = ClassCommitmentTree::load(transaction, head)
            .context("Loading class commitment trie")?;

        for (class_hash, casm_update) in updates {
            let new_value = match casm_update {
                None => {
                    // The class must be removed
                    ClassCommitmentLeafHash::ZERO
                }
                Some(casm_hash) => {
                    // Class hash has changed. Note that the class commitment leaf must have already been added to storage.
                    pathfinder_common::calculate_class_commitment_leaf_hash(casm_hash)
                }
            };

            class_tree
                .set(class_hash, new_value)
                .context("Updating class commitment trie")?;
        }

        let (class_commitment, nodes_added) =
            class_tree.commit().context("Committing class trie")?;

        if expected_class_commitment != class_commitment {
            anyhow::bail!(
                "Storage commitment mismatch: expected {}, calculated {}",
                expected_class_commitment,
                class_commitment
            );
        }

        let root_idx = if !class_commitment.0.is_zero() {
            let root_idx = transaction
                .insert_class_trie(class_commitment, &nodes_added)
                .context("Persisting class trie")?;

            Some(root_idx)
        } else {
            None
        };

        transaction
            .insert_or_update_class_root(target_block, root_idx)
            .context("Inserting class root index")?;

        tracing::debug!(%target_block, %class_commitment, "Committed class trie");
    }

    Ok(())
}
