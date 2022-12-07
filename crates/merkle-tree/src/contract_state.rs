use crate::state_tree::{ContractsStateTree, GlobalStateTree};
use anyhow::Context;
use pathfinder_common::{
    ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
};
use pathfinder_storage::{ContractsStateTable, ContractsTable};
use rusqlite::Transaction;
use stark_hash::{stark_hash, StarkHash};
use starknet_gateway_types::reply::state_update::StorageDiff;

/// Updates a contract's state with the given [`StorageDiff`]. It returns the
/// [ContractStateHash] of the new state.
///
/// Specifically, it updates the [ContractsStateTree] and [ContractsStateTable].
pub fn update_contract_state(
    contract_address: ContractAddress,
    updates: &[StorageDiff],
    new_nonce: Option<ContractNonce>,
    global_tree: &GlobalStateTree<'_, '_>,
    db: &Transaction<'_>,
) -> anyhow::Result<ContractStateHash> {
    // Update the contract state tree.
    let state_hash = global_tree
        .get(contract_address)
        .context("Get contract state hash from global state tree")?
        .unwrap_or(ContractStateHash(StarkHash::ZERO));

    // Fetch contract's previous root and nonce. Both default to ZERO if they do not exist.
    //
    // Contract root defaults to ZERO because that is the default merkle tree value.
    // Contract nonce defaults to ZERO because that is its historical value before being added in 0.10.
    let (old_root, old_nonce) = ContractsStateTable::get_root_and_nonce(db, state_hash)
        .context("Read contract root and nonce from contracts state table")?
        .unwrap_or((ContractRoot::ZERO, ContractNonce::ZERO));

    let new_nonce = new_nonce.unwrap_or(old_nonce);

    // Load the contract tree and insert the updates.
    let new_root = if !updates.is_empty() {
        let mut contract_tree =
            ContractsStateTree::load(db, old_root).context("Load contract state tree")?;
        for storage_diff in updates {
            contract_tree
                .set(storage_diff.key, storage_diff.value)
                .context("Update contract storage tree")?;
        }
        contract_tree
            .apply()
            .context("Apply contract storage tree changes")?
    } else {
        old_root
    };

    // Calculate contract state hash, update global state tree and persist pre-image.
    let class_hash = ContractsTable::get_hash(db, contract_address)
        .context("Read class hash from contracts table")?
        .context("Class hash is missing from contracts table")?;
    let contract_state_hash = calculate_contract_state_hash(class_hash, new_root, new_nonce);

    ContractsStateTable::upsert(db, contract_state_hash, class_hash, new_root, new_nonce)
        .context("Insert constract state hash into contracts state table")?;

    Ok(contract_state_hash)
}

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(
    hash: ClassHash,
    root: ContractRoot,
    nonce: ContractNonce,
) -> ContractStateHash {
    const CONTRACT_STATE_HASH_VERSION: StarkHash = StarkHash::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = stark_hash(hash.0, root.0);
    let hash = stark_hash(hash, nonce.0);
    let hash = stark_hash(hash, CONTRACT_STATE_HASH_VERSION);

    // Compare this with the HashChain construction used in the contract_hash: the number of
    // elements is not hashed to this hash, and this is supposed to be different.
    ContractStateHash(hash)
}

#[cfg(test)]
mod tests {
    use super::calculate_contract_state_hash;
    use pathfinder_common::starkhash;
    use pathfinder_common::{ClassHash, ContractNonce, ContractRoot, ContractStateHash};

    #[test]
    fn hash() {
        let root = starkhash!("04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028");
        let root = ContractRoot(root);

        let hash = starkhash!("02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779");
        let hash = ClassHash(hash);

        let nonce = ContractNonce::ZERO;

        let expected =
            starkhash!("07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3");
        let expected = ContractStateHash(expected);

        let result = calculate_contract_state_hash(hash, root, nonce);

        assert_eq!(result, expected);
    }
}
