use std::collections::HashMap;

use crate::ContractsStorageTree;
use anyhow::Context;
use pathfinder_common::{
    BlockNumber, ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
    StorageAddress, StorageValue,
};
use pathfinder_crypto::{hash::pedersen_hash, Felt};
use pathfinder_storage::{Node, Transaction};

pub struct ContractStateUpdateResult {
    pub state_hash: ContractStateHash,
    pub contract_address: ContractAddress,
    root: ContractRoot,
    did_storage_updates: bool,
    // trie nodes to be inserted into the database
    nodes: HashMap<Felt, Node>,
}

impl ContractStateUpdateResult {
    /// Inserts the results of a contract state update into the database.
    ///
    /// The new trie nodes are committed first, then the root node index and the contract state hash
    /// is persisted.
    pub fn insert(self, block: BlockNumber, transaction: &Transaction<'_>) -> anyhow::Result<()> {
        // Insert nodes only if we made storage updates.
        if self.did_storage_updates {
            let root_index = if !self.root.0.is_zero() && !self.nodes.is_empty() {
                let root_index = transaction
                    .insert_contract_trie(self.root, &self.nodes)
                    .context("Persisting contract trie")?;
                Some(root_index)
            } else {
                None
            };

            transaction
                .insert_contract_root(block, self.contract_address, root_index)
                .context("Inserting contract's root index")?;
        }

        transaction
            .insert_contract_state_hash(block, self.contract_address, self.state_hash)
            .context("Inserting contract state hash")
    }
}

/// Updates a contract's state with and returns the resulting [ContractStateHash].
pub fn update_contract_state(
    contract_address: ContractAddress,
    updates: &HashMap<StorageAddress, StorageValue>,
    new_nonce: Option<ContractNonce>,
    new_class_hash: Option<ClassHash>,
    transaction: &Transaction<'_>,
    verify_hashes: bool,
    block: BlockNumber,
) -> anyhow::Result<ContractStateUpdateResult> {
    // Load the contract tree and insert the updates.
    let (new_root, nodes) = if !updates.is_empty() {
        let mut contract_tree = match block.parent() {
            Some(parent) => ContractsStorageTree::load(transaction, contract_address, parent)
                .context("Loading contract storage tree")?
                .with_verify_hashes(verify_hashes),
            None => ContractsStorageTree::empty(transaction, contract_address),
        }
        .with_verify_hashes(verify_hashes);

        for (key, value) in updates {
            contract_tree
                .set(*key, *value)
                .context("Update contract storage tree")?;
        }
        let (contract_root, nodes) = contract_tree
            .commit()
            .context("Apply contract storage tree changes")?;

        (contract_root, nodes)
    } else {
        let current_root = transaction
            .contract_root(block, contract_address)
            .context("Querying current contract root")?
            .unwrap_or_default();

        (current_root, Default::default())
    };

    let class_hash = if contract_address == ContractAddress::ONE {
        // This is a special system contract at address 0x1, which doesn't have a class hash.
        ClassHash::ZERO
    } else if let Some(class_hash) = new_class_hash {
        class_hash
    } else {
        transaction
            .contract_class_hash(block.into(), contract_address)
            .context("Querying contract's class hash")?
            .context("Contract's class hash is missing")?
    };

    let nonce = if let Some(nonce) = new_nonce {
        nonce
    } else {
        transaction
            .contract_nonce(contract_address, block.into())
            .context("Querying contract's nonce")?
            //Nonce defaults to ZERO because that is its historical value before being added in 0.10.
            .unwrap_or_default()
    };

    let state_hash = calculate_contract_state_hash(class_hash, new_root, nonce);

    Ok(ContractStateUpdateResult {
        contract_address,
        state_hash,
        root: new_root,
        did_storage_updates: !updates.is_empty(),
        nodes,
    })
}

/// Calculates the contract state hash from its preimage.
pub fn calculate_contract_state_hash(
    hash: ClassHash,
    root: ContractRoot,
    nonce: ContractNonce,
) -> ContractStateHash {
    const CONTRACT_STATE_HASH_VERSION: Felt = Felt::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
    let hash = pedersen_hash(hash.0, root.0);
    let hash = pedersen_hash(hash, nonce.0);
    let hash = pedersen_hash(hash, CONTRACT_STATE_HASH_VERSION);

    // Compare this with the HashChain construction used in the contract_hash: the number of
    // elements is not hashed to this hash, and this is supposed to be different.
    ContractStateHash(hash)
}

#[cfg(test)]
mod tests {
    use super::calculate_contract_state_hash;
    use pathfinder_common::felt;
    use pathfinder_common::{ClassHash, ContractNonce, ContractRoot, ContractStateHash};

    #[test]
    fn hash() {
        let root = felt!("0x4fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028");
        let root = ContractRoot(root);

        let hash = felt!("0x2ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779");
        let hash = ClassHash(hash);

        let nonce = ContractNonce::ZERO;

        let expected = felt!("0x7161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3");
        let expected = ContractStateHash(expected);

        let result = calculate_contract_state_hash(hash, root, nonce);

        assert_eq!(result, expected);
    }
}
