use std::collections::HashMap;

use crate::{ContractsStorageTree, StorageCommitmentTree};
use anyhow::Context;
use pathfinder_common::{
    trie::TrieNode, ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
    StorageAddress, StorageValue,
};
use pathfinder_storage::Transaction;
use stark_hash::{stark_hash, Felt};

pub struct ContractUpdateResult {
    pub contract_address: ContractAddress,
    pub state_hash: ContractStateHash,
    pub root: ContractRoot,
    pub nonce: ContractNonce,
    pub trie_nodes: HashMap<Felt, TrieNode>,
    pub class_hash: ClassHash,
}

impl ContractUpdateResult {
    pub fn insert(self, transaction: &Transaction<'_>) -> anyhow::Result<()> {
        transaction.insert_contract_state(
            self.state_hash,
            self.class_hash,
            self.root,
            self.nonce,
        )?;
        let count = transaction.insert_contract_trie(self.root, &self.trie_nodes)?;
        tracing::trace!(contract=%self.contract_address, new_nodes=%count, "Persisted contract trie");

        Ok(())
    }
}

/// Updates a contract's state with and returns the resulting [ContractStateHash].
pub fn update_contract_state(
    contract_address: ContractAddress,
    updates: &HashMap<StorageAddress, StorageValue>,
    new_nonce: Option<ContractNonce>,
    new_class_hash: Option<ClassHash>,
    storage_commitment_tree: &StorageCommitmentTree<'_>,
    transaction: &Transaction<'_>,
    verify_hashes: bool,
) -> anyhow::Result<ContractUpdateResult> {
    // Update the contract state tree.
    let state_hash = storage_commitment_tree
        .get(contract_address)
        .context("Get contract state hash from global state tree")?
        .unwrap_or(ContractStateHash(Felt::ZERO));

    // Fetch contract's previous root, class hash and nonce.
    //
    // If the contract state does not exist yet (new contract):
    // Contract root defaults to ZERO because that is the default merkle tree value.
    // Contract nonce defaults to ZERO because that is its historical value before being added in 0.10.
    let (old_root, old_class_hash, old_nonce) = transaction
        .contract_state(state_hash)
        .context("Read contract root and nonce from contracts state table")?
        .map_or_else(
            || (ContractRoot::ZERO, None, ContractNonce::ZERO),
            |(root, class_hash, nonce)| (root, Some(class_hash), nonce),
        );

    let new_nonce = new_nonce.unwrap_or(old_nonce);

    // Load the contract tree and insert the updates.
    let (new_root, new_nodes) = if !updates.is_empty() {
        let mut contract_tree =
            ContractsStorageTree::load(transaction, old_root).with_verify_hashes(verify_hashes);
        for (key, value) in updates {
            contract_tree
                .set(*key, *value)
                .context("Update contract storage tree")?;
        }
        contract_tree
            .commit()
            .context("Apply contract storage tree changes")?
    } else {
        (old_root, Default::default())
    };

    // Calculate contract state hash, update global state tree and persist pre-image.
    //
    // The contract at address 0x1 is special. It was never deployed and doesn't have a class.
    let new_class_hash = if contract_address == ContractAddress::ONE {
        ClassHash::ZERO
    } else {
        new_class_hash
            .or(old_class_hash)
            .context("Class hash is unknown for new contract")?
    };
    let new_state_hash = calculate_contract_state_hash(new_class_hash, new_root, new_nonce);

    Ok(ContractUpdateResult {
        contract_address,
        state_hash: new_state_hash,
        root: new_root,
        nonce: new_nonce,
        trie_nodes: new_nodes,
        class_hash: new_class_hash,
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
