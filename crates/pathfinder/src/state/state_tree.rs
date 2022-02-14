//! Contains the [GlobalStateTree] and [ContractsStateTree] trees, which combined
//! store the total StarkNet state.
//!
//! These are abstractions built-on the [Binary Merkle-Patricia Tree](MerkleTree).

use rusqlite::Transaction;

use crate::{
    core::{
        ContractAddress, ContractRoot, ContractStateHash, GlobalRoot, StorageAddress, StorageValue,
    },
    state::merkle_tree::MerkleTree,
};

/// A Binary Merkle-Patricia Tree which contains
/// the storage state of all StarkNet contracts.
pub struct ContractsStateTree<'a> {
    tree: MerkleTree<'a>,
}

impl<'a> ContractsStateTree<'a> {
    /// Loads a [ContractsStateTree] with the given root. Use [None] to create an empty tree.
    pub fn load(transaction: &'a Transaction, root: Option<ContractRoot>) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let root = root.map(|val| val.0);
        let tree = MerkleTree::load("tree_contracts".to_string(), transaction, root)?;

        Ok(Self { tree })
    }

    pub fn _get(&self, address: StorageAddress) -> anyhow::Result<Option<StorageValue>> {
        let value = self.tree.get(address.0)?.map(StorageValue);
        Ok(value)
    }

    pub fn set(&mut self, address: StorageAddress, value: StorageValue) -> anyhow::Result<()> {
        self.tree.set(address.0, value.0)
    }

    /// Applies and persists any changes. Returns the new tree root.
    pub fn apply(self) -> anyhow::Result<ContractRoot> {
        let root = self.tree.commit()?;
        Ok(ContractRoot(root))
    }
}

/// A Binary Merkle-Patricia Tree which contains
/// the global state of StarkNet.
pub struct GlobalStateTree<'a> {
    tree: MerkleTree<'a>,
}

impl<'a> GlobalStateTree<'a> {
    /// Loads a [GlobalStateTree] with the given root. Use [None] to create an empty tree.
    pub fn load(transaction: &'a Transaction, root: Option<GlobalRoot>) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let root = root.map(|val| val.0);
        let tree = MerkleTree::load("tree_global".to_string(), transaction, root)?;

        Ok(Self { tree })
    }

    pub fn get(&self, address: ContractAddress) -> anyhow::Result<Option<ContractStateHash>> {
        let value = self.tree.get(address.0)?.map(ContractStateHash);
        Ok(value)
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(address.0, value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<GlobalRoot> {
        let root = self.tree.commit()?;
        Ok(GlobalRoot(root))
    }
}
