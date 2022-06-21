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
    storage::merkle_tree::RcNodeStorage,
};

/// A Binary Merkle-Patricia Tree which contains
/// the storage state of all StarkNet contracts.
pub struct ContractsStateTree<'a> {
    tree: MerkleTree<RcNodeStorage<'a>>,
}

impl<'a> ContractsStateTree<'a> {
    pub fn load(transaction: &'a Transaction<'_>, root: ContractRoot) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_contracts".to_string(), transaction, root.0)?;

        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn get(&self, address: StorageAddress) -> anyhow::Result<StorageValue> {
        let value = self.tree.get(address.0.view_bits())?;
        Ok(StorageValue(value))
    }

    pub fn set(&mut self, address: StorageAddress, value: StorageValue) -> anyhow::Result<()> {
        self.tree.set(address.0.view_bits(), value.0)
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
    tree: MerkleTree<RcNodeStorage<'a>>,
}

impl<'a> GlobalStateTree<'a> {
    pub fn load(transaction: &'a Transaction<'_>, root: GlobalRoot) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_global".to_string(), transaction, root.0)?;

        Ok(Self { tree })
    }

    pub fn get(&self, address: ContractAddress) -> anyhow::Result<ContractStateHash> {
        let value = self.tree.get(address.0.view_bits())?;
        Ok(ContractStateHash(value))
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(address.0.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<GlobalRoot> {
        let root = self.tree.commit()?;
        Ok(GlobalRoot(root))
    }
}
