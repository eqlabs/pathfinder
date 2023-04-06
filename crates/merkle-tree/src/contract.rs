//! Contains the [StorageCommitmentTree] and [ContractsStateTree] trees, which combined
//! store the total StarkNet state.
//!
//! These are abstractions built-on the [Binary Merkle-Patricia Tree](MerkleTree).

use crate::PedersenHash;
use crate::{
    merkle_node::InternalNode,
    merkle_tree::{MerkleTree, Visit},
};
use anyhow::Context;
use bitvec::{prelude::Msb0, slice::BitSlice};
use pathfinder_common::{
    ContractAddress, ContractRoot, ContractStateHash, StorageAddress, StorageCommitment,
    StorageValue,
};
use rusqlite::Transaction;
use std::ops::ControlFlow;

crate::define_sqlite_storage!(ContractsStorage, "tree_contracts");
crate::define_sqlite_storage!(GlobalStorage, "tree_global");

/// A Binary Merkle-Patricia Tree which contains
/// the storage state of all StarkNet contracts.
pub struct ContractsStateTree<'tx> {
    tree: MerkleTree<PedersenHash, 251>,
    storage: ContractsStorage<'tx>,
}

impl<'tx> ContractsStateTree<'tx> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ContractRoot) -> Self {
        let tree = MerkleTree::new(root.0);
        let storage = ContractsStorage::new(&transaction);

        Self { tree, storage }
    }

    #[allow(dead_code)]
    pub fn get(&self, address: StorageAddress) -> anyhow::Result<Option<StorageValue>> {
        let value = self.tree.get(&self.storage, address.view_bits())?;
        Ok(value.map(StorageValue))
    }

    /// Generates a proof for `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<Vec<crate::Node>> {
        self.tree.get_proof(&self.storage, key)
    }

    pub fn set(&mut self, address: StorageAddress, value: StorageValue) -> anyhow::Result<()> {
        self.tree.set(&self.storage, address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new tree root.
    pub fn commit_and_persist_changes(self) -> anyhow::Result<ContractRoot> {
        let update = self.tree.commit()?;
        for (hash, node) in update.added {
            self.storage.insert(&hash, &node)?;
        }
        Ok(ContractRoot(update.root))
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&InternalNode, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(&self.storage, f)
    }
}

/// A Binary Merkle-Patricia Tree which contains StarkNet's storage commitment.
pub struct StorageCommitmentTree<'tx> {
    tree: MerkleTree<PedersenHash, 251>,
    storage: GlobalStorage<'tx>,
}

impl<'tx> StorageCommitmentTree<'tx> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: StorageCommitment) -> Self {
        let tree = MerkleTree::new(root.0);
        let storage = GlobalStorage::new(&transaction);

        Self { tree, storage }
    }

    pub fn get(&self, address: ContractAddress) -> anyhow::Result<Option<ContractStateHash>> {
        let value = self.tree.get(&self.storage, address.view_bits())?;
        Ok(value.map(ContractStateHash))
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(&self.storage, address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn commit_and_persist_changes(self) -> anyhow::Result<StorageCommitment> {
        let update = self.tree.commit()?;
        for (hash, node) in update.added {
            self.storage.insert(&hash, &node)?;
        }
        Ok(StorageCommitment(update.root))
    }

    /// Generates a proof for the given `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&self, address: &ContractAddress) -> anyhow::Result<Vec<crate::Node>> {
        self.tree.get_proof(&self.storage, address.view_bits())
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&InternalNode, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(&self.storage, f)
    }
}
