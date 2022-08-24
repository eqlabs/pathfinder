//! Contains the [GlobalStateTree] and [ContractsStateTree] trees, which combined
//! store the total StarkNet state.
//!
//! These are abstractions built-on the [Binary Merkle-Patricia Tree](MerkleTree).

use bitvec::{prelude::Msb0, slice::BitSlice};
use rusqlite::Transaction;
use std::ops::ControlFlow;

use crate::{
    core::{
        ContractAddress, ContractRoot, ContractStateHash, GlobalRoot, StorageAddress, StorageValue,
    },
    state::merkle_tree::{MerkleTree, Visit},
    storage::merkle_tree::RcNodeStorage,
};

use super::{merkle_node::Node, merkle_tree::VerificationMode};

/// A Binary Merkle-Patricia Tree which contains
/// the storage state of all StarkNet contracts.
pub struct ContractsStateTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>>,
}

impl<'tx> ContractsStateTree<'tx, '_> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ContractRoot) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_contracts", transaction, root.0)?;

        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn get(&self, address: StorageAddress) -> anyhow::Result<StorageValue> {
        let value = self.tree.get(address.view_bits())?;
        Ok(StorageValue(value))
    }

    pub fn set(&mut self, address: StorageAddress, value: StorageValue) -> anyhow::Result<()> {
        self.tree.set(address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new tree root.
    pub fn apply(self) -> anyhow::Result<ContractRoot> {
        let root = self.tree.commit()?;
        Ok(ContractRoot(root))
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&Node, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(f)
    }

    pub fn verification(&mut self) -> &mut VerificationMode {
        self.tree.verification()
    }
}

/// A Binary Merkle-Patricia Tree which contains
/// the global state of StarkNet.
pub struct GlobalStateTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>>,
}

impl<'tx> GlobalStateTree<'tx, '_> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: GlobalRoot) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_global", transaction, root.0)?;

        Ok(Self { tree })
    }

    pub fn get(&self, address: ContractAddress) -> anyhow::Result<ContractStateHash> {
        let value = self.tree.get(address.view_bits())?;
        Ok(ContractStateHash(value))
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<GlobalRoot> {
        let root = self.tree.commit()?;
        Ok(GlobalRoot(root))
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&Node, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(f)
    }

    pub fn verification(&mut self) -> &mut VerificationMode {
        self.tree.verification()
    }
}
