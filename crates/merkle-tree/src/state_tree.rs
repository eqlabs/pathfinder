//! Contains the [StorageCommitmentTree] and [ContractsStateTree] trees, which combined
//! store the total StarkNet state.
//!
//! These are abstractions built-on the [Binary Merkle-Patricia Tree](MerkleTree).

use crate::{
    merkle_node::Node,
    merkle_tree::{MerkleTree, ProofNode, Visit},
};
use crate::{PedersenHash, PoseidonHash};
use bitvec::{prelude::Msb0, slice::BitSlice};
use pathfinder_common::{
    ClassCommitment, ClassCommitmentLeafHash, ContractAddress, ContractRoot, ContractStateHash,
    SierraHash, StorageAddress, StorageCommitment, StorageValue,
};
use pathfinder_storage::merkle_tree::RcNodeStorage;
use rusqlite::Transaction;
use std::ops::ControlFlow;

/// A Binary Merkle-Patricia Tree which contains
/// the storage state of all StarkNet contracts.
pub struct ContractsStateTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>, PedersenHash>,
}

impl<'tx> ContractsStateTree<'tx, '_> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ContractRoot) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_contracts", transaction, root.0)?;

        Ok(Self { tree })
    }

    #[allow(dead_code)]
    pub fn get(&self, address: StorageAddress) -> anyhow::Result<Option<StorageValue>> {
        let value = self.tree.get(address.view_bits())?;
        Ok(value.map(StorageValue))
    }

    /// Generates a proof for `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<Vec<ProofNode>> {
        self.tree.get_proof(key)
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
}

/// A Binary Merkle-Patricia Tree which contains StarkNet's storage commitment.
pub struct StorageCommitmentTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>, PedersenHash>,
}

impl<'tx> StorageCommitmentTree<'tx, '_> {
    pub fn load(
        transaction: &'tx Transaction<'tx>,
        root: StorageCommitment,
    ) -> anyhow::Result<Self> {
        // TODO: move the string into storage.
        let tree = MerkleTree::load("tree_global", transaction, root.0)?;

        Ok(Self { tree })
    }

    pub fn get(&self, address: ContractAddress) -> anyhow::Result<Option<ContractStateHash>> {
        let value = self.tree.get(address.view_bits())?;
        Ok(value.map(ContractStateHash))
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<StorageCommitment> {
        let root = self.tree.commit()?;
        Ok(StorageCommitment(root))
    }

    /// Generates a proof for the given `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&self, address: &ContractAddress) -> anyhow::Result<Vec<ProofNode>> {
        self.tree.get_proof(address.view_bits())
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&Node, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(f)
    }
}

/// Merkle tree which contains Starknet's class commitment.
///
/// This tree maps a class's [SierraHash] to its [ClassCommitmentLeafHash]
pub struct ClassCommitmentTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>, PoseidonHash>,
}

impl<'tx> ClassCommitmentTree<'tx, '_> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ClassCommitment) -> anyhow::Result<Self> {
        let tree = MerkleTree::load("tree_class", transaction, root.0)?;

        Ok(Self { tree })
    }

    /// Adds a leaf node for a Sierra -> CASM commitment.
    ///
    /// Note that the leaf value is _not_ the Cairo hash, but a hashed value based on that.
    /// See <https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/state.cairo#L302>
    /// for details.
    pub fn set(&mut self, class: SierraHash, value: ClassCommitmentLeafHash) -> anyhow::Result<()> {
        self.tree.set(class.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<ClassCommitment> {
        let root = self.tree.commit()?;
        Ok(ClassCommitment(root))
    }
}
