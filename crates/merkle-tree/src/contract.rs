//! Contains the [StorageCommitmentTree] and [ContractsStorageTree] trees, which combined
//! store the total Starknet storage state.
//!
//! These are abstractions built-on the [Binary Merkle-Patricia Tree](MerkleTree).

use crate::{
    merkle_node::InternalNode,
    tree::{MerkleTree, Visit},
};
use anyhow::Context;
use bitvec::{prelude::Msb0, slice::BitSlice};
use pathfinder_common::hash::PedersenHash;
use pathfinder_common::trie::TrieNode;
use pathfinder_common::{
    ContractAddress, ContractRoot, ContractStateHash, StorageAddress, StorageCommitment,
    StorageValue,
};
use pathfinder_storage::{ContractTrieReader, StorageTrieReader, Transaction};
use stark_hash::Felt;
use std::collections::HashMap;
use std::ops::ControlFlow;

/// A [Patricia Merkle tree](MerkleTree) used to calculate commitments to a Starknet contract's storage.
///
/// It maps a contract's [storage addresses](StorageAddress) to their [values](StorageValue).
///
/// Tree data is persisted by a sqlite table 'tree_contracts'.
pub struct ContractsStorageTree<'tx> {
    tree: MerkleTree<PedersenHash, 251>,
    storage: ContractTrieReader<'tx>,
}

impl<'tx> ContractsStorageTree<'tx> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ContractRoot) -> anyhow::Result<Self> {
        let tree = MerkleTree::new(root.0);
        let storage = transaction
            .contract_trie_reader()
            .context("Loading storage")?;

        Ok(Self { tree, storage })
    }

    #[allow(dead_code)]
    pub fn get(&mut self, address: StorageAddress) -> anyhow::Result<Option<StorageValue>> {
        let value = self.tree.get(&mut self.storage, address.view_bits())?;
        Ok(value.map(StorageValue))
    }

    /// Generates a proof for `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&mut self, key: &BitSlice<Msb0, u8>) -> anyhow::Result<Vec<TrieNode>> {
        self.tree.get_proof(&mut self.storage, key)
    }

    pub fn set(&mut self, address: StorageAddress, value: StorageValue) -> anyhow::Result<()> {
        self.tree.set(&mut self.storage, address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new tree root.
    pub fn commit(self) -> anyhow::Result<(ContractRoot, HashMap<Felt, TrieNode>)> {
        let update = self.tree.commit()?;
        let commitment = ContractRoot(update.root);
        Ok((commitment, update.nodes))
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&InternalNode, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &mut self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(&mut self.storage, f)
    }
}

/// A [Patricia Merkle tree](MerkleTree) used to calculate commitments to all of Starknet's storage.
///
/// It maps each contract's [address](ContractAddress) to it's [state hash](ContractStateHash).
///
/// Tree data is persisted by a sqlite table 'tree_global'.
pub struct StorageCommitmentTree<'tx> {
    tree: MerkleTree<PedersenHash, 251>,
    storage: StorageTrieReader<'tx>,
}

impl<'tx> StorageCommitmentTree<'tx> {
    pub fn load(
        transaction: &'tx Transaction<'tx>,
        root: StorageCommitment,
    ) -> anyhow::Result<Self> {
        let tree = MerkleTree::new(root.0);
        let storage = transaction
            .storage_trie_reader()
            .context("Loading storage")?;

        Ok(Self { tree, storage })
    }

    pub fn get(&mut self, address: ContractAddress) -> anyhow::Result<Option<ContractStateHash>> {
        let value = self.tree.get(&mut self.storage, address.view_bits())?;
        Ok(value.map(ContractStateHash))
    }

    pub fn set(
        &mut self,
        address: ContractAddress,
        value: ContractStateHash,
    ) -> anyhow::Result<()> {
        self.tree.set(&mut self.storage, address.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn commit(self) -> anyhow::Result<(StorageCommitment, HashMap<Felt, TrieNode>)> {
        let update = self.tree.commit()?;
        let commitment = StorageCommitment(update.root);
        Ok((commitment, update.nodes))
    }

    /// Generates a proof for the given `key`. See [`MerkleTree::get_proof`].
    pub fn get_proof(&mut self, address: &ContractAddress) -> anyhow::Result<Vec<TrieNode>> {
        self.tree.get_proof(&mut self.storage, address.view_bits())
    }

    /// See [`MerkleTree::dfs`]
    pub fn dfs<B, F: FnMut(&InternalNode, &BitSlice<Msb0, u8>) -> ControlFlow<B, Visit>>(
        &mut self,
        f: &mut F,
    ) -> anyhow::Result<Option<B>> {
        self.tree.dfs(&mut self.storage, f)
    }
}
