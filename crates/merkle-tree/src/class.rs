use std::collections::HashMap;

use pathfinder_common::{ClassCommitment, ClassCommitmentLeafHash, SierraHash};
use pathfinder_storage::{Node, Transaction};
use stark_hash::Felt;

use crate::tree::MerkleTree;
use pathfinder_common::hash::PoseidonHash;

/// A [Patricia Merkle tree](MerkleTree) used to calculate commitments to Starknet's Sierra classes.
///
/// It maps a class's [SierraHash] to its [ClassCommitmentLeafHash]
///
/// Tree data is persisted by a sqlite table 'tree_class'.
pub struct ClassCommitmentTree<'tx> {
    tree: MerkleTree<PoseidonHash, 251>,
    storage: ClassStorage<'tx>,
}

impl<'tx> ClassCommitmentTree<'tx> {
    pub fn empty(transaction: &'tx Transaction<'tx>) -> Self {
        let storage = ClassStorage(transaction);
        let tree = MerkleTree::empty();

        Self { tree, storage }
    }

    pub fn load(transaction: &'tx Transaction<'tx>, root: u32) -> Self {
        let storage = ClassStorage(transaction);
        let tree = MerkleTree::new(root);

        Self { tree, storage }
    }

    pub fn with_verify_hashes(mut self, verify_hashes: bool) -> Self {
        self.tree = self.tree.with_verify_hashes(verify_hashes);
        self
    }

    /// Adds a leaf node for a Sierra -> CASM commitment.
    ///
    /// Note that the leaf value is _not_ the Cairo hash, but a hashed value based on that.
    /// See <https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/state.cairo#L302>
    /// for details.
    pub fn set(&mut self, class: SierraHash, value: ClassCommitmentLeafHash) -> anyhow::Result<()> {
        self.tree.set(&self.storage, class.view_bits(), value.0)
    }

    /// Commits the changes and calculates the new node hashes. Returns the new commitment and
    /// any potentially newly created nodes.
    pub fn commit(self) -> anyhow::Result<(ClassCommitment, HashMap<Felt, Node>)> {
        let update = self.tree.commit(&self.storage)?;

        let commitment = ClassCommitment(update.root);
        Ok((commitment, update.nodes))
    }
}

struct ClassStorage<'tx>(&'tx Transaction<'tx>);

impl crate::storage::Storage for ClassStorage<'_> {
    fn get(&self, index: u32) -> anyhow::Result<Option<pathfinder_storage::StoredNode>> {
        self.0.class_trie_node(index)
    }

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>> {
        self.0.class_trie_node_hash(index)
    }
}
