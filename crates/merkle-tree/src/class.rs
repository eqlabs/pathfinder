use std::collections::HashMap;

use anyhow::Context;
use pathfinder_common::{
    calculate_class_commitment_leaf_hash, BlockNumber, ClassCommitment, ClassCommitmentLeafHash,
    ClassHash, SierraHash,
};
use pathfinder_crypto::Felt;
use pathfinder_storage::{Node, Transaction};

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
    pub fn empty(tx: &'tx Transaction<'tx>) -> Self {
        let storage = ClassStorage { tx, block: None };
        let tree = MerkleTree::empty();

        Self { tree, storage }
    }

    pub fn load(tx: &'tx Transaction<'tx>, block: BlockNumber) -> anyhow::Result<Self> {
        let root = tx
            .class_root_index(block)
            .context("Querying class root index")?;
        let Some(root) = root else {
            return Ok(Self::empty(tx));
        };

        let storage = ClassStorage {
            tx,
            block: Some(block),
        };
        let tree = MerkleTree::new(root);

        Ok(Self { tree, storage })
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
        let key = class.view_bits().to_owned();
        self.tree.set(&self.storage, key, value.0)
    }

    /// Commits the changes and calculates the new node hashes. Returns the new commitment and
    /// any potentially newly created nodes.
    pub fn commit(self) -> anyhow::Result<(ClassCommitment, HashMap<Felt, Node>)> {
        let update = self.tree.commit(&self.storage)?;

        let commitment = ClassCommitment(update.root);
        Ok((commitment, update.nodes))
    }
}

struct ClassStorage<'tx> {
    tx: &'tx Transaction<'tx>,
    block: Option<BlockNumber>,
}

impl crate::storage::Storage for ClassStorage<'_> {
    fn get(&self, index: u64) -> anyhow::Result<Option<pathfinder_storage::StoredNode>> {
        self.tx.class_trie_node(index)
    }

    fn hash(&self, index: u64) -> anyhow::Result<Option<Felt>> {
        self.tx.class_trie_node_hash(index)
    }

    fn leaf(
        &self,
        path: &bitvec::slice::BitSlice<u8, bitvec::prelude::Msb0>,
    ) -> anyhow::Result<Option<Felt>> {
        assert!(path.len() == 251);

        let Some(block) = self.block else {
            return Ok(None);
        };

        let sierra = ClassHash(Felt::from_bits(path).context("Mapping path to sierra hash")?);

        let casm = self
            .tx
            .casm_hash_at(block.into(), sierra)
            .context("Querying CASM hash")?;
        let Some(casm) = casm else {
            return Ok(None);
        };

        let leaf = self
            .tx
            .class_commitment_leaf(block, &casm)
            .context("Querying class leaf")?
            .map(|x| x.0);

        Ok(leaf)
    }
}

/// Revert all class trie updates.
pub fn revert_class_updates(
    transaction: &Transaction<'_>,
    head: BlockNumber,
    target_block: BlockNumber,
    expected_class_commitment: ClassCommitment,
    force: bool,
) -> anyhow::Result<()> {
    let class_root_exists = match transaction.class_root_index(target_block)? {
        None => false,
        Some(root_idx) => transaction.class_trie_node(root_idx)?.is_some(),
    };

    if force || !class_root_exists {
        let updates = transaction.reverse_sierra_class_updates(head, target_block)?;

        let mut class_tree = ClassCommitmentTree::load(transaction, head)
            .context("Loading class commitment trie")?;

        for (class_hash, casm_update) in updates {
            let new_value = match casm_update {
                None => {
                    // The class must be removed
                    ClassCommitmentLeafHash::ZERO
                }
                Some(casm_hash) => {
                    // Class hash has changed. Note that the class commitment leaf must have already been added to storage.
                    calculate_class_commitment_leaf_hash(casm_hash)
                }
            };

            class_tree
                .set(class_hash, new_value)
                .context("Updating class commitment trie")?;
        }

        let (class_commitment, nodes_added) =
            class_tree.commit().context("Committing class trie")?;

        if expected_class_commitment != class_commitment {
            anyhow::bail!(
                "Storage commitment mismatch: expected {}, calculated {}",
                expected_class_commitment,
                class_commitment
            );
        }

        let root_idx = if !class_commitment.0.is_zero() {
            let root_idx = transaction
                .insert_class_trie(class_commitment, &nodes_added)
                .context("Persisting class trie")?;

            Some(root_idx)
        } else {
            None
        };

        transaction
            .insert_or_update_class_root(target_block, root_idx)
            .context("Inserting class root index")?;

        tracing::debug!(%target_block, %class_commitment, "Committed class trie");
    }

    Ok(())
}
