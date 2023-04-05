use anyhow::Context;
use pathfinder_common::{ClassCommitment, ClassCommitmentLeafHash, SierraHash};
use rusqlite::Transaction;

use crate::merkle_tree::MerkleTree;
use crate::PoseidonHash;

/// Merkle tree which contains Starknet's class commitment.
///
/// This tree maps a class's [SierraHash] to its [ClassCommitmentLeafHash]
pub struct ClassCommitmentTree<'tx> {
    tree: MerkleTree<PoseidonHash, 251>,
    storage: ClassStorage<'tx>,
}

crate::define_sqlite_storage!(ClassStorage, "tree_class");

impl<'tx> ClassCommitmentTree<'tx> {
    pub fn load(transaction: &'tx Transaction<'tx>, root: ClassCommitment) -> Self {
        let tree = MerkleTree::new(root.0);
        let storage = ClassStorage::new(&transaction);

        Self { tree, storage }
    }

    /// Adds a leaf node for a Sierra -> CASM commitment.
    ///
    /// Note that the leaf value is _not_ the Cairo hash, but a hashed value based on that.
    /// See <https://github.com/starkware-libs/cairo-lang/blob/12ca9e91bbdc8a423c63280949c7e34382792067/src/starkware/starknet/core/os/state.cairo#L302>
    /// for details.
    pub fn set(&mut self, class: SierraHash, value: ClassCommitmentLeafHash) -> anyhow::Result<()> {
        self.tree.set(&self.storage, class.view_bits(), value.0)
    }

    /// Applies and persists any changes. Returns the new global root.
    pub fn apply(self) -> anyhow::Result<ClassCommitment> {
        let root = self.tree.commit(&self.storage)?;
        Ok(ClassCommitment(root))
    }
}
