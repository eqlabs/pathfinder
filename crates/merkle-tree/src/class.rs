use pathfinder_common::{ClassCommitment, ClassCommitmentLeafHash, SierraHash};
use pathfinder_storage::merkle_tree::RcNodeStorage;
use rusqlite::Transaction;

use crate::merkle_tree::MerkleTree;
use crate::PoseidonHash;

/// Merkle tree which contains Starknet's class commitment.
///
/// This tree maps a class's [SierraHash] to its [ClassCommitmentLeafHash]
pub struct ClassCommitmentTree<'tx, 'queries> {
    tree: MerkleTree<RcNodeStorage<'tx, 'queries>, PoseidonHash, 251>,
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
