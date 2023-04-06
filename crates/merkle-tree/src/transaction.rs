use bitvec::view::BitView;
use stark_hash::Felt;

use crate::merkle_tree::MerkleTree;

/// A Patricia Merkle tree with height 64 used to compute transaction and event commitments.
///
/// According to the [documentation](https://docs.starknet.io/docs/Blocks/header/#block-header)
/// the commitment trees are of height 64, because the key used is the 64 bit representation
/// of the index of the transaction / event within the block.
///
/// The tree height is 64 in our case since our set operation takes u64 index values.
pub struct TransactionTree {
    tree: MerkleTree<crate::PedersenHash, 64>,
}

impl Default for TransactionTree {
    fn default() -> Self {
        Self {
            tree: MerkleTree::empty(),
        }
    }
}

struct NullStorage;

impl crate::storage::Storage for NullStorage {
    type Error = std::convert::Infallible;

    fn get(&self, _node: &Felt) -> Result<Option<crate::Node>, Self::Error> {
        Ok(None)
    }
}

impl TransactionTree {
    pub fn set(&mut self, index: u64, value: Felt) -> anyhow::Result<()> {
        let key = index.to_be_bytes();
        self.tree.set(&NullStorage {}, key.view_bits(), value)
    }

    pub fn commit(self) -> anyhow::Result<Felt> {
        self.tree.commit().map(|update| update.root)
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::felt;

    use super::*;

    #[test]
    fn test_commitment_merkle_tree() {
        let mut tree = TransactionTree::default();

        for (idx, hash) in [1u64, 2, 3, 4].into_iter().enumerate() {
            let hash = Felt::from(hash);
            let idx: u64 = idx.try_into().unwrap();
            tree.set(idx, hash).unwrap();
        }

        // produced by the cairo-lang Python implementation:
        // `hex(asyncio.run(calculate_patricia_root([1, 2, 3, 4], height=64, ffc=ffc))))`
        let expected_root_hash =
            felt!("0x1a0e579b6b444769e4626331230b5ae39bd880f47e703b73fa56bf77e52e461");
        let computed_root_hash = tree.commit().unwrap();

        assert_eq!(expected_root_hash, computed_root_hash);
    }
}
