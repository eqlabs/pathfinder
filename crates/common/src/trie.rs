use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use pathfinder_crypto::Felt;

use crate::hash::FeltHash;

/// A node in a Starknet patricia-merkle trie.
///
/// See pathfinders merkle-tree crate for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrieNode {
    Binary { left: Felt, right: Felt },
    Edge { child: Felt, path: BitVec<u8, Msb0> },
}

impl TrieNode {
    pub fn hash<H: FeltHash>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right } => H::hash(*left, *right),
            TrieNode::Edge { child, path } => {
                let mut length = [0; 32];
                // Safe as len() is guaranteed to be <= 251
                length[31] = path.len() as u8;
                let path = Felt::from_bits(path).unwrap();

                let length = Felt::from_be_bytes(length).unwrap();
                H::hash(*child, path) + length
            }
        }
    }
}
