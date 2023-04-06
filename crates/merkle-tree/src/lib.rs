pub mod contract_state;
pub mod merkle_node;
pub mod merkle_tree;

mod class;
mod contract;
mod hash;
mod storage;
mod transaction;

use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use stark_hash::Felt;

pub use class::ClassCommitmentTree;
pub use contract::{ContractsStateTree, StorageCommitmentTree};
pub use hash::{Hash, PedersenHash, PoseidonHash};
pub use storage::Storage;
pub use transaction::TransactionTree;

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Binary { left: Felt, right: Felt },
    Edge { child: Felt, path: BitVec<Msb0, u8> },
}

impl Node {
    pub fn hash<H: Hash>(&self) -> Felt {
        match self {
            Node::Binary { left, right } => H::hash(*left, *right),
            Node::Edge { child, path } => {
                let mut length = [0; 32];
                // // Safe as len() is guaranteed to be <= 251
                length[31] = path.len() as u8;
                let path = Felt::from_bits(&path).unwrap();

                let length = Felt::from_be_bytes(length).unwrap();
                H::hash(*child, path) + length
            }
        }
    }
}
