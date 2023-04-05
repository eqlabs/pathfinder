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
