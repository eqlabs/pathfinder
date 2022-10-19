//! Contains simplified types for parsing JSON-RPC responses.
//!
//! In order not to depend on pathfinder_lib these types "duplicate" similar functionality
//! already found in pathfinder. However, these types are simplified and are missing fields
//! that are irrelevant for load tests.
//!
use stark_hash::StarkHash;

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct Block {
    pub block_hash: StarkHash,
    pub parent_hash: StarkHash,
    pub block_number: u64,
    pub new_root: StarkHash,
    pub timestamp: u64,
    pub sequencer_address: StarkHash,
    pub transactions: Vec<StarkHash>,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub r#type: String,
    pub transaction_hash: StarkHash,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub r#type: String,
    pub transaction_hash: StarkHash,
}
