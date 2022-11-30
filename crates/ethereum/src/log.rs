use crate::EthOrigin;
use pathfinder_common::{GlobalRoot, StarknetBlockNumber};

mod fetch;
mod parse;

pub use fetch::*;

/// Describes a state update log event.
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateUpdateLog {
    pub origin: EthOrigin,
    pub global_root: GlobalRoot,
    pub block_number: StarknetBlockNumber,
}
