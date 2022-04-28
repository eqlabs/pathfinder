mod fetch;
mod parse;

pub use fetch::*;

use web3::types::H256;

use crate::{
    core::{GlobalRoot, StarknetBlockNumber},
    ethereum::EthOrigin,
};

/// Describes a state update log event. Is always emitted
/// as a pair with [StateTransitionFactLog].
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdateLog {
    pub origin: EthOrigin,
    pub global_root: GlobalRoot,
    pub block_number: StarknetBlockNumber,
}

/// Links a [StateUpdateLog] event to its data -- which is contained
/// by a [MemoryPagesHashesLog] fact log.
///
/// Is always emitted as a pair with [StateUpdateLog].
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Clone, PartialEq)]
pub struct StateTransitionFactLog {
    pub origin: EthOrigin,
    pub fact_hash: H256,
}

/// Links together multiple [memory page logs](MemoryPageFactContinuousLog) into
/// a single fact. The memory pages can then be interpretted as [state update data](crate::ethereum::state_update::StateUpdate).
///
/// This is emitted by the GPS contract.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryPagesHashesLog {
    pub origin: EthOrigin,
    pub hash: H256,
    pub mempage_hashes: Vec<H256>,
}

/// A memory page log event. The data of this memory page is contained
/// in the transaction's input data.
///
/// This is emitted by the memory page contract.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct MemoryPageFactContinuousLog {
    pub origin: EthOrigin,
    pub hash: H256,
}
