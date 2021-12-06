mod fetch;
mod parse;

pub use fetch::*;

use web3::{
    types::{Filter, H256, U256},
    Transport, Web3,
};

use crate::ethereum::{EthOrigin, RpcErrorCode};

/// Describes a state update log event. Is always emitted
/// as a pair with [StateTransitionFactLog].
///
/// This is emitted by the Starknet core contract.
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdateLog {
    pub origin: EthOrigin,
    pub global_root: U256,
    pub sequence_number: U256,
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

/// Error return by [get_logs].
#[derive(Debug)]
enum GetLogsError {
    /// Query exceeded limits (time or result length).
    ///
    /// In particular, this can occur when connecting to an
    /// Infura endpoint.
    QueryLimit,
    Other(anyhow::Error),
}

/// Wraps the Ethereum get_logs call to handle [GetLogsError::QueryLimit] situations.
async fn get_logs<T: Transport>(
    transport: &Web3<T>,
    filter: Filter,
) -> Result<Vec<web3::types::Log>, GetLogsError> {
    match transport.eth().logs(filter).await {
        Ok(logs) => Ok(logs),
        Err(web3::Error::Rpc(err)) if err.code.code() == RpcErrorCode::LimitExceeded.code() => {
            Err(GetLogsError::QueryLimit)
        }
        Err(other) => Err(GetLogsError::Other(anyhow::anyhow!(
            "Error getting logs: {:?}",
            other
        ))),
    }
}
