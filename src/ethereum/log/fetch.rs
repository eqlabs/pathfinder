use web3::types::{H160, H256, U256};

use crate::ethereum::{
    contract::{
        CORE_CONTRACT_ADDRESS, GPS_CONTRACT_ADDRESS, MEMORY_PAGE_FACT_CONTINUOUS_EVENT,
        MEMORY_PAGE_HASHES_EVENT, MEMPAGE_CONTRACT_ADDRESS, STATE_TRANSITION_FACT_EVENT,
        STATE_UPDATE_EVENT,
    },
    log::{
        MemoryPageFactContinuousLog, MemoryPagesHashesLog, StateTransitionFactLog, StateUpdateLog,
    },
    EthOrigin,
};

mod backward;
mod forward;

pub use backward::*;
pub use forward::*;

/// May contain one of two types of [MetaLog].
///
/// Used by [BackwardLogFetcher].
#[derive(Debug, PartialEq)]
pub enum EitherMetaLog<L, R>
where
    L: MetaLog + PartialEq,
    R: MetaLog + PartialEq,
{
    Left(L),
    Right(R),
}

/// Trait used by [LogFetcher] and indirectly by [BackwardLogFetcher] (via [EitherMetaLog]).
///
/// Contains metadata for a log such as its point-of-origin on L1 and it's
/// emitting contract and event signature.
///
/// Implemented for the four Starknet log types,
///     - [StateUpdateLog]
///     - [StateTransitionFactLog]
///     - [MemoryPagesHashesLog]
///     - [MemoryPageFactContinuousLog]
pub trait MetaLog: TryFrom<web3::types::Log, Error = anyhow::Error> {
    fn contract_address() -> H160;

    fn signature() -> H256;

    fn origin(&self) -> &EthOrigin;

    fn log_index(&self) -> U256;
}

impl MetaLog for StateUpdateLog {
    fn contract_address() -> H160 {
        *CORE_CONTRACT_ADDRESS
    }

    fn signature() -> H256 {
        STATE_UPDATE_EVENT.signature()
    }

    fn origin(&self) -> &EthOrigin {
        &self.origin
    }

    fn log_index(&self) -> U256 {
        self.log_index
    }
}

impl MetaLog for StateTransitionFactLog {
    fn contract_address() -> web3::types::H160 {
        *CORE_CONTRACT_ADDRESS
    }

    fn signature() -> H256 {
        STATE_TRANSITION_FACT_EVENT.signature()
    }

    fn origin(&self) -> &EthOrigin {
        &self.origin
    }

    fn log_index(&self) -> U256 {
        self.log_index
    }
}

impl MetaLog for MemoryPagesHashesLog {
    fn contract_address() -> web3::types::H160 {
        *GPS_CONTRACT_ADDRESS
    }

    fn signature() -> H256 {
        MEMORY_PAGE_HASHES_EVENT.signature()
    }

    fn origin(&self) -> &EthOrigin {
        &self.origin
    }

    fn log_index(&self) -> U256 {
        self.log_index
    }
}

impl MetaLog for MemoryPageFactContinuousLog {
    fn contract_address() -> web3::types::H160 {
        *MEMPAGE_CONTRACT_ADDRESS
    }

    fn signature() -> H256 {
        MEMORY_PAGE_FACT_CONTINUOUS_EVENT.signature()
    }

    fn origin(&self) -> &EthOrigin {
        &self.origin
    }

    fn log_index(&self) -> U256 {
        self.log_index
    }
}

impl<L, R> TryFrom<web3::types::Log> for EitherMetaLog<L, R>
where
    L: MetaLog + PartialEq,
    R: MetaLog + PartialEq,
{
    type Error = anyhow::Error;

    fn try_from(value: web3::types::Log) -> Result<Self, Self::Error> {
        match value.topics.first() {
            Some(signature) if signature == &L::signature() => Ok(Self::Left(L::try_from(value)?)),
            Some(signature) if signature == &R::signature() => Ok(Self::Right(R::try_from(value)?)),
            Some(signature) => Err(anyhow::anyhow!("Unknown log signature: {}", signature)),
            None => Err(anyhow::anyhow!("Missing log signature")),
        }
    }
}

impl<L, R> EitherMetaLog<L, R>
where
    L: MetaLog + PartialEq,
    R: MetaLog + PartialEq,
{
    fn origin(&self) -> &EthOrigin {
        match self {
            EitherMetaLog::Left(left) => left.origin(),
            EitherMetaLog::Right(right) => right.origin(),
        }
    }

    fn log_index(&self) -> U256 {
        match self {
            EitherMetaLog::Left(left) => left.log_index(),
            EitherMetaLog::Right(right) => right.log_index(),
        }
    }
}