use web3::types::H256;

use crate::{contract::STATE_UPDATE_EVENT, log::StateUpdateLog, EthOrigin};

mod forward;

pub use forward::*;

/// May contain one of two types of [MetaLog].
///
/// Used by [BackwardLogFetcher].
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EitherMetaLog<L, R>
where
    L: MetaLog + PartialEq + std::fmt::Debug + Clone,
    R: MetaLog + PartialEq + std::fmt::Debug + Clone,
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
    fn signature() -> H256;

    fn origin(&self) -> &EthOrigin;
}

impl MetaLog for StateUpdateLog {
    fn signature() -> H256 {
        STATE_UPDATE_EVENT.signature()
    }

    fn origin(&self) -> &EthOrigin {
        &self.origin
    }
}
