use web3::types::H256;

use crate::{contract::STATE_UPDATE_EVENT, log::StateUpdateLog, EthOrigin};

mod forward;

pub use forward::*;

/// Trait used by [LogFetcher].
///
/// Contains metadata for a log such as its point-of-origin on L1 and it's
/// emitting contract and event signature.
///
/// Implemented by [StateUpdateLog]
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
