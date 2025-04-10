/// Malachite traits
/// 
/// This module is just to keep things tidy when referencing them.
mod mt {
    pub use malachite::app::types::core::{Address, Context, Height, Proposal};
}

/// A block number for the malachite context.
/// 
/// This is a wrapper around the `BlockNumber` type from the `pathfinder_common` crate
/// which implements the `Height` trait for the malachite context.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug, Default)]
pub(crate) struct BlockNumber(pathfinder_common::BlockNumber);

impl mt::Height for BlockNumber {

    const ZERO: Self = Self(pathfinder_common::BlockNumber::GENESIS);

    const INITIAL: Self = Self(pathfinder_common::BlockNumber::GENESIS);

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(Self)
    }

    fn as_u64(&self) -> u64 {
        self.0.get()
    }

    fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    fn decrement(&self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

impl std::fmt::Display for BlockNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


/// A validator address for the malachite context.
/// 
/// This is a wrapper around the `ContractAddress` type from the `pathfinder_common` crate
/// which implements the `Address` trait for the malachite context.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug, Default)]
pub(crate) struct ValidatorAddress(pathfinder_common::ContractAddress);

impl mt::Address for ValidatorAddress {}

impl std::fmt::Display for ValidatorAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A proposal for the malachite context.
/// 
/// This is the value being agreed upon in consensus, corresponding to a block and composed of:
/// - Metadata (height, round, proposer, etc.)
/// - Transactions
/// - Block hash / commitment
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Proposal<C: mt::Context> {
    pub init: ProposalInit,
    pub block_info: ConsensusBlockInfo,
    pub transactions: Vec<ConsensusTransaction>,
    pub fin: ProposalFin,
}

impl<C: mt::Context> mt::Proposal<C> for Proposal<C> {

    fn height(&self) -> C::Height {
        self.init.height
    }
    
    fn round(&self) -> malachite::app::types::core::Round {
        todo!()
    }
    
    fn value(&self) -> &<C as mt::Context>::Value {
        todo!()
    }
    
    fn take_value(self) -> <C as mt::Context>::Value {
        todo!()
    }
    
    fn pol_round(&self) -> malachite::app::types::core::Round {
        todo!()
    }
    
    fn validator_address(&self) -> &<C as mt::Context>::Address {
        todo!()
    }

}
