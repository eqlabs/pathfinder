//! Consensus behaviour and other related utilities for the consensus p2p
//! network.
mod behaviour;
mod types;

use std::{collections::{HashMap, HashSet}, fmt::Display};

pub use behaviour::Behaviour;

use p2p_proto::consensus::{Vote, ProposalPart};

/// Commands for the consensus behaviour.
#[derive(Debug, Clone)]
pub enum Command {
    /// Broadcast a vote to the network.
    BroadcastVote(Vote),
    /// Broadcast a chunk of a proposal to the network.
    BroadcastProposalPart {
        height: u64,
        round: u32,
        part: ProposalPart,
    },
    /// Start gossiping consensus for a new height.
    StartHeight {
        height: u64,
        validators: ValidatorSet,
    },
}

/// Events emitted by the consensus behaviour.
pub enum Event {
    /// A vote (prevote or precommit) received from another validator.
    ReceivedVote(Vote),
    /// A proposal part (e.g., Init, Transactions, BlockInfo, Fin) received from the network.
    ReceivedProposalPart {
        height: u64,
        round: u32,
        part: ProposalPart,
    },
}

/// State of the consensus behaviour.
pub struct State {

    /// The minimum height available in the node's local history.
    pub min_height: u64,

    /// The current height and round of consensus.
    pub current_height: u64,
    pub current_round: u32,

    /// The current validator set.
    pub validator_set: HashSet<ContractAddress>,

    /// A map of height -> ProposalParts (for tracking parts of a proposal).
    pub proposals: HashMap<u64, Vec<ProposalPart>>,

    /// A map of height -> round -> votes cast (Prevote, Precommit, etc.)
    pub votes: HashMap<u64, HashMap<u32, Vote>>,

    /// The set of finalized (decided) blocks, identified by height and round.
    pub decided_blocks: HashSet<(u64, u32)>,

    /// The set of already received proposal parts to avoid reprocessing.
    pub received_proposals: HashSet<(u64, u32, ProposalPart)>,

}

/// Configuration for the consensus P2P network.
pub struct Config {}


/// ------ Malachite Context ------




use malachite::app::types::core::Context;
use types::{BlockNumber, Proposal, ValidatorAddress};

/// The malachite context for the consensus logic.
#[derive(Debug, Clone, Eq, PartialEq)]
struct ConsensusContext;

impl Context for ConsensusContext {

    type Address = ValidatorAddress;
    type Height = BlockNumber;
    type ProposalPart;
    
    type Proposal = Proposal<Self>;

    type Validator;
    type ValidatorSet;
    
    type Value;
    
    type Vote;
    
    type Extension;
    
    type SigningScheme;
    
    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: informalsystems_malachitebft_app_channel::app::types::core::Round,
    ) -> &'a Self::Validator {
        todo!()
    }
    
    fn new_proposal(
        &self,
        height: Self::Height,
        round: informalsystems_malachitebft_app_channel::app::types::core::Round,
        value: Self::Value,
        pol_round: informalsystems_malachitebft_app_channel::app::types::core::Round,
        address: Self::Address,
    ) -> Self::Proposal {
        todo!()
    }
    
    fn new_prevote(
        &self,
        height: Self::Height,
        round: informalsystems_malachitebft_app_channel::app::types::core::Round,
        value_id: informalsystems_malachitebft_app_channel::app::types::core::NilOrVal<informalsystems_malachitebft_app_channel::app::types::core::ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        todo!()
    }
    
    fn new_precommit(
        &self,
        height: Self::Height,
        round: informalsystems_malachitebft_app_channel::app::types::core::Round,
        value_id: informalsystems_malachitebft_app_channel::app::types::core::NilOrVal<informalsystems_malachitebft_app_channel::app::types::core::ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        todo!()
    }
}
