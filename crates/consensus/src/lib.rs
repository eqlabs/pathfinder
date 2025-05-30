use std::collections::{HashMap, VecDeque};

use malachite_consensus::{Params, VoteSyncMode};
pub use malachite_types::VoteType;
use malachite_types::{ThresholdParam, ThresholdParams, Timeout, ValuePayload};
use p2p_proto::common::Hash;
use tracing::warn;

use crate::engine::InternalEngine;
// Re-export malachite types needed by the public API
pub use crate::malachite::{
    ConsensusValue,
    Height,
    Proposal,
    Round,
    Validator,
    ValidatorAddress,
    ValidatorSet,
    ValueId,
    Vote,
};

mod engine;
mod malachite;

/// A signature for the malachite context.
pub type Signature = malachite_signing_ed25519::Signature;

/// Pathfinder consensus engine.
pub struct Consensus {
    internal: HashMap<Height, InternalEngine>,
    event_queue: VecDeque<ConsensusEvent>,
    address: ValidatorAddress,
}

impl Consensus {
    /// Create a new consensus engine for the current validator.
    pub fn new(address: ValidatorAddress) -> Self {
        Self {
            internal: HashMap::new(),
            event_queue: VecDeque::new(),
            address,
        }
    }

    /// Feed a command into the consensus engine.
    pub fn handle_command(&mut self, cmd: ConsensusCommand) {
        match cmd {
            // Start a new height.
            ConsensusCommand::StartHeight(height, validator_set) => {
                let params = Params {
                    initial_height: height,
                    initial_validator_set: validator_set.clone(),
                    address: self.address.clone(),
                    //threshold_params: ThresholdParams::default(),
                    threshold_params: ThresholdParams {
                        quorum: ThresholdParam::new(1, 1),
                        honest: ThresholdParam::new(1, 1),
                    },
                    value_payload: ValuePayload::ProposalOnly,
                    vote_sync_mode: VoteSyncMode::Rebroadcast,
                };
                // A new engine is created for every new height.
                let mut engine = InternalEngine::new(params);
                engine.handle_command(ConsensusCommand::StartHeight(height, validator_set));
                self.internal.insert(height, engine);
                tracing::info!(
                    "{}: Started consensus engine for height {}",
                    self.address,
                    height
                );
            }
            other => {
                let height = other.height();
                if let Some(engine) = self.internal.get_mut(&height) {
                    engine.handle_command(other);
                } else {
                    warn!("Received command for unknown height {}", height);
                }
            }
        }
    }

    /// Poll all engines for an event.
    pub async fn next_event(&mut self) -> Option<ConsensusEvent> {
        let mut finished_heights = Vec::new();
        // Drain each internal engine.
        for (height, engine) in self.internal.iter_mut() {
            if let Some(event) = engine.poll_internal().await {
                tracing::info!(
                    "{}: Engine at height {} returned event {:?}",
                    self.address,
                    height,
                    event
                );
                // If the engine has finished, remove it from the map.
                if let ConsensusEvent::Decision { height, .. } = &event {
                    finished_heights.push(height.clone());
                }
                // Push the event to the queue.
                self.event_queue.push_back(event);
            }
        }
        // Remove finished engines.
        for height in finished_heights {
            self.internal.remove(&height);
        }
        // Return the first event from the queue.
        self.event_queue.pop_front()
    }

    #[cfg(test)]
    pub fn drain_events(&mut self) -> Vec<ConsensusEvent> {
        std::mem::take(&mut self.event_queue).into()
    }
}

/// A fully validated, signed proposal ready to enter consensus.
#[derive(Debug, Clone)]
pub struct SignedProposal {
    pub proposal: Proposal,
    pub signature: Signature,
}

/// Vote type.
#[derive(Debug, Clone)]
pub struct SignedVote {
    pub vote: Vote,
    pub signature: Signature,
}

/// Commands that the application can send into the consensus engine.
#[derive(Debug)]
pub enum ConsensusCommand {
    /// Start consensus at a given height with the validator set.
    StartHeight(Height, ValidatorSet),
    /// A complete, locally validated and signed proposal that we create as the
    /// proposer for the current round.
    Propose(Proposal),
    /// A complete, locally validated and signed proposal that was received over
    /// the network from another validator.
    Proposal(SignedProposal),
    /// A signed vote received from the network.
    Vote(SignedVote),
}

impl ConsensusCommand {
    /// Get the consensus height associated with the command.
    pub fn height(&self) -> Height {
        match self {
            ConsensusCommand::StartHeight(height, _) => *height,
            ConsensusCommand::Propose(proposal) => proposal.height,
            ConsensusCommand::Proposal(proposal) => proposal.proposal.height,
            ConsensusCommand::Vote(vote) => vote.vote.height,
        }
    }
}
/// A message to be gossiped to peers.
#[derive(Clone, Debug)]
pub enum NetworkMessage {
    /// A complete, locally validated and signed proposal ready to be gossiped.
    Proposal(SignedProposal),
    /// A vote received from the network.
    Vote(SignedVote),
}

/// Events that the consensus engine emits for the application to handle.
#[derive(Debug)]
pub enum ConsensusEvent {
    /// The consensus wants this message to be gossiped to peers.
    Gossip(NetworkMessage),
    /// The consensus needs the app to build and inject a proposal.
    RequestProposal {
        height: Height,
        round: Round,
        timeout: Timeout,
    },
    /// The consensus has reached a decision and committed a block.
    Decision { height: Height, hash: Hash },
    /// An internal error occurred in consensus.
    Error(anyhow::Error),
}
