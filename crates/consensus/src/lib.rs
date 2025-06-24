use std::collections::{HashMap, VecDeque};

use malachite_consensus::{Params, VoteSyncMode};
pub use malachite_types::VoteType;
use malachite_types::{Timeout, ValuePayload};
use p2p_proto::common::Hash;
use serde::{Deserialize, Serialize};

pub use crate::config::Config;
use crate::internal::InternalConsensus;
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
use crate::wal::{FileWalSink, NoopWal, WalSink};

mod config;
mod internal;
mod malachite;
mod wal;

/// A signature for the malachite context.
pub type Signature = malachite_signing_ed25519::Signature;

/// Pathfinder consensus engine.
pub struct Consensus {
    internal: HashMap<Height, InternalConsensus>,
    event_queue: VecDeque<ConsensusEvent>,
    config: Config,
    min_kept_height: Option<Height>,
}

impl Consensus {
    /// Create a new consensus engine for the current validator.
    pub fn new(config: Config) -> Self {
        Self {
            internal: HashMap::new(),
            event_queue: VecDeque::new(),
            config,
            min_kept_height: None,
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
                    address: self.config.address,
                    threshold_params: self.config.threshold_params,
                    value_payload: ValuePayload::ProposalOnly,
                    vote_sync_mode: self.config.vote_sync_mode,
                };

                // Create a WAL for the height. If we fail, use a NoopWal.
                let wal = match FileWalSink::new(&self.config.address, &height) {
                    Ok(wal) => Box::new(wal) as Box<dyn WalSink>,
                    Err(e) => {
                        tracing::error!(
                            validator = %self.config.address,
                            height = %height,
                            error = %e,
                            "Failed to create wal for height"
                        );
                        Box::new(NoopWal)
                    }
                };

                // A new consensus is created for every new height.
                let mut consensus =
                    InternalConsensus::new(params, self.config.timeout_values.clone(), wal);
                consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
                self.internal.insert(height, consensus);
                tracing::debug!(
                    validator = %self.config.address,
                    height = %height,
                    "Started new consensus"
                );
            }
            other => {
                let height = other.height();
                if let Some(engine) = self.internal.get_mut(&height) {
                    engine.handle_command(other);
                } else {
                    tracing::warn!(
                        validator = %self.config.address,
                        height = %height,
                        command = ?other,
                        "Received command for unknown height"
                    );
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
                tracing::trace!(
                    validator = %self.config.address,
                    height = %height,
                    event = ?event,
                    "Engine returned event"
                );
                // Track finished heights.
                if let ConsensusEvent::Decision { height, .. } = &event {
                    finished_heights.push(*height);
                }
                // Push the event to the queue.
                self.event_queue.push_back(event);
            }
        }

        // Prune old engines if we have any finished heights.
        if !finished_heights.is_empty() {
            self.prune_old_engines();
        }

        // Return the first event from the queue.
        self.event_queue.pop_front()
    }

    /// Prune old engines from the internal map.
    fn prune_old_engines(&mut self) {
        use malachite_types::Height;
        let max_height = self.internal.keys().max().copied();
        if let Some(max_height) = max_height {
            let new_min_height = max_height.decrement_by(self.config.history_depth);

            if let Some(new_min) = new_min_height {
                self.min_kept_height = Some(new_min);
                self.internal.retain(|height, _| *height >= new_min);

                tracing::debug!(
                    validator = %self.config.address,
                    min_height = %new_min,
                    max_height = %max_height,
                    "Pruned old consensus engines"
                );
            }
        }
    }

    #[cfg(test)]
    pub fn drain_events(&mut self) -> Vec<ConsensusEvent> {
        std::mem::take(&mut self.event_queue).into()
    }
}

/// A fully validated, signed proposal ready to enter consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProposal {
    pub proposal: Proposal,
    pub signature: Signature,
}

/// A signed vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
