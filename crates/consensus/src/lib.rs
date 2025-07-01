use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

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

    /// Recover all heights from the write-ahead log.
    pub fn recover<P: ValidatorSetProvider + 'static>(
        config: Config,
        validator_sets: Arc<P>,
    ) -> Self {
        use crate::wal::recovery;

        tracing::info!(
            validator = %config.address,
            wal_dir = %config.wal_dir.display(),
            "Starting consensus recovery from WAL"
        );

        // Read the write-ahead log and recover all incomplete heights.
        let incomplete_heights = match recovery::recover_incomplete_heights(&config.wal_dir) {
            Ok(heights) => {
                tracing::info!(
                    validator = %config.address,
                    incomplete_heights = heights.len(),
                    "Found incomplete heights to recover"
                );
                heights
            }
            Err(e) => {
                tracing::error!(
                    validator = %config.address,
                    wal_dir = %config.wal_dir.display(),
                    error = %e,
                    "Failed to recover incomplete heights from WAL"
                );
                Vec::new()
            }
        };

        // Create a new consensus engine.
        let mut consensus = Self::new(config);

        // Manually recover all incomplete heights.
        for (height, entries) in incomplete_heights {
            tracing::info!(
                validator = %consensus.config.address,
                height = %height,
                entry_count = entries.len(),
                "Recovering height from WAL"
            );

            let validator_set = validator_sets.get_validator_set(&height);
            let mut internal_consensus = consensus.create_consensus(height, &validator_set);
            internal_consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
            internal_consensus.recover_from_wal(entries);
            consensus.internal.insert(height, internal_consensus);
        }

        tracing::info!(
            validator = %consensus.config.address,
            recovered_heights = consensus.internal.len(),
            "Completed consensus recovery"
        );

        consensus
    }

    fn create_consensus(
        &mut self,
        height: Height,
        validator_set: &ValidatorSet,
    ) -> InternalConsensus {
        let params = Params {
            initial_height: height,
            initial_validator_set: validator_set.clone(),
            address: self.config.address,
            threshold_params: self.config.threshold_params,
            value_payload: ValuePayload::ProposalOnly,
            vote_sync_mode: self.config.vote_sync_mode,
        };

        // Create a WAL for the height. If we fail, use a NoopWal.
        let wal = match FileWalSink::new(&self.config.address, &height, &self.config.wal_dir) {
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
        InternalConsensus::new(params, self.config.timeout_values.clone(), wal)
    }

    /// Feed a command into the consensus engine.
    pub fn handle_command(&mut self, cmd: ConsensusCommand) {
        match cmd {
            // Start a new height.
            ConsensusCommand::StartHeight(height, validator_set) => {
                // A new consensus is created for every new height.
                let mut consensus = self.create_consensus(height, &validator_set);
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

    /// Check if a specific height has been finalized (i.e., a decision has been
    /// reached)
    pub fn is_height_finalized(&self, height: &Height) -> bool {
        if let Some(engine) = self.internal.get(height) {
            engine.is_finalized()
        } else {
            // If the height is not in our internal map, it might have been pruned
            // after being finalized, so we assume it's finalized
            if let Some(min_height) = self.min_kept_height {
                if *height < min_height {
                    return true;
                }
            }
            false
        }
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
    /// Vote set received from the network.
    VoteSet(Height, Round, Vec<SignedVote>),
    /// Request a vote set sync from the network.
    RequestVoteSet(ValidatorAddress, Height, Round),
}

impl ConsensusCommand {
    /// Get the consensus height associated with the command.
    pub fn height(&self) -> Height {
        match self {
            ConsensusCommand::StartHeight(height, _) => *height,
            ConsensusCommand::Propose(proposal) => proposal.height,
            ConsensusCommand::Proposal(proposal) => proposal.proposal.height,
            ConsensusCommand::Vote(vote) => vote.vote.height,
            ConsensusCommand::VoteSet(height, _, _) => *height,
            ConsensusCommand::RequestVoteSet(_, height, _) => *height,
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
    /// A vote set response.
    VoteSetResponse {
        requester: ValidatorAddress,
        height: Height,
        round: Round,
        votes: Vec<SignedVote>,
    },
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
    /// The consensus needs the app to request a vote set sync.
    RequestVoteSet { height: Height, round: Round },
    /// The consensus has reached a decision and committed a block.
    Decision { height: Height, hash: Hash },
    /// An internal error occurred in consensus.
    Error(anyhow::Error),
}

/// A trait for types that can provide a validator set for a given height.
pub trait ValidatorSetProvider: Send + Sync {
    fn get_validator_set(&self, height: &Height) -> ValidatorSet;
}

/// A validator set provider that always returns the same validator set.
pub struct StaticValidatorSetProvider {
    validator_set: ValidatorSet,
}

impl StaticValidatorSetProvider {
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self { validator_set }
    }
}

impl ValidatorSetProvider for StaticValidatorSetProvider {
    fn get_validator_set(&self, _height: &Height) -> ValidatorSet {
        self.validator_set.clone()
    }
}
