use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Display};
use std::ops::{Add, Sub};
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// Re-export consensus types needed by the public API
pub use crate::config::{Config, TimeoutValues};
use crate::internal::{InternalConsensus, InternalParams};
use crate::wal::{FileWalSink, NoopWal, WalSink};

mod config;
mod internal;
mod wal;

/// A signature for the malachite context.
pub type Signature = malachite_signing_ed25519::Signature;

/// A trait for consensusvalidator addresses.
pub trait ValidatorAddress:
    Sync + Send + Ord + Display + Debug + Default + Clone + Into<Vec<u8>> + Serialize + DeserializeOwned
{
}
impl<T> ValidatorAddress for T where
    T: Sync
        + Send
        + Ord
        + Display
        + Debug
        + Default
        + Clone
        + Into<Vec<u8>>
        + Serialize
        + DeserializeOwned
{
}

/// A trait for consensus value payloads.
pub trait ValuePayload:
    Sync + Send + Ord + Display + Debug + Default + Clone + Serialize + DeserializeOwned
{
}
impl<T> ValuePayload for T where
    T: Sync + Send + Ord + Display + Debug + Default + Clone + Serialize + DeserializeOwned
{
}

/// Pathfinder consensus engine.
pub struct Consensus<V: ValuePayload + 'static, A: ValidatorAddress + 'static> {
    internal: HashMap<u64, InternalConsensus<V, A>>,
    event_queue: VecDeque<ConsensusEvent<V, A>>,
    config: Config<A>,
    min_kept_height: Option<u64>,
}

impl<V: ValuePayload + 'static, A: ValidatorAddress + 'static> Consensus<V, A> {
    /// Create a new consensus engine for the current validator.
    pub fn new(config: Config<A>) -> Self {
        Self {
            internal: HashMap::new(),
            event_queue: VecDeque::new(),
            config,
            min_kept_height: None,
        }
    }

    /// Recover all heights from the write-ahead log.
    pub fn recover<P: ValidatorSetProvider<A> + 'static>(
        config: Config<A>,
        validator_sets: Arc<P>,
    ) -> Self {
        use crate::wal::recovery;

        tracing::info!(
            validator = ?config.address,
            wal_dir = %config.wal_dir.display(),
            "Starting consensus recovery from WAL"
        );

        // Read the write-ahead log and recover all incomplete heights.
        let incomplete_heights = match recovery::recover_incomplete_heights(&config.wal_dir) {
            Ok(heights) => {
                tracing::info!(
                    validator = ?config.address,
                    incomplete_heights = heights.len(),
                    "Found incomplete heights to recover"
                );
                heights
            }
            Err(e) => {
                tracing::error!(
                    validator = ?config.address,
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
                validator = ?consensus.config.address,
                height = %height,
                entry_count = entries.len(),
                "Recovering height from WAL"
            );

            let validator_set = validator_sets.get_validator_set(height);
            let mut internal_consensus = consensus.create_consensus(height, &validator_set);
            internal_consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
            internal_consensus.recover_from_wal(entries);
            consensus.internal.insert(height, internal_consensus);
        }

        tracing::info!(
            validator = ?consensus.config.address,
            recovered_heights = consensus.internal.len(),
            "Completed consensus recovery"
        );

        consensus
    }

    fn create_consensus(
        &mut self,
        height: u64,
        validator_set: &ValidatorSet<A>,
    ) -> InternalConsensus<V, A> {
        let params = InternalParams {
            height,
            validator_set: validator_set.clone(),
            address: self.config.address.clone(),
            threshold_params: self.config.threshold_params,
            value_payload: malachite_types::ValuePayload::ProposalOnly,
        };

        // Create a WAL for the height. If we fail, use a NoopWal.
        let wal = match FileWalSink::new(&self.config.address, height, &self.config.wal_dir) {
            Ok(wal) => Box::new(wal) as Box<dyn WalSink<V, A>>,
            Err(e) => {
                tracing::error!(
                    validator = ?self.config.address,
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
    pub fn handle_command(&mut self, cmd: ConsensusCommand<V, A>) {
        match cmd {
            // Start a new height.
            ConsensusCommand::StartHeight(height, validator_set) => {
                // A new consensus is created for every new height.
                let mut consensus = self.create_consensus(height, &validator_set);
                consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
                self.internal.insert(height, consensus);
                tracing::debug!(
                    validator = ?self.config.address,
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
                        validator = ?self.config.address,
                        height = %height,
                        command = ?other,
                        "Received command for unknown height"
                    );
                }
            }
        }
    }

    /// Poll all engines for an event.
    pub async fn next_event(&mut self) -> Option<ConsensusEvent<V, A>> {
        let mut finished_heights = Vec::new();
        // Drain each internal engine.
        for (height, engine) in self.internal.iter_mut() {
            if let Some(event) = engine.poll_internal().await {
                tracing::trace!(
                    validator = ?self.config.address,
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
        let max_height = self.internal.keys().max().copied();
        if let Some(max_height) = max_height {
            let new_min_height = max_height.checked_sub(self.config.history_depth);

            if let Some(new_min) = new_min_height {
                self.min_kept_height = Some(new_min);
                self.internal.retain(|height, _| *height >= new_min);

                tracing::debug!(
                    validator = ?self.config.address,
                    min_height = %new_min,
                    max_height = %max_height,
                    "Pruned old consensus engines"
                );
            }
        }
    }

    /// Check if a specific height has been finalized (i.e., a decision has been
    /// reached)
    pub fn is_height_finalized(&self, height: u64) -> bool {
        if let Some(engine) = self.internal.get(&height) {
            engine.is_finalized()
        } else {
            // If the height is not in our internal map, it might have been pruned
            // after being finalized, so we assume it's finalized
            if let Some(min_height) = self.min_kept_height {
                if height < min_height {
                    return true;
                }
            }
            false
        }
    }
}

/// A round number (or `None` if the round is nil).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Round(pub Option<u32>);

impl Round {
    pub fn new(round: u32) -> Self {
        Self(Some(round))
    }

    pub fn nil() -> Self {
        Self(None)
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.0
    }
}

impl Add<u32> for Round {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0.map(|round| round + rhs))
    }
}

impl Sub<u32> for Round {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        Self(self.0.map(|round| round - rhs))
    }
}

impl Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(round) => write!(f, "{round}"),
            None => write!(f, "Nil"),
        }
    }
}

impl Debug for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// A proposal for a block value in a consensus round.
///
/// A proposal is created by the designated proposer for a given height and
/// round. It contains the proposed block value along with additional metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal<V, A> {
    pub height: u64,
    pub round: Round,
    pub value: V,
    pub pol_round: Round,
    pub proposer: A,
}

impl<V: Debug, A: Debug> std::fmt::Debug for Proposal<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H:{} R:{} From:{:?} Val:{:?}",
            self.height, self.round, self.proposer, self.value
        )
    }
}

/// The type of vote.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// A vote for a value in a consensus round.
///
/// A vote is cast by a validator to indicate their agreement or disagreement
/// with a proposed block value. The vote includes the validator's address, the
/// round number, and the block value being voted on.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<V, A> {
    pub r#type: VoteType,
    pub height: u64,
    pub round: Round,
    pub value: Option<V>,
    pub validator_address: A,
}

impl<V: Debug, A: Debug> std::fmt::Debug for Vote<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = match &self.value {
            Some(val) => format!("{val:?}"),
            None => "Nil".to_string(),
        };
        write!(
            f,
            "H:{} R:{} {:?} From:{:?} Val:{val}",
            self.height, self.round, self.r#type, self.validator_address
        )
    }
}

/// A fully validated, signed proposal ready to enter consensus.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedProposal<V, A> {
    pub proposal: Proposal<V, A>,
    pub signature: Signature,
}

/// A signed vote.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedVote<V, A> {
    pub vote: Vote<V, A>,
    pub signature: Signature,
}

// Note: We intentionally ignore the signature as it's not used yet.
impl<V: Debug, A: Debug> std::fmt::Debug for SignedProposal<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.proposal)
    }
}

// Note: We intentionally ignore the signature as it's not used yet.
impl<V: Debug, A: Debug> std::fmt::Debug for SignedVote<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.vote)
    }
}

/// A public key for the consensus protocol.
pub type PublicKey = malachite_signing_ed25519::PublicKey;

/// A validator's voting power.
pub type VotingPower = u64;

/// A validator in the consensus protocol.
///
/// Each validator has an associated address and public key to uniquely identify
/// them. The voting power determines their weight in consensus decisions.
#[derive(Clone, PartialEq, Eq)]
pub struct Validator<A> {
    pub address: A,
    pub public_key: PublicKey,
    pub voting_power: VotingPower,
}

impl<A: Debug> std::fmt::Debug for Validator<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({})", self.address, self.voting_power)
    }
}

impl<A> Validator<A> {
    /// Create a new validator with the given address and public key.
    pub fn new(address: A, public_key: PublicKey) -> Self {
        Self {
            address,
            public_key,
            voting_power: 1,
        }
    }

    /// Set the voting power for the validator.
    pub fn with_voting_power(mut self, voting_power: VotingPower) -> Self {
        self.voting_power = voting_power;
        self
    }
}

/// A validator set represents a group of consensus participants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet<A> {
    pub validators: Vec<Validator<A>>, /* > */
}

impl<A> ValidatorSet<A> {
    pub fn new(validators: Vec<Validator<A>>) -> Self {
        Self { validators }
    }

    pub fn count(&self) -> usize {
        self.validators.len()
    }
}

/// Commands that the application can send into the consensus engine.
pub enum ConsensusCommand<V, A> {
    /// Start consensus at a given height with the validator set.
    StartHeight(u64, ValidatorSet<A>),
    /// A complete, locally validated and signed proposal that we create as the
    /// proposer for the current round.
    Propose(Proposal<V, A>),
    /// A complete, locally validated and signed proposal that was received over
    /// the network from another validator.
    Proposal(SignedProposal<V, A>),
    /// A signed vote received from the network.
    Vote(SignedVote<V, A>),
}

impl<V, A> ConsensusCommand<V, A> {
    /// Get the consensus height associated with the command.
    pub fn height(&self) -> u64 {
        match self {
            ConsensusCommand::StartHeight(height, _) => *height,
            ConsensusCommand::Propose(proposal) => proposal.height,
            ConsensusCommand::Proposal(proposal) => proposal.proposal.height,
            ConsensusCommand::Vote(vote) => vote.vote.height,
        }
    }
}

impl<V: Debug, A: Debug> std::fmt::Debug for ConsensusCommand<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusCommand::StartHeight(height, validator_set) => write!(
                f,
                "StartHeight({}, [{}])",
                height,
                validator_set
                    .validators
                    .iter()
                    .map(|v| format!("{:?}", v.address))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ConsensusCommand::Propose(proposal) => write!(f, "Propose({proposal:?})"),
            ConsensusCommand::Proposal(proposal) => write!(f, "Proposal({proposal:?})"),
            ConsensusCommand::Vote(vote) => write!(f, "Vote({vote:?})"),
        }
    }
}

/// A message to be gossiped to peers.
#[derive(Clone, Debug)]
pub enum NetworkMessage<V, A> {
    /// A complete, locally validated and signed proposal ready to be gossiped.
    Proposal(SignedProposal<V, A>),
    /// A vote received from the network.
    Vote(SignedVote<V, A>),
}

/// Events that the consensus engine emits for the application to handle.
pub enum ConsensusEvent<V, A> {
    /// The consensus wants this message to be gossiped to peers.
    Gossip(NetworkMessage<V, A>),
    /// The consensus needs the app to build and inject a proposal.
    RequestProposal { height: u64, round: u32 },
    /// The consensus has reached a decision and committed a block.
    Decision { height: u64, value: V },
    /// An internal error occurred in consensus.
    Error(anyhow::Error),
}

impl<V: Debug, A: Debug> std::fmt::Debug for ConsensusEvent<V, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusEvent::Gossip(msg) => match msg {
                NetworkMessage::Proposal(proposal) => write!(f, "Gossip(Proposal({proposal:?}))"),
                NetworkMessage::Vote(vote) => write!(f, "Gossip(Vote({vote:?}))"),
            },
            ConsensusEvent::RequestProposal { height, round, .. } => {
                write!(f, "RequestProposal(H:{height} R:{round})")
            }
            ConsensusEvent::Decision { height, value } => {
                write!(f, "Decision(H:{height} Val:{value:?})")
            }
            ConsensusEvent::Error(error) => write!(f, "Error({error:?})"),
        }
    }
}

/// A trait for retrieving the validator set at a specific blockchain height.
///
/// This trait allows consensus to dynamically determine the set of validators
/// that are eligible to participate in consensus at any given height.
///
/// This is useful for handling validator set changes across heights.
pub trait ValidatorSetProvider<A>: Send + Sync {
    fn get_validator_set(&self, height: u64) -> ValidatorSet<A>;
}

/// A validator set provider that always returns the same validator set.
pub struct StaticValidatorSetProvider<A> {
    validator_set: ValidatorSet<A>,
}

impl<A> StaticValidatorSetProvider<A> {
    pub fn new(validator_set: ValidatorSet<A>) -> Self {
        Self { validator_set }
    }
}

impl<A: Clone + Send + Sync> ValidatorSetProvider<A> for StaticValidatorSetProvider<A> {
    fn get_validator_set(&self, _height: u64) -> ValidatorSet<A> {
        self.validator_set.clone()
    }
}
