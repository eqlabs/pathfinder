use std::collections::{BinaryHeap, VecDeque};

use malachite_consensus::{
    process,
    Effect,
    Error,
    Input,
    LocallyProposedValue,
    Params,
    Resumable,
    Resume,
    SignedConsensusMsg,
    State as ConsensusState,
};
use malachite_signing_ed25519::Signature;
use malachite_types::{SignedMessage, Timeout, ValidatorSet as _, VoteType};
use tokio::time::Instant;

use crate::config::TimeoutValues;
use crate::malachite::MalachiteContext;
use crate::wal::WalSink;
use crate::{ConsensusCommand, ConsensusEvent, SignedVote, ValidatorSet};

/// The [InternalConsensus] acts as a driver for the Malachite core and allows
/// us to decouple all the Malachite intrinsics from our public interface.
///
/// We spawn a new instance of this entity for each height, as we might be
/// involved in multiple consensus processes at the same time.
pub struct InternalConsensus {
    state: ConsensusState<MalachiteContext>,
    metrics: malachite_metrics::Metrics,
    input_queue: VecDeque<ConsensusCommand>,
    output_queue: VecDeque<ConsensusEvent>,
    timeout_manager: TimeoutManager,
    wal: Box<dyn WalSink>,
}

impl InternalConsensus {
    pub fn new(
        params: Params<MalachiteContext>,
        timeout_values: TimeoutValues,
        wal: Box<dyn WalSink>,
    ) -> Self {
        let state = ConsensusState::new(MalachiteContext, params);
        Self {
            state,
            metrics: Default::default(),
            input_queue: VecDeque::new(),
            output_queue: VecDeque::new(),
            timeout_manager: TimeoutManager {
                timeouts: BinaryHeap::new(),
                timeout_values,
            },
            wal,
        }
    }

    pub fn handle_command(&mut self, cmd: ConsensusCommand) {
        self.input_queue.push_back(cmd);
    }

    pub async fn poll_internal(&mut self) -> Option<ConsensusEvent> {
        // Process any timeouts that are due.
        let now = Instant::now();
        while let Some(next) = self.timeout_manager.timeouts.peek() {
            if now < next.due {
                break;
            }
            let ScheduledTimeout { timeout, .. } = self
                .timeout_manager
                .timeouts
                .pop()
                .expect("No timeout to pop");
            let input = Input::TimeoutElapsed(timeout);
            tracing::debug!(
                validator = %self.state.address(),
                timeout = ?timeout,
                "Timeout elapsed"
            );
            if let Err(e) = self.process_input(input) {
                self.output_queue.push_back(ConsensusEvent::Error(e.into()));
            }
        }

        // Process any commands that are waiting in the input queue.
        if let Some(cmd) = self.input_queue.pop_front() {
            let input = match cmd {
                ConsensusCommand::Vote(vote) => {
                    tracing::debug!(
                        validator = %self.state.address(),
                        vote_type = ?vote.vote.r#type,
                        from = %vote.vote.validator_address,
                        height = %vote.vote.height,
                        round = %vote.vote.round,
                        "Received vote"
                    );
                    Input::Vote(convert_vote(vote))
                }
                ConsensusCommand::Proposal(proposal) => {
                    tracing::debug!(
                        validator = %self.state.address(),
                        value_id = ?proposal.proposal.value_id,
                        from = %proposal.proposal.proposer,
                        height = %proposal.proposal.height,
                        round = %proposal.proposal.round,
                        "Received proposal"
                    );
                    let signed_msg =
                        malachite_types::SignedProposal::new(proposal.proposal, proposal.signature);
                    Input::Proposal(signed_msg)
                }
                ConsensusCommand::Propose(proposal) => {
                    tracing::debug!(
                        validator = %self.state.address(),
                        value_id = ?proposal.value_id,
                        height = %proposal.height,
                        round = %proposal.round,
                        "Proposing value"
                    );
                    Input::Propose(LocallyProposedValue::new(
                        proposal.height,
                        proposal.round.into_inner(),
                        proposal.value_id,
                    ))
                }
                ConsensusCommand::StartHeight(height, validators) => {
                    tracing::info!(
                        validator = %self.state.address(),
                        height = %height,
                        validator_count = validators.count(),
                        "Starting new height"
                    );
                    Input::StartHeight(height, validators)
                }
            };

            if let Err(e) = self.process_input(input) {
                self.output_queue.push_back(ConsensusEvent::Error(e.into()));
            }
        }

        self.output_queue.pop_front()
    }

    #[allow(clippy::result_large_err)]
    fn process_input(
        &mut self,
        input: Input<MalachiteContext>,
    ) -> Result<(), Error<MalachiteContext>> {
        let output = &mut self.output_queue;
        let validator_set = self.state.validator_set().clone();

        process!(
            input: input,
            state: &mut self.state,
            metrics: &mut self.metrics,
            with: effect => handle_effect(effect, &validator_set, &mut self.timeout_manager, &mut self.wal, output)
        )
    }
}

#[allow(clippy::result_large_err)]
fn handle_effect(
    effect: Effect<MalachiteContext>,
    validator_set: &ValidatorSet,
    timeout_manager: &mut TimeoutManager,
    wal: &mut Box<dyn WalSink>,
    output_queue: &mut VecDeque<ConsensusEvent>,
) -> Result<Resume<MalachiteContext>, Error<MalachiteContext>> {
    match effect {
        // Start a new round.
        Effect::StartRound(height, round, address, resume) => {
            tracing::debug!(
                height = %height,
                round = %round,
                address = %address,
                "Starting new round"
            );
            Ok(resume.resume_with(()))
        }
        // Get the validator set at a given height.
        Effect::GetValidatorSet(height, resume) => {
            tracing::debug!(
                height = %height,
                "Getting validator set"
            );
            Ok(resume.resume_with(Some(validator_set.clone())))
        }
        // Publish a message to peers.
        Effect::Publish(msg, resume) => {
            match &msg {
                SignedConsensusMsg::Proposal(proposal) => {
                    tracing::debug!(
                        proposer = %proposal.message.proposer,
                        "Publishing proposal"
                    );
                }
                SignedConsensusMsg::Vote(vote) => {
                    tracing::debug!(
                        validator = %vote.message.validator_address,
                        vote_type = ?vote.message.r#type,
                        "Publishing vote"
                    );
                }
            }
            let event = convert_publish(msg);
            output_queue.push_back(event);
            Ok(resume.resume_with(()))
        }
        // Request the application to build a value for consensus to run on.
        Effect::GetValue(height, round, timeout, resume) => {
            tracing::debug!(
                height = %height,
                round = %round,
                "Requesting value"
            );
            output_queue.push_back(ConsensusEvent::RequestProposal {
                height,
                round: round.into(),
                timeout,
            });
            Ok(resume.resume_with(()))
        }
        // Notifies the application that consensus has decided on a value.
        Effect::Decide(cert, _, resume) => {
            tracing::info!(
                height = %cert.height,
                hash = ?cert.value_id.clone().into_inner(),
                "Consensus decided on value"
            );
            output_queue.push_back(ConsensusEvent::Decision {
                height: cert.height,
                hash: cert.value_id.into_inner(),
            });
            Ok(resume.resume_with(()))
        }
        // Sign a vote.
        Effect::SignVote(vote, resume) => {
            tracing::debug!(
                vote_type = ?vote.r#type,
                "Signing vote"
            );
            if vote.r#type == VoteType::Precommit {
                tracing::debug!(
                    vote = ?vote,
                    "Transitioning to Precommit step"
                );
            }
            Ok(resume.resume_with(SignedMessage::new(vote, Signature::from_bytes([0; 64]))))
        }
        // Sign a proposal.
        Effect::SignProposal(proposal, resume) => {
            tracing::debug!(
                proposal = ?proposal,
                "Signing proposal"
            );
            Ok(resume.resume_with(SignedMessage::new(proposal, Signature::from_bytes([0; 64]))))
        }
        // Verify a signature.
        Effect::VerifySignature(msg, pk, resume) => {
            tracing::debug!(
                msg = ?msg,
                pk = ?pk,
                "Verifying signature"
            );
            Ok(resume.resume_with(true)) // Replace with real verification later
        }
        // Verify a commit certificate.
        Effect::VerifyCommitCertificate(cert, _validators, _params, resume) => {
            tracing::debug!(
                cert = ?cert,
                "Verifying commit certificate"
            );
            Ok(resume.resume_with(Ok(())))
        }
        // Verify a polka certificate.
        Effect::VerifyPolkaCertificate(cert, _validators, _params, resume) => {
            tracing::debug!(
                cert = ?cert,
                "Verifying polka certificate"
            );
            Ok(resume.resume_with(Ok(())))
        }
        // Extend a vote.
        Effect::ExtendVote(height, round, value_id, resume) => {
            tracing::debug!(
                height = %height,
                round = %round,
                value_id = ?value_id,
                "Extending vote"
            );
            Ok(resume.resume_with(None))
        }
        // Verify a vote extension.
        Effect::VerifyVoteExtension(
            height,
            round,
            value_id,
            _extension,
            _validator_address,
            resume,
        ) => {
            tracing::debug!(
                height = %height,
                round = %round,
                value_id = ?value_id,
                "Verifying vote extension"
            );
            Ok(resume.resume_with(Ok(())))
        }
        Effect::ScheduleTimeout(timeout, resume) => {
            timeout_manager.schedule_timeout(timeout);
            Ok(resume.resume_with(()))
        }
        Effect::CancelTimeout(timeout, resume) => {
            timeout_manager.cancel_timeout(timeout);
            Ok(resume.resume_with(()))
        }
        Effect::CancelAllTimeouts(resume) => {
            timeout_manager.cancel_all_timeouts();
            Ok(resume.resume_with(()))
        }
        Effect::ResetTimeouts(resume) => {
            timeout_manager.reset_timeouts();
            Ok(resume.resume_with(()))
        }
        Effect::WalAppend(msg, resume) => {
            wal.append(msg.into());
            Ok(resume.resume_with(()))
        }
        // Internally handled effects.
        Effect::RequestVoteSet(_, _, resume)
        | Effect::RestreamProposal(_, _, _, _, _, resume)
        | Effect::SendVoteSetResponse(_, _, _, _, _, resume) => Ok(resume.resume_with(())),

        other => {
            tracing::warn!(
                effect = ?other,
                "Unhandled effect (internal-only)"
            );
            Ok(Resume::Continue)
        }
    }
}

fn convert_publish(msg: SignedConsensusMsg<MalachiteContext>) -> ConsensusEvent {
    use crate::NetworkMessage;

    let network_msg = match msg {
        SignedConsensusMsg::Proposal(proposal) => NetworkMessage::Proposal(crate::SignedProposal {
            proposal: proposal.message,
            signature: proposal.signature,
        }),
        SignedConsensusMsg::Vote(vote) => {
            let wire_vote = convert_vote_out(vote);
            NetworkMessage::Vote(wire_vote)
        }
    };

    ConsensusEvent::Gossip(network_msg)
}

fn convert_vote(vote: SignedVote) -> malachite_types::SignedVote<MalachiteContext> {
    malachite_types::SignedVote::new(vote.vote, vote.signature)
}

fn convert_vote_out(vote: malachite_types::SignedVote<MalachiteContext>) -> SignedVote {
    SignedVote {
        vote: vote.message,
        signature: vote.signature,
    }
}

/// A scheduled timeout.
struct ScheduledTimeout {
    timeout: Timeout,
    due: Instant,
}

impl PartialEq for ScheduledTimeout {
    fn eq(&self, other: &Self) -> bool {
        self.timeout == other.timeout && self.due == other.due
    }
}

impl Eq for ScheduledTimeout {}

impl Ord for ScheduledTimeout {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // We want a min-heap, so reverse ordering by due.
        other.due.cmp(&self.due)
    }
}

impl PartialOrd for ScheduledTimeout {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A manager for consensus timeouts.
///
/// Keeps track of all the scheduled timeouts, as well as the timeout values for
/// each timeout kind.
struct TimeoutManager {
    timeouts: BinaryHeap<ScheduledTimeout>,
    timeout_values: TimeoutValues,
}

impl TimeoutManager {
    /// Schedule a new timeout.
    pub fn schedule_timeout(&mut self, timeout: Timeout) {
        let due = Instant::now() + self.timeout_values.get(timeout.kind);
        self.timeouts.push(ScheduledTimeout { timeout, due });

        tracing::debug!(
            timeout = ?timeout,
            due = ?due,
            "Scheduled timeout"
        );
    }

    /// Cancel a timeout.
    pub fn cancel_timeout(&mut self, timeout: Timeout) {
        self.timeouts = self
            .timeouts
            .drain()
            .filter(|st| st.timeout != timeout)
            .collect();

        tracing::debug!(
            timeout = ?timeout,
            "Cancelled timeout"
        );
    }

    /// Cancel all timeouts.
    pub fn cancel_all_timeouts(&mut self) {
        self.timeouts.clear();

        tracing::debug!("Cancelled all timeouts");
    }

    /// Reset all timeouts.
    pub fn reset_timeouts(&mut self) {
        let now = Instant::now();
        let mut reset = BinaryHeap::new();

        // Drain all timeouts and update their due times
        for mut scheduled_timeout in self.timeouts.drain() {
            scheduled_timeout.due = now + self.timeout_values.get(scheduled_timeout.timeout.kind);
            reset.push(scheduled_timeout);
        }

        self.timeouts = reset;

        tracing::debug!("Reset all timeouts");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use malachite_types::{Round, Timeout, TimeoutKind};

    use crate::config::TimeoutValues;
    use crate::internal::TimeoutManager;

    /// Tests basic timeout scheduling and firing behavior.
    /// Verifies that timeouts are scheduled correctly and the shortest timeout
    /// fires first.
    #[tokio::test]
    async fn test_timeout_manager_scheduling() {
        let timeout_values = TimeoutValues {
            propose: Duration::from_millis(100),
            prevote: Duration::from_millis(200),
            precommit: Duration::from_millis(300),
            prevote_time_limit: Duration::from_millis(400),
            precommit_time_limit: Duration::from_millis(500),
            prevote_rebroadcast: Duration::from_millis(600),
            precommit_rebroadcast: Duration::from_millis(700),
        };

        let mut manager = TimeoutManager {
            timeouts: std::collections::BinaryHeap::new(),
            timeout_values,
        };

        // Schedule timeouts with different durations
        let timeout1 = Timeout::new(Round::Some(1), TimeoutKind::Propose);
        let timeout2 = Timeout::new(Round::Some(2), TimeoutKind::Prevote);
        let timeout3 = Timeout::new(Round::Some(3), TimeoutKind::Precommit);

        manager.schedule_timeout(timeout1);
        manager.schedule_timeout(timeout2);
        manager.schedule_timeout(timeout3);

        // Verify all timeouts are scheduled
        assert_eq!(manager.timeouts.len(), 3);

        // Wait for the shortest timeout to fire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Check that the propose timeout (shortest) has fired
        let now = tokio::time::Instant::now();
        if let Some(next) = manager.timeouts.peek() {
            if now >= next.due {
                let scheduled_timeout = manager.timeouts.pop().expect("No timeout to pop");
                assert_eq!(scheduled_timeout.timeout.kind, TimeoutKind::Propose);
                assert_eq!(scheduled_timeout.timeout.round, Round::Some(1));
            }
        }

        // Verify remaining timeouts
        assert_eq!(manager.timeouts.len(), 2);
    }

    /// Tests timeout cancellation functionality.
    /// Verifies that specific timeouts can be cancelled and all timeouts can be
    /// cleared.
    #[tokio::test]
    async fn test_timeout_manager_cancellation() {
        let timeout_values = TimeoutValues::default();
        let mut manager = TimeoutManager {
            timeouts: std::collections::BinaryHeap::new(),
            timeout_values,
        };

        let timeout1 = Timeout::new(Round::Some(1), TimeoutKind::Propose);
        let timeout2 = Timeout::new(Round::Some(2), TimeoutKind::Prevote);
        let timeout3 = Timeout::new(Round::Some(3), TimeoutKind::Precommit);

        // Schedule timeouts
        manager.schedule_timeout(timeout1);
        manager.schedule_timeout(timeout2);
        manager.schedule_timeout(timeout3);

        assert_eq!(manager.timeouts.len(), 3);

        // Cancel a specific timeout
        manager.cancel_timeout(timeout2);
        assert_eq!(manager.timeouts.len(), 2);

        // Verify the cancelled timeout is not present
        for scheduled_timeout in manager.timeouts.iter() {
            assert_ne!(scheduled_timeout.timeout, timeout2);
        }

        // Cancel all timeouts
        manager.cancel_all_timeouts();
        assert_eq!(manager.timeouts.len(), 0);
    }

    /// Tests timeout reset functionality.
    /// Verifies that all timeouts can be reset with new due times while
    /// preserving their count.
    #[tokio::test]
    async fn test_timeout_manager_reset() {
        let timeout_values = TimeoutValues {
            propose: Duration::from_millis(100),
            prevote: Duration::from_millis(200),
            precommit: Duration::from_millis(300),
            prevote_time_limit: Duration::from_millis(400),
            precommit_time_limit: Duration::from_millis(500),
            prevote_rebroadcast: Duration::from_millis(600),
            precommit_rebroadcast: Duration::from_millis(700),
        };

        let mut manager = TimeoutManager {
            timeouts: std::collections::BinaryHeap::new(),
            timeout_values,
        };

        let timeout1 = Timeout::new(Round::Some(1), TimeoutKind::Propose);
        let timeout2 = Timeout::new(Round::Some(2), TimeoutKind::Prevote);

        // Schedule timeouts
        manager.schedule_timeout(timeout1);
        manager.schedule_timeout(timeout2);

        assert_eq!(manager.timeouts.len(), 2);

        // Wait a bit to ensure time has passed
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Reset timeouts
        manager.reset_timeouts();

        // Verify timeouts are still present but with updated due times
        assert_eq!(manager.timeouts.len(), 2);

        // Verify the due times are in the future
        let now = tokio::time::Instant::now();
        for scheduled_timeout in manager.timeouts.iter() {
            assert!(scheduled_timeout.due > now);
        }
    }

    /// Tests timeout ordering and firing sequence.
    /// Verifies that timeouts fire in the correct order (shortest duration
    /// first) regardless of scheduling order.
    #[tokio::test]
    async fn test_timeout_manager_ordering() {
        let timeout_values = TimeoutValues {
            propose: Duration::from_millis(300),   // Longest
            prevote: Duration::from_millis(100),   // Shortest
            precommit: Duration::from_millis(200), // Medium
            prevote_time_limit: Duration::from_millis(400),
            precommit_time_limit: Duration::from_millis(500),
            prevote_rebroadcast: Duration::from_millis(600),
            precommit_rebroadcast: Duration::from_millis(700),
        };

        let mut manager = TimeoutManager {
            timeouts: std::collections::BinaryHeap::new(),
            timeout_values,
        };

        // Schedule timeouts in reverse order
        let timeout1 = Timeout::new(Round::Some(1), TimeoutKind::Propose); // 300ms
        let timeout2 = Timeout::new(Round::Some(2), TimeoutKind::Prevote); // 100ms
        let timeout3 = Timeout::new(Round::Some(3), TimeoutKind::Precommit); // 200ms

        manager.schedule_timeout(timeout1);
        manager.schedule_timeout(timeout2);
        manager.schedule_timeout(timeout3);

        // First should be prevote (100ms)
        tokio::time::sleep(Duration::from_millis(150)).await;
        if let Some(scheduled_timeout) = manager.timeouts.pop() {
            assert_eq!(scheduled_timeout.timeout.kind, TimeoutKind::Prevote);
            assert_eq!(scheduled_timeout.timeout.round, Round::Some(2));
        }

        // Second should be precommit (200ms)
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(scheduled_timeout) = manager.timeouts.pop() {
            assert_eq!(scheduled_timeout.timeout.kind, TimeoutKind::Precommit);
            assert_eq!(scheduled_timeout.timeout.round, Round::Some(3));
        }

        // Third should be propose (300ms)
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(scheduled_timeout) = manager.timeouts.pop() {
            assert_eq!(scheduled_timeout.timeout.kind, TimeoutKind::Propose);
            assert_eq!(scheduled_timeout.timeout.round, Round::Some(1));
        }

        assert_eq!(manager.timeouts.len(), 0);
    }

    /// Tests edge cases and error conditions.
    /// Verifies behavior with non-existent timeouts, empty states, and
    /// duplicate timeouts.
    #[tokio::test]
    async fn test_timeout_manager_edge_cases() {
        let timeout_values = TimeoutValues::default();
        let mut manager = TimeoutManager {
            timeouts: std::collections::BinaryHeap::new(),
            timeout_values,
        };

        // Test cancelling non-existent timeout
        let non_existent_timeout = Timeout::new(Round::Some(999), TimeoutKind::Propose);
        manager.cancel_timeout(non_existent_timeout);
        assert_eq!(manager.timeouts.len(), 0);

        // Test cancelling all timeouts when empty
        manager.cancel_all_timeouts();
        assert_eq!(manager.timeouts.len(), 0);

        // Test resetting timeouts when empty
        manager.reset_timeouts();
        assert_eq!(manager.timeouts.len(), 0);

        // Test scheduling same timeout multiple times
        let timeout = Timeout::new(Round::Some(1), TimeoutKind::Propose);
        manager.schedule_timeout(timeout);
        manager.schedule_timeout(timeout);
        manager.schedule_timeout(timeout);

        assert_eq!(manager.timeouts.len(), 3);

        // Cancel all instances of this timeout (correct behavior)
        manager.cancel_timeout(timeout);
        assert_eq!(manager.timeouts.len(), 0);

        // Test scheduling different timeouts and cancelling one
        let timeout1 = Timeout::new(Round::Some(1), TimeoutKind::Propose);
        let timeout2 = Timeout::new(Round::Some(2), TimeoutKind::Prevote);

        manager.schedule_timeout(timeout1);
        manager.schedule_timeout(timeout2);

        assert_eq!(manager.timeouts.len(), 2);

        // Cancel one specific timeout
        manager.cancel_timeout(timeout1);
        assert_eq!(manager.timeouts.len(), 1);

        // Verify the remaining timeout is the correct one
        let remaining = manager.timeouts.peek().unwrap();
        assert_eq!(remaining.timeout, timeout2);
    }
}
