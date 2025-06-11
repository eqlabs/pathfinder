use std::collections::VecDeque;

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
use malachite_types::{SignedMessage, ValidatorSet as _, VoteType};

use crate::malachite::MalachiteContext;
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
}

impl InternalConsensus {
    pub fn new(params: Params<MalachiteContext>) -> Self {
        let state = ConsensusState::new(MalachiteContext, params);
        Self {
            state,
            metrics: Default::default(),
            input_queue: VecDeque::new(),
            output_queue: VecDeque::new(),
        }
    }

    pub fn handle_command(&mut self, cmd: ConsensusCommand) {
        self.input_queue.push_back(cmd);
    }

    pub async fn poll_internal(&mut self) -> Option<ConsensusEvent> {
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
                        proposal.round,
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
            with: effect => handle_effect(effect, &validator_set, output)
        )
    }
}

#[allow(clippy::result_large_err)]
fn handle_effect(
    effect: Effect<MalachiteContext>,
    validator_set: &ValidatorSet,
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
                round,
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
        // Reset timeouts.
        Effect::ResetTimeouts(resume) => {
            tracing::debug!("Resetting timeouts");
            Ok(resume.resume_with(()))
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
        // Internally handled effects.
        Effect::ScheduleTimeout(_, resume)
        | Effect::CancelTimeout(_, resume)
        | Effect::CancelAllTimeouts(resume)
        | Effect::RequestVoteSet(_, _, resume)
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
