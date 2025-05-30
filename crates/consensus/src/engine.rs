// src/consensus/engine.rs

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
use malachite_types::SignedMessage;
use tracing::{debug, info};

use crate::malachite::MyContext;
use crate::{ConsensusCommand, ConsensusEvent, SignedVote, ValidatorSet};

pub struct InternalEngine {
    state: ConsensusState<MyContext>,
    input_queue: VecDeque<ConsensusCommand>,
    output_queue: VecDeque<ConsensusEvent>,
}

impl InternalEngine {
    pub fn new(params: Params<MyContext>) -> Self {
        let state = ConsensusState::new(MyContext, params);
        Self {
            state,
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
                ConsensusCommand::Vote(vote) => Input::Vote(convert_vote(vote)),
                ConsensusCommand::Proposal(proposal) => {
                    info!(
                        "{}: Received proposal {:?} from {:?} at height {:?} and round {:?}",
                        self.state.address(),
                        proposal.proposal.value_id,
                        proposal.proposal.proposer,
                        proposal.proposal.height,
                        proposal.proposal.round
                    );
                    let signed_msg =
                        malachite_types::SignedProposal::new(proposal.proposal, proposal.signature);
                    Input::Proposal(signed_msg)
                }
                ConsensusCommand::Propose(proposal) => {
                    info!(
                        "{}: Proposing value {:?} at height {:?} and round {:?}",
                        self.state.address(),
                        proposal.value_id,
                        proposal.height,
                        proposal.round
                    );
                    Input::Propose(LocallyProposedValue::new(
                        proposal.height,
                        proposal.round,
                        proposal.value_id,
                    ))
                }
                ConsensusCommand::StartHeight(height, validators) => {
                    info!(
                        "{}: Starting height {:?} with validator set {:?}",
                        self.state.address(),
                        height,
                        validators
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

    fn process_input(&mut self, input: Input<MyContext>) -> Result<(), Error<MyContext>> {
        let metrics = Default::default();
        let output = &mut self.output_queue;
        let validator_set = self.state.validator_set().clone();

        process!(
            input: input,
            state: &mut self.state,
            metrics: &metrics,
            with: effect => handle_effect(effect, &validator_set, output)
        )
    }
}

fn handle_effect(
    effect: Effect<MyContext>,
    validator_set: &ValidatorSet,
    output_queue: &mut VecDeque<ConsensusEvent>,
) -> Result<Resume<MyContext>, Error<MyContext>> {
    match effect {
        // Start a new round
        Effect::StartRound(height, round, address, resume) => {
            debug!(
                "✨ Starting round {:?} at height {:?} with address {:?}",
                round, height, address
            );
            Ok(resume.resume_with(()))
        }
        // Get the validator set at a given height
        Effect::GetValidatorSet(height, resume) => {
            debug!("✨ Getting validator set at height {:?}", height);
            Ok(resume.resume_with(Some(validator_set.clone())))
        }
        // Publish a message to peers
        Effect::Publish(msg, resume) => {
            match &msg {
                SignedConsensusMsg::Proposal(proposal) => {
                    debug!(
                        "✨ {:?} is publishing a proposal",
                        &proposal.message.proposer
                    );
                }
                SignedConsensusMsg::Vote(vote) => {
                    debug!(
                        "✨ {:?} is publishing a vote",
                        &vote.message.validator_address
                    );
                }
            }
            let event = convert_publish(msg);
            output_queue.push_back(event);
            Ok(resume.resume_with(()))
        }
        // Request the application to build a value for consensus to run on.
        Effect::GetValue(height, round, timeout, resume) => {
            debug!(
                "✨ Requesting value at height {:?} and round {:?}",
                height, round
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
            debug!(
                "✨ Validator decided on hash {:?} at height {:?}",
                cert.value_id.clone().into_inner(),
                cert.height
            );
            output_queue.push_back(ConsensusEvent::Decision {
                height: cert.height,
                hash: cert.value_id.into_inner(),
            });
            Ok(resume.resume_with(()))
        }

        Effect::VerifySignature(_msg, _pk, resume) => {
            Ok(resume.resume_with(true)) // TODO: Implement signature
                                         // verification
        }

        Effect::VerifyCommitCertificate(_cert, _validators, _params, resume) => {
            Ok(resume.resume_with(Ok(())))
        }

        Effect::VerifyPolkaCertificate(_cert, _validators, _params, resume) => {
            Ok(resume.resume_with(Ok(())))
        }

        Effect::SignVote(vote, resume) => {
            Ok(resume.resume_with(SignedMessage::new(vote, Signature::from_bytes([0; 64]))))
        }

        Effect::SignProposal(proposal, resume) => {
            Ok(resume.resume_with(SignedMessage::new(proposal, Signature::from_bytes([0; 64]))))
        }

        Effect::ResetTimeouts(resume) => {
            debug!("✨ Resetting timeouts");
            Ok(resume.resume_with(()))
        }

        // Internally handled effects
        Effect::ScheduleTimeout(_, resume)
        | Effect::CancelTimeout(_, resume)
        | Effect::CancelAllTimeouts(resume)
        | Effect::RequestVoteSet(_, _, resume)
        | Effect::RestreamProposal(_, _, _, _, _, resume)
        | Effect::SendVoteSetResponse(_, _, _, _, _, resume) => Ok(resume.resume_with(())),

        // Skipped: SignVote, SignProposal, Verify*, ExtendVote
        // because signing and verification are handled internally
        _other => {
            // Log and skip anything else for now
            //tracing::warn!("Unhandled effect (internal-only): {other:?}");
            Ok(Resume::Continue)
        }
    }
}

fn convert_publish(msg: SignedConsensusMsg<MyContext>) -> ConsensusEvent {
    use crate::NetworkMessage;

    let network_msg = match msg {
        SignedConsensusMsg::Proposal(proposal) => {
            // We're publishing a proposal *we* created, so we know it's valid.
            NetworkMessage::Proposal(crate::SignedProposal {
                proposal: proposal.message,
                signature: proposal.signature,
            })
        }
        SignedConsensusMsg::Vote(vote) => {
            // Convert internal vote → p2p-compatible vote format
            // This assumes you’ve implemented this somewhere
            let wire_vote = convert_vote_out(vote);
            NetworkMessage::Vote(wire_vote)
        }
    };

    ConsensusEvent::Gossip(network_msg)
}

fn convert_vote(vote: SignedVote) -> malachite_types::SignedVote<MyContext> {
    let my_vote = crate::malachite::Vote::from(vote.vote);
    malachite_types::SignedVote::new(my_vote, vote.signature)
}

fn convert_vote_out(vote: malachite_types::SignedVote<MyContext>) -> SignedVote {
    SignedVote {
        vote: vote.message.into(),
        signature: vote.signature,
    }
}
