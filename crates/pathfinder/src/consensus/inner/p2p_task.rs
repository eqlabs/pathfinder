use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::Context;
use p2p::consensus::{Client, Event, HeightAndRound};
use p2p::libp2p::gossipsub::PublishError;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{ChainId, ContractAddress};
use pathfinder_consensus::{
    ConsensusCommand,
    NetworkMessage,
    Proposal,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
};
use pathfinder_storage::Storage;
use tokio::sync::mpsc;

use super::{ConsensusTaskEvent, P2PTaskEvent};
use crate::consensus::inner::ConsensusValue;
use crate::validator::ValidatorBlockInfoStage;

pub fn spawn(
    chain_id: ChainId,
    validator_address: ContractAddress,
    p2p_client: Client,
    storage: Storage,
    mut p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    tx_to_consensus: mpsc::Sender<ConsensusTaskEvent>,
    mut rx_from_consensus: mpsc::Receiver<P2PTaskEvent>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    // Cache for proposals that we created and are waiting to be gossiped upon a
    // command from the consensus engine. Once the proposal is gossiped, it is
    // removed from the cache.
    let mut my_proposals_cache = HashMap::new();
    // Cache for proposals that we received from other validators and may need to be
    // proposed by us in another round at the same height. The proposals are removed
    // either when we gossip them or when decision is made at the same height.
    let mut incoming_proposals_cache = BTreeMap::new();

    util::task::spawn(async move {
        loop {
            let p2p_task_event = tokio::select! {
                p2p_event = p2p_event_rx.recv() => {
                    match p2p_event {
                        Some(event) => P2PTaskEvent::P2PEvent(event),
                        None => {
                            tracing::warn!("P2P event receiver was dropped, exiting P2P task");
                            anyhow::bail!("P2P event receiver was dropped, exiting P2P task");
                        }
                    }
                }
                from_consensus = rx_from_consensus.recv() => {
                    from_consensus.expect("Receiver not to be dropped")
                }
            };

            match p2p_task_event {
                P2PTaskEvent::P2PEvent(event) => {
                    tracing::info!("🖧  💌 {validator_address} incoming p2p event: {event:?}");

                    match event {
                        Event::Proposal(height_and_round, proposal_part) => {
                            if let Ok(Some((proposal_commitment, proposer))) =
                                handle_incoming_proposal_part(
                                    chain_id,
                                    height_and_round,
                                    proposal_part,
                                    &mut incoming_proposals_cache,
                                    &storage,
                                )
                            {
                                let proposal = Proposal {
                                    height: height_and_round.height(),
                                    round: height_and_round.round().into(),
                                    value: ConsensusValue(proposal_commitment),
                                    pol_round: Round::nil(),
                                    proposer,
                                };

                                let cmd = ConsensusCommand::Proposal(SignedProposal {
                                    proposal,
                                    signature: Signature::test(),
                                });

                                tx_to_consensus
                                    .send(ConsensusTaskEvent::CommandFromP2P(cmd))
                                    .await
                                    .expect("Receiver not to be dropped");
                            }
                        }
                        Event::Vote(vote) => {
                            let vote = p2p_vote_to_consensus_vote(vote);
                            let cmd = ConsensusCommand::Vote(SignedVote {
                                vote,
                                signature: Signature::test(),
                            });

                            tx_to_consensus
                                .send(ConsensusTaskEvent::CommandFromP2P(cmd))
                                .await
                                .expect("Receiver not to be dropped");
                        }
                    }
                }
                P2PTaskEvent::CacheProposal(height_and_round, proposal_parts) => {
                    let ProposalFin {
                        proposal_commitment,
                    } = proposal_parts
                        .last()
                        .and_then(ProposalPart::as_fin)
                        .expect("Proposals produced by our node are always coherent and complete");

                    tracing::info!(
                        "🖧  🗃️  {validator_address} caching our proposal for {height_and_round}, \
                         hash {proposal_commitment}"
                    );

                    let duplicate_encountered = my_proposals_cache
                        .insert(height_and_round, proposal_parts)
                        .is_some();

                    if duplicate_encountered {
                        tracing::warn!("Duplicate proposal cache request for {height_and_round}!");
                    }
                }
                P2PTaskEvent::RemoveProposal(height) => {
                    tracing::info!(
                        "🖧  🗑️ {validator_address} removing incoming proposals from cache for \
                         height {height} ..."
                    );

                    let removed = incoming_proposals_cache.remove(&height).map(|x| {
                        x.into_keys()
                            .map(|k| k.as_u32().expect("Round not to be None"))
                            .collect::<Vec<_>>()
                    });

                    tracing::debug!(
                        "🖧  🗑️ {validator_address} removing incoming proposals from cache for \
                         height {height} DONE, removed rounds: {removed:?}",
                    );
                }
                P2PTaskEvent::GossipRequest(msg) => match msg {
                    NetworkMessage::Proposal(SignedProposal {
                        proposal,
                        signature: _,
                    }) => {
                        let height_and_round = HeightAndRound::new(
                            proposal.height,
                            proposal.round.as_u32().expect("Valid round"),
                        );

                        let proposal_parts = if let Some(proposal_parts) =
                            my_proposals_cache.remove(&height_and_round)
                        {
                            // TODO we're assuming that all proposals are valid and any failure
                            // to reach consensus in round 0
                            // always yields reproposing the same
                            // proposal in following rounds. This will change once proposal
                            // validation is integrated.
                            proposal_parts
                        } else {
                            // TODO this is here to catch a very rare case which I'm almost
                            // sure occurred at least once during tests on my machine.
                            tracing::warn!(
                                "Engine requested gossiping a proposal for {height_and_round} via \
                                 ConsensusEvent::Gossip but we did not create it due to missing \
                                 respective ConsensusEvent::RequestProposal. my_proposals_cache: \
                                 {my_proposals_cache:#?}, incoming_proposals_cache: \
                                 {incoming_proposals_cache:#?}",
                            );

                            // The engine chose us for this round as proposer and requested that
                            // we gossip a proposal from a
                            // previous round.
                            let mut prev_rounds_proposals = incoming_proposals_cache
                                .remove(&proposal.height)
                                .expect("Proposal was inserted into the cache");
                            // For now we just choose the proposal from the previous round, and
                            // the rest are kept for debugging
                            // purposes.
                            let (round, mut proposal_parts) = prev_rounds_proposals
                                .pop_last()
                                .expect("At least one proposal from a previous round");
                            assert_eq!(
                                round.as_u32().expect("Round not to be None") + 1,
                                proposal.round.as_u32().expect("Round not to be None")
                            );
                            let ProposalInit {
                                round, proposer, ..
                            } = proposal_parts
                                .first_mut()
                                .and_then(ProposalPart::as_init_mut)
                                .expect("First part to be Init");
                            // Since the proposal comes from some previous round we need to
                            // correct the round number and
                            // proposer address.
                            assert_ne!(
                                *round,
                                proposal.round.as_u32().expect("Round not to be None")
                            );
                            assert_ne!(*proposer, Address(proposal.proposer.0));
                            *round = proposal.round.as_u32().expect("Round not to be None");
                            *proposer = Address(proposal.proposer.0);
                            proposal_parts
                        };

                        loop {
                            tracing::info!(
                                "🖧  🚀 {validator_address} Gossiping proposal for \
                                 {height_and_round} ..."
                            );
                            match p2p_client
                                .gossip_proposal(height_and_round, proposal_parts.clone())
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  🚀 {validator_address} Gossiping proposal for \
                                         {height_and_round} DONE"
                                    );
                                    break;
                                }
                                Err(PublishError::InsufficientPeers) => {
                                    tracing::warn!(
                                        "Insufficient peers to gossip proposal for \
                                         {height_and_round}, retrying..."
                                    );
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                Err(error) => {
                                    tracing::error!(
                                        "Error gossiping proposal for {height_and_round}: {error}"
                                    );
                                    // TODO implement proper error handling policy
                                    Err(error)?;
                                }
                            }
                        }
                    }
                    NetworkMessage::Vote(SignedVote { vote, signature: _ }) => {
                        loop {
                            tracing::info!("🖧  ✋ {validator_address} Gossiping vote {vote:?} ...");
                            match p2p_client
                                .gossip_vote(consensus_vote_to_p2p_vote(vote.clone()))
                                .await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        "🖧  ✋ {validator_address} Gossiping vote {vote:?} SUCCESS"
                                    );
                                    break;
                                }
                                Err(PublishError::InsufficientPeers) => {
                                    tracing::warn!(
                                        "Insufficient peers to gossip {vote:?}, retrying..."
                                    );
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                Err(error) => {
                                    tracing::error!("Error gossiping {vote:?}: {error}");
                                    // TODO implement proper error handling policy
                                    Err(error)?;
                                }
                            }
                        }
                    }
                },
            }
        }
    })
}

fn handle_incoming_proposal_part(
    chain_id: ChainId,
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    cache: &mut BTreeMap<u64, BTreeMap<Round, Vec<ProposalPart>>>,
    storage: &Storage,
) -> anyhow::Result<Option<(Hash, ContractAddress)>> {
    let height = height_and_round.height();
    let round = height_and_round.round().into();
    let proposals_at_height = cache.entry(height).or_default();
    let parts = proposals_at_height.entry(round).or_default();
    match proposal_part {
        ProposalPart::Init(ref prop_init) => {
            if parts.is_empty() {
                let proposal_init = prop_init.clone();
                parts.push(proposal_part);
                let _ = ValidatorBlockInfoStage::new(chain_id, proposal_init)?;
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal Init for height and round {} at position {}",
                    height,
                    parts.len()
                ))
            }
        }
        ProposalPart::BlockInfo(ref block_info) => {
            if parts.len() == 1 {
                let proposal_init = parts
                    .first()
                    .and_then(ProposalPart::as_init)
                    .expect("First part to be Init")
                    .clone();
                let block_info = block_info.clone();
                parts.push(proposal_part);
                let db_conn = storage
                    .connection()
                    .context("Creating database connection")?;
                let validator = ValidatorBlockInfoStage::new(chain_id, proposal_init)?;
                let _ = validator.validate_consensus_block_info(block_info, db_conn)?;
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal BlockInfo for height and round {} at position {}",
                    height,
                    parts.len()
                ))
            }
        }
        ProposalPart::TransactionBatch(_) => {
            // TODO check if there is a length limit for the batch at network level
            if parts.len() >= 2 {
                parts.push(proposal_part);
                // TODO send for execution
                Ok(None)
            } else {
                Err(anyhow::anyhow!(
                    "Unexpected proposal TransactionBatch for height and round {} at position {}",
                    height,
                    parts.len()
                ))
            }
        }
        ProposalPart::Fin(ProposalFin {
            proposal_commitment,
        }) => {
            parts.push(proposal_part);
            let ProposalPart::Init(ProposalInit { proposer, .. }) =
                parts.first().expect("Proposal Init")
            else {
                unreachable!("Proposal Init is inserted first");
            };

            // TODO validate commitment
            Ok(Some((proposal_commitment, ContractAddress(proposer.0))))
        }
    }
}

fn p2p_vote_to_consensus_vote(
    vote: p2p_proto::consensus::Vote,
) -> pathfinder_consensus::Vote<ConsensusValue, ContractAddress> {
    pathfinder_consensus::Vote {
        r#type: match vote.vote_type {
            p2p_proto::consensus::VoteType::Prevote => pathfinder_consensus::VoteType::Prevote,
            p2p_proto::consensus::VoteType::Precommit => pathfinder_consensus::VoteType::Precommit,
        },
        height: vote.height,
        round: vote.round.into(),
        value: vote.block_hash.map(ConsensusValue),
        validator_address: ContractAddress(vote.voter.0),
    }
}

fn consensus_vote_to_p2p_vote(
    vote: pathfinder_consensus::Vote<ConsensusValue, ContractAddress>,
) -> p2p_proto::consensus::Vote {
    p2p_proto::consensus::Vote {
        vote_type: match vote.r#type {
            pathfinder_consensus::VoteType::Prevote => p2p_proto::consensus::VoteType::Prevote,
            pathfinder_consensus::VoteType::Precommit => p2p_proto::consensus::VoteType::Precommit,
        },
        height: vote.height,
        round: vote.round.as_u32().expect("Round not to be Nil"),
        block_hash: vote.value.map(|v| v.0),
        voter: Address(vote.validator_address.0),
        extension: None,
    }
}
