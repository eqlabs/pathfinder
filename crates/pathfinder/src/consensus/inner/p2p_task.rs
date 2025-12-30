//! This task:
//! 1. handles events from the P2P network, for example a vote or a proposal has
//!    been received
//! 2. handles requests from the consensus task, for example to gossip a
//!    proposal or a vote
//! 3. issues commands to the consensus engine, for example to process a
//!    proposal or a vote received from the P2P network
//! 4. caches proposals that we created and are waiting to be gossiped when the
//!    consensus task requests so
//! 5. caches proposals that we received from other validators and may need to
//!    be proposed by us in another round at the same height

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use p2p::consensus::{peer_score, Client, Event, EventKind, HeightAndRound};
use p2p::libp2p::PeerId;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{
    BlockId,
    BlockNumber,
    ChainId,
    ConsensusInfo,
    ContractAddress,
    ProposalCommitment,
};
use pathfinder_consensus::{
    ConsensusCommand,
    NetworkMessage,
    Proposal,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
};
use pathfinder_executor::{BlockExecutor, BlockExecutorExt};
use pathfinder_storage::consensus::ConsensusStorage;
use pathfinder_storage::{Storage, Transaction, TransactionBehavior};
use tokio::sync::{mpsc, watch};

use super::gossip_retry::{GossipHandler, GossipRetryConfig};
use super::persist_proposals::ConsensusProposals;
use super::{integration_testing, ConsensusTaskEvent, ConsensusValue, P2PTaskConfig, P2PTaskEvent};
use crate::config::integration_testing::InjectFailureConfig;
use crate::consensus::inner::batch_execution::{
    should_defer_execution,
    BatchExecutionManager,
    DeferredExecution,
    ProposalCommitmentWithOrigin,
};
use crate::consensus::inner::create_empty_block;
use crate::consensus::{ProposalError, ProposalHandlingError};
use crate::validator::{
    ProdTransactionMapper,
    TransactionExt,
    ValidatorBlockInfoStage,
    ValidatorStage,
};
use crate::SyncMessageToConsensus;

#[cfg(test)]
mod handler_proptest;
#[cfg(test)]
mod p2p_task_tests;

// Successful result of handling an incoming message in a dedicated
// thread; carried data are used for async handling (e.g. gossiping).
enum ComputationSuccess {
    Continue,
    ChangePeerScore {
        peer_id: PeerId,
        delta: f64,
    },
    IncomingProposalCommitment(HeightAndRound, ProposalCommitmentWithOrigin),
    EventVote(p2p_proto::consensus::Vote),
    ProposalGossip(HeightAndRound, Vec<ProposalPart>),
    GossipVote(p2p_proto::consensus::Vote),
    /// When a proposal has been decided upon and has been successfully
    /// finalized for some height H, there may be another proposal at H+1  whose
    /// execution was deferred until this block at H is committed. This variant
    /// indicates that the deferred proposal at H+1 has been finalized.
    PreviouslyDeferredProposalIsFinalized(HeightAndRound, ProposalCommitmentWithOrigin),
}

const EVENT_CHANNEL_SIZE_LIMIT: usize = 1024;

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    chain_id: ChainId,
    config: P2PTaskConfig,
    p2p_client: Client,
    mut p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    tx_to_consensus: mpsc::Sender<ConsensusTaskEvent>,
    mut rx_from_consensus: mpsc::Receiver<P2PTaskEvent>,
    mut rx_from_sync: mpsc::Receiver<SyncMessageToConsensus>,
    info_watch_tx: watch::Sender<ConsensusInfo>,
    main_storage: Storage,
    consensus_storage: ConsensusStorage,
    data_directory: &Path,
    verify_tree_hashes: bool,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure: Option<InjectFailureConfig>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let validator_address = config.my_validator_address;
    // TODO validators are long-lived but not persisted
    let validator_cache = ValidatorCache::<BlockExecutor>::new();
    // Contains transaction batches and proposal finalizations that are
    // waiting for previous block to be committed before they can be executed.
    let deferred_executions = Arc::new(Mutex::new(HashMap::new()));
    // Manages batch execution with checkpoint-based rollback for
    // ExecutedTransactionCount support
    let mut batch_execution_manager = BatchExecutionManager::new();
    // Keep track of whether we've already emitted a warning about the
    // event channel size exceeding the limit, to avoid spamming the logs.
    let mut channel_size_warning_emitted = false;

    // Decay application peer scores at regular intervals. The first tick completing
    // immediately is okay since we likely won't have any peers with modified
    // scores this early anyway.
    let mut peer_score_decay_timer = tokio::time::interval(peer_score::DECAY_PERIOD);

    let data_directory = data_directory.to_path_buf();

    util::task::spawn(async move {
        let main_readonly_storage = main_storage.clone();
        let mut main_db_conn = main_storage
            .connection()
            .context("Creating main database connection")?;
        let mut cons_db_conn = consensus_storage
            .connection()
            .context("Creating consensus database connection")?;
        let gossip_handler = GossipHandler::new(validator_address, GossipRetryConfig::default());
        loop {
            let p2p_task_event = tokio::select! {
                _ = peer_score_decay_timer.tick() => {
                    p2p_client.decay_peer_scores();
                    continue;
                }
                p2p_event = p2p_event_rx.recv() => {
                    // Unbounded channel size monitoring.
                    let channel_size = p2p_event_rx.len();
                    if channel_size > EVENT_CHANNEL_SIZE_LIMIT {
                        if !channel_size_warning_emitted {
                            tracing::warn!(%channel_size, "Event channel size exceeded limit");
                            channel_size_warning_emitted = true;
                        }
                    } else {
                        channel_size_warning_emitted = false;
                    }

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
                from_sync = rx_from_sync.recv() => match from_sync {
                    Some(request) => P2PTaskEvent::SyncRequest(request),
                    None => {
                        tracing::warn!("Sync request receiver was dropped, exiting P2P task");
                        anyhow::bail!("Sync request receiver was dropped, exiting P2P task");
                    }
                }
            };

            let success = tokio::task::block_in_place(|| {
                tracing::debug!("creating DB txs");
                let mut main_db_tx = main_db_conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .context("Create main database transaction")?;
                let proposals_db = cons_db_conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map(ConsensusProposals::new)
                    .context("Create consensus database transaction")?;

                let success = match p2p_task_event {
                    P2PTaskEvent::P2PEvent(event) => {
                        tracing::info!("🖧  💌 {validator_address} incoming p2p event: {event:?}");

                        // Even though rebroadcast certificates are not implemented yet, it still
                        // does make sense to keep `history_depth` larger than 0. This is due to
                        // race conditions that occur between the current height, which is being
                        // committed and the next height which is being  proposed. For example: we
                        // may have 3 nodes, from which ours has already committed H, while the
                        // other 2 have not. If we fall over and respawn, the other nodes will still
                        // be voting for H, while we are at H+1 and we are actively discarding votes
                        // for H, so the other 2 nodes will not make any progress at H. And since
                        // we're not keeping any historical engines (ie. including for H), we will
                        // not help the other 2 nodes in the voting process.
                        //
                        // This call may yield unreliable results if history_depth is too small and
                        // the currently decided upon and finalized block has not been committed by
                        // the sync task yet, because we're only checking the main DB here.
                        if is_outdated_p2p_event(
                            &main_db_tx,
                            &event.kind,
                            config.history_depth,
                            &proposals_db,
                        )? {
                            return Ok(ComputationSuccess::ChangePeerScore {
                                peer_id: event.source,
                                delta: peer_score::penalty::OUTDATED_MESSAGE,
                            });
                        }

                        match event.kind {
                            EventKind::Proposal(height_and_round, proposal_part) => {
                                let vcache = validator_cache.clone();
                                let dex = deferred_executions.clone();
                                let result = handle_incoming_proposal_part::<
                                    BlockExecutor,
                                    ProdTransactionMapper,
                                >(
                                    chain_id,
                                    validator_address,
                                    height_and_round,
                                    proposal_part,
                                    vcache,
                                    dex,
                                    main_readonly_storage.clone(),
                                    &proposals_db,
                                    &mut batch_execution_manager,
                                    &data_directory,
                                    inject_failure,
                                );
                                match result {
                                    Ok(Some(commitment)) => {
                                        // Does nothing in production builds.
                                        integration_testing::debug_fail_on_entire_proposal_rx(
                                            height_and_round.height(),
                                            inject_failure,
                                            &data_directory,
                                        );

                                        anyhow::Ok(ComputationSuccess::IncomingProposalCommitment(
                                            height_and_round,
                                            commitment,
                                        ))
                                    }
                                    Ok(None) => {
                                        // Still waiting for more parts to complete
                                        // the proposal or the proposal is complete
                                        // but cannot be executed yet, because the
                                        // previous block is not committed yet.
                                        Ok(ComputationSuccess::Continue)
                                    }
                                    Err(error) => {
                                        // Log and skip on recoverable errors, don't bail out!
                                        if error.is_recoverable() {
                                            tracing::warn!(
                                                validator = %validator_address,
                                                height_and_round = %height_and_round,
                                                error = %error.error_message(),
                                                "Invalid proposal part from peer - skipping, continuing operation"
                                            );
                                            // Purge the proposal from storage
                                            if let Err(purge_err) = proposals_db.remove_parts(
                                                height_and_round.height(),
                                                Some(height_and_round.round()),
                                            ) {
                                                tracing::error!(
                                                    validator = %validator_address,
                                                    height_and_round = %height_and_round,
                                                    error = %purge_err,
                                                    "Failed to purge proposal parts after recoverable error"
                                                );
                                            } else {
                                                tracing::debug!(
                                                    validator = %validator_address,
                                                    height_and_round = %height_and_round,
                                                    "Purged proposal parts after recoverable error"
                                                );
                                            }
                                            Ok(ComputationSuccess::Continue)
                                        } else {
                                            tracing::error!(
                                                validator = %validator_address,
                                                height_and_round = %height_and_round,
                                                error = %error.error_message(),
                                                error_chain = %format!("{:#}", error),
                                                "Fatal error handling proposal part"
                                            );
                                            anyhow::bail!(
                                                "Fatal error handling incoming proposal part for \
                                                 {height_and_round}: {error:#?}"
                                            );
                                        }
                                    }
                                }
                            }

                            EventKind::Vote(vote) => {
                                // Does nothing in production builds.
                                integration_testing::debug_fail_on_vote(
                                    &vote,
                                    inject_failure,
                                    &data_directory,
                                );

                                Ok(ComputationSuccess::EventVote(vote))
                            }
                        }
                    }

                    P2PTaskEvent::SyncRequest(request) => {
                        tracing::info!("🖧  📥 {validator_address} processing request from sync");

                        match request {
                            // Sync asks for finalized block at given height.
                            SyncMessageToConsensus::GetConsensusFinalizedBlock {
                                number,
                                reply,
                            } => {
                                tracing::trace!(
                                    %number, "🖧  📥 {validator_address} get consensus finalized and decided upon block"
                                );
                                // If we're the proposer we could have a false positive here.
                                // Luckily the block has to additionally be marked as decided too,
                                // because if we're proposing, we're also caching a finalized block
                                // that has not been decided yet.
                                let resp = proposals_db
                                    .read_consensus_finalized_and_decided_block(number.get())?
                                    .map(Box::new);

                                tracing::trace!(
                                    %number, response=?resp, "🖧  📥 {validator_address} get consensus finalized and decided upon block"
                                );

                                reply
                                    .send(resp)
                                    .map_err(|_| anyhow::anyhow!("Reply channel closed"))?;

                                Ok(ComputationSuccess::Continue)
                            }
                            // Sync confirms that the finalized block at given height has been
                            // committed to storage.
                            SyncMessageToConsensus::ConfirmFinalizedBlockCommitted { number } => {
                                tracing::trace!(
                                    %number, "🖧  📥 {validator_address} confirm finalized block committed"
                                );
                                // There are 2 scenarios here:
                                // 1. The normal scenario where consensus is used by sync to get the
                                //    tip because the FGw is naturally lagging behind sync as it's
                                //    just duplicating whatever consensus provides. In such case the
                                //    following call will actually remove the finalized block for
                                //    the last round at the height and run any deferred executions
                                //    for the next height.
                                // 2. An abnormal scenario where the FGw is ahead of consensus and
                                //    somehow magically produces valid blocks. In this case the call
                                //    has no effect. Why do we take this absurd scenario into
                                //    account? Because consistency of our storage is more important
                                //    than whatever irrational scenarios that reality can surprise
                                //    us with. In this case consistency means not piling up useless
                                //    data in the consensus db that we then don't ever purge. See
                                //    how P2PTaskEvent::CommitBlock is handled for more details.
                                let success = on_finalized_block_committed(
                                    validator_address,
                                    &validator_cache,
                                    deferred_executions.clone(),
                                    &mut batch_execution_manager,
                                    &proposals_db,
                                    number,
                                )?;
                                Ok(success)
                            }
                            SyncMessageToConsensus::ValidateBlock { block, reply, .. } => {
                                use pathfinder_common::StateCommitment;
                                use pathfinder_merkle_tree::starknet_state::update_starknet_state;

                                use crate::validator;

                                let state_commitment = update_starknet_state(
                                    &main_db_tx,
                                    block.state_update.as_ref(),
                                    verify_tree_hashes,
                                    block.header.number,
                                    main_readonly_storage.clone(),
                                )
                                .context("Updating Starknet state")
                                .map(|(storage, class)| StateCommitment::calculate(storage, class));

                                // Do not commit this.
                                drop(main_db_tx);
                                main_db_tx = main_db_conn
                                    .transaction_with_behavior(TransactionBehavior::Immediate)
                                    .context("Create database transaction")?;

                                let resp = match state_commitment {
                                    Ok(state_commitment) => {
                                        if state_commitment == block.header.state_commitment {
                                            validator::ValidationResult::Valid
                                        } else {
                                            validator::ValidationResult::Invalid
                                        }
                                    }
                                    Err(e) => validator::ValidationResult::Error(e),
                                };

                                reply
                                    .send(resp)
                                    .map_err(|_| anyhow::anyhow!("Reply channel closed"))?;

                                Ok(ComputationSuccess::Continue)
                            }
                        }
                    }

                    P2PTaskEvent::CacheProposal(
                        height_and_round,
                        proposal_parts,
                        finalized_block,
                    ) => {
                        let ProposalFin {
                            proposal_commitment,
                        } = proposal_parts.last().and_then(ProposalPart::as_fin).expect(
                            "Proposals produced by our node are always coherent and complete",
                        );

                        tracing::info!(
                            "🖧  🗃️  {validator_address} caching our proposal for \
                             {height_and_round}, hash {proposal_commitment}"
                        );

                        let duplicate_encountered = proposals_db.persist_parts(
                            height_and_round.height(),
                            height_and_round.round(),
                            &validator_address,
                            &proposal_parts,
                        )?;
                        proposals_db.persist_consensus_finalized_block(
                            height_and_round.height(),
                            height_and_round.round(),
                            finalized_block,
                        )?;
                        if duplicate_encountered {
                            tracing::warn!(
                                "Duplicate proposal cache request for {height_and_round}!"
                            );
                        }

                        Ok(ComputationSuccess::Continue)
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

                            let proposal_parts = if let Some(proposal_parts) = proposals_db
                                .own_parts(
                                    height_and_round.height(),
                                    height_and_round.round(),
                                    &validator_address,
                                )? {
                                // TODO we're assuming that all proposals are valid and any failure
                                // to reach consensus in round 0
                                // always yields re-proposing the same
                                // proposal in following rounds. This will change once proposal
                                // validation is integrated.
                                proposal_parts
                            } else {
                                // TODO this is here to catch a very rare case which I'm almost
                                // sure occurred at least once during tests on my machine.
                                tracing::warn!(
                                    "Engine requested gossiping a proposal for {height_and_round} \
                                     via ConsensusEvent::Gossip but we did not create it due to \
                                     missing respective ConsensusEvent::RequestProposal.",
                                );

                                // The engine chose us for this round as proposer and requested that
                                // we gossip a proposal from a previous round. For now we just
                                // choose the proposal from the previous round, and the rest are
                                // kept for debugging purposes.
                                let Some((round, mut proposal_parts)) =
                                    proposals_db.last_parts(proposal.height, &validator_address)?
                                else {
                                    panic!("At least one proposal from a previous round");
                                };
                                assert_eq!(
                                    round + 1,
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
                                let proposer_address = ContractAddress(proposal.proposer.0);
                                proposals_db.persist_parts(
                                    proposal.height,
                                    *round,
                                    &proposer_address,
                                    &proposal_parts,
                                )?;
                                proposal_parts
                            };

                            Ok(ComputationSuccess::ProposalGossip(
                                height_and_round,
                                proposal_parts,
                            ))
                        }
                        NetworkMessage::Vote(SignedVote { vote, signature: _ }) => {
                            // Never happens in production builds.
                            let vote = if integration_testing::send_outdated_vote(
                                vote.height,
                                inject_failure,
                            ) {
                                pathfinder_consensus::Vote {
                                    height: 0, // This should make the vote outdated.
                                    ..vote
                                }
                            } else {
                                vote
                            };

                            tracing::info!("🖧  ✋ {validator_address} Gossiping vote {vote:?} ...");
                            Ok(ComputationSuccess::GossipVote(consensus_vote_to_p2p_vote(
                                vote,
                            )))
                        }
                    },
                    // Consensus has reached a positive decision on this proposal so the proposal's
                    // execution needs to be finalized and the resulting block has to be committed
                    // to the main database.
                    P2PTaskEvent::MarkBlockAsDecidedAndCleanUp(height_and_round, value) => {
                        // TODO: We do not have to commit these blocks to the main database
                        // anymore because they are being stored by the sync task (if enabled).
                        // Once we are ready to get rid of fake proposals, consider storing
                        // recently decided-upon blocks in memory (instead of a database) and
                        // swapping out the notion of "committed" for something like "decided".
                        //
                        // NOTE: The main database still gets the state updates via consensus,
                        // which is the only reason why we still need the main database here at
                        // all. I could get it to work with only the consensus database in all
                        // scenarios except for when the node is chosen as a proposer and needs
                        // to cache the proposal for later.
                        //
                        // TODO(consensus) consult sistemd about the above comments and align them
                        // accordingly.
                        tracing::info!(
                            "🖧  💾 {validator_address} Finalizing and committing block at \
                             {height_and_round} to the database ...",
                        );
                        let stopwatch = std::time::Instant::now();

                        let block = proposals_db
                            .read_consensus_finalized_block(
                                height_and_round.height(),
                                height_and_round.round(),
                            )?
                            // This will cause the p2p_task to exit which will in turn cause the
                            // entire process to exit.
                            .context(format!(
                                "Consensus finalized block at {height_and_round} that is about to \
                                 be committed should always be waiting in the consensus DB - \
                                 logic error",
                            ))?;

                        assert_eq!(
                            value.0 .0, block.header.state_diff_commitment.0,
                            "Proposal commitment mismatch"
                        );

                        proposals_db.mark_consensus_finalized_block_as_decided(
                            height_and_round.height(),
                            height_and_round.round(),
                        )?;

                        info_watch_tx.send_if_modified(|info| {
                            let do_update = match info.highest_decision {
                                None => true,
                                Some((highest_decided_height, highest_decided_value)) => {
                                    let new_height =
                                        height_and_round.height() > highest_decided_height.get();
                                    let new_value = value.0 != highest_decided_value;
                                    new_height || new_value
                                }
                            };
                            if do_update {
                                let height = BlockNumber::new_or_panic(height_and_round.height());
                                *info = ConsensusInfo {
                                    highest_decision: Some((height, value.0)),
                                    ..*info
                                };
                            }
                            do_update
                        });

                        integration_testing::debug_fail_on_proposal_committed(
                            height_and_round.height(),
                            inject_failure,
                            &data_directory,
                        );

                        tracing::info!(
                            "🖧  💾 {validator_address} Finalized and prepared block for \
                             committing to the database at {height_and_round} in {} ms",
                            stopwatch.elapsed().as_millis()
                        );

                        // Remove all finalized blocks for previous rounds at this height
                        // because they will not be committed to the main DB. Do not remove the
                        // block, which has just been marked as decided upon, that will be
                        // committed by the sync task until it is confirmed that it was indeed
                        // committed.
                        proposals_db.remove_undecided_consensus_finalized_blocks(
                            height_and_round.height(),
                        )?;
                        tracing::debug!(
                            "🖧  🗑️ {validator_address} removed my undecided finalized blocks for \
                             height {}",
                            height_and_round.height()
                        );

                        // Clean up batch execution state for this height
                        batch_execution_manager.cleanup(&height_and_round);
                        tracing::debug!(
                            "🖧  🗑️ {validator_address} cleaned up batch execution state for \
                             height {}",
                            height_and_round.height()
                        );

                        // Remove cached proposal parts for this height
                        proposals_db.remove_parts(height_and_round.height(), None)?;
                        tracing::debug!(
                            "🖧  🗑️ {validator_address} removed my proposal parts for height {}",
                            height_and_round.height()
                        );

                        // Consistency of our storage is more important than any irrational
                        // scenarios that in theory cannot occur. In the abnormal case that
                        // the FGw is actually ahead of consensus, we can check if the finalized
                        // block has already been committed to the main DB without waiting for a
                        // commit confirmation which had already arrived in the past and will result
                        // in finalized blocks for last rounds piling up without ever being removed.
                        let block_number = BlockNumber::new(height_and_round.height())
                            .context("height exceeds i64::MAX")?;
                        let is_already_committed =
                            main_db_tx.block_exists(BlockId::Number(block_number))?;
                        if is_already_committed {
                            tracing::trace!(
                                number=%block_number, "🖧  📥 {validator_address} finalized block is already committed"
                            );

                            let success = on_finalized_block_committed(
                                validator_address,
                                &validator_cache,
                                deferred_executions.clone(),
                                &mut batch_execution_manager,
                                &proposals_db,
                                block_number,
                            )?;

                            return Ok(success);
                        }

                        Ok(ComputationSuccess::Continue)
                    }
                }?;

                main_db_tx.commit()?;
                proposals_db.commit()?;
                tracing::debug!("DB txs committed");
                Ok(success)
            })?;

            match success {
                ComputationSuccess::Continue => (),
                ComputationSuccess::ChangePeerScore { peer_id, delta } => {
                    p2p_client.change_peer_score(peer_id, delta);

                    info_watch_tx.send_modify(|info| {
                        info.peer_score_change_counter += 1;
                    });
                }
                ComputationSuccess::IncomingProposalCommitment(height_and_round, commitment) => {
                    // Does nothing in production builds.
                    integration_testing::debug_fail_on_entire_proposal_persisted(
                        height_and_round.height(),
                        inject_failure,
                        &data_directory,
                    );

                    send_proposal_to_consensus(&tx_to_consensus, height_and_round, commitment)
                        .await;
                }
                ComputationSuccess::EventVote(vote) => {
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
                ComputationSuccess::ProposalGossip(height_and_round, proposal_parts) => {
                    tracing::info!(
                        "🖧  🚀 {validator_address} Gossiping proposal for {height_and_round} ..."
                    );
                    gossip_handler
                        .gossip_proposal(&p2p_client, height_and_round, proposal_parts)
                        .await?;
                }
                ComputationSuccess::GossipVote(vote) => {
                    gossip_handler.gossip_vote(&p2p_client, vote).await?;
                }
                ComputationSuccess::PreviouslyDeferredProposalIsFinalized(hnr, commitment) => {
                    send_proposal_to_consensus(&tx_to_consensus, hnr, commitment).await;
                }
            }
        }
    })
}

/// Handle commit confirmation for a finalized block at given height.
fn on_finalized_block_committed(
    validator_address: ContractAddress,
    validator_cache: &ValidatorCache<BlockExecutor>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    proposals_db: &ConsensusProposals<'_>,
    number: pathfinder_common::BlockNumber,
) -> Result<ComputationSuccess, anyhow::Error> {
    // In practice this should only remove the finalized block for the last round at
    // the height, because lower rounds were already removed when the proposal
    // was decided upon in that last round.
    proposals_db.remove_consensus_finalized_blocks(number.get())?;

    tracing::debug!(
        "🖧  🗑️ {validator_address} removed finalized block for last round at height {} after \
         commit confirmation",
        number.get()
    );
    let exec_success = execute_deferred_for_next_height::<BlockExecutor, ProdTransactionMapper>(
        number.get(),
        validator_cache.clone(),
        deferred_executions.clone(),
        batch_execution_manager,
        proposals_db,
    )?;

    let success = match exec_success {
        Some((hnr, commitment)) => {
            ComputationSuccess::PreviouslyDeferredProposalIsFinalized(hnr, commitment)
        }
        None => ComputationSuccess::Continue,
    };
    Ok(success)
}

struct ValidatorCache<E>(Arc<Mutex<HashMap<HeightAndRound, ValidatorStage<E>>>>);

impl<E> Clone for ValidatorCache<E> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<E> ValidatorCache<E> {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn insert(&mut self, hnr: HeightAndRound, stage: ValidatorStage<E>) {
        let mut cache = self.0.lock().unwrap();
        cache.insert(hnr, stage);
    }

    fn remove(&mut self, hnr: &HeightAndRound) -> Result<ValidatorStage<E>, ProposalHandlingError> {
        let mut cache = self.0.lock().unwrap();
        cache.remove(hnr).ok_or_else(|| {
            ProposalHandlingError::Recoverable(ProposalError::ValidatorStageNotFound {
                height_and_round: hnr.to_string(),
            })
        })
    }
}

fn execute_deferred_for_next_height<E: BlockExecutorExt, T: TransactionExt>(
    height: u64,
    mut validator_cache: ValidatorCache<E>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    proposals_db: &ConsensusProposals<'_>,
) -> anyhow::Result<Option<(HeightAndRound, ProposalCommitmentWithOrigin)>> {
    // Retrieve and execute any deferred transactions or proposal finalizations
    // for the next height, if any. Sort by (height, round) in ascending order.
    let deferred = {
        let mut dex = deferred_executions.lock().unwrap();
        dex.extract_if(|hnr, _| hnr.height() == height + 1)
            .collect::<BTreeMap<_, _>>()
    };

    // Execute deferred transactions and proposal finalization only for the last
    // stored deferred round in the height, because if there are any deferred
    // transactions or proposal finalization for lower rounds, they are already
    // outdated and can be discarded. `deferred_executions` is sorted by (height,
    // round) in ascending order, so we can just take the last entry.
    if let Some((hnr, deferred)) = deferred.into_iter().next_back() {
        tracing::debug!("🖧  ⚙️ executing deferred proposal for height and round {hnr}");

        let validator_stage = validator_cache.remove(&hnr).map_err(anyhow::Error::from)?;
        let mut validator = validator_stage.try_into_transaction_batch_stage()?;

        // Execute deferred transactions first.
        let opt_commitment = {
            // Parent block is now committed, so we can execute directly without deferral
            // checks
            if !deferred.transactions.is_empty() {
                batch_execution_manager.execute_batch::<E, T>(
                    hnr,
                    deferred.transactions,
                    &mut validator,
                )?;
            }

            // Process deferred ExecutedTransactionCount
            if let Some(executed_transaction_count) = deferred.executed_transaction_count {
                tracing::debug!(
                    "🖧  ⚙️ processing deferred ExecutedTransactionCount for height and round {hnr}"
                );
                // Execution has started at this point (from execute_batch above, if
                // transactions were non-empty). If transactions were empty,
                // execute_batch handles marking execution as started, so we can
                // process ExecutedTransactionCount immediately.
                batch_execution_manager.process_executed_transaction_count::<E, T>(
                    hnr,
                    executed_transaction_count,
                    &mut validator,
                )?;
            }

            // Process deferred commitment
            if let Some(commitment) = deferred.commitment {
                // We've executed all transactions at the height, we can now
                // finalize the proposal.
                let block = validator.consensus_finalize(commitment.proposal_commitment)?;
                tracing::debug!(
                    "🖧  ⚙️ executed deferred finalized consensus for height and round {hnr}"
                );

                proposals_db.persist_consensus_finalized_block(hnr.height(), hnr.round(), block)?;
                Some(commitment)
            } else {
                tracing::debug!(
                    "🖧  ⚙️ executed deferred transactions for height and round {hnr}, no \
                     consensus finalize yet"
                );

                // We've only executed the transaction batches that we have
                // but apparently we haven't received the entire proposal so
                // the rest of the transaction batches could be still be
                // coming from the network, definitely the proposal fin is
                // still missing for sure.
                validator_cache.insert(hnr, ValidatorStage::TransactionBatch(validator));
                None
            }
        };

        Ok(opt_commitment.map(|commitment| (hnr, commitment)))
    } else {
        Ok(None)
    }
}

/// Check whether the incoming p2p event is outdated, i.e. it refers to a block
/// that is already committed to the database. If so, log it and return `true`,
/// otherwise return `false`.
fn is_outdated_p2p_event(
    db_tx: &Transaction<'_>,
    event: &EventKind,
    history_depth: u64,
    proposals_db: &ConsensusProposals<'_>,
) -> anyhow::Result<bool> {
    // Ignore messages that refer to already committed blocks.
    let incoming_height = event.height();

    // Check the consensus database for the latest finalized height, which
    // represents blocks that consensus has decided upon (even if not yet
    // committed to main DB).
    let latest_finalized = proposals_db
        .inner()
        .latest_finalized_height()
        .map_err(|e| {
            anyhow::Error::from(e)
                .context("Failed to query latest finalized height from consensus database")
        })?;

    if let Some(latest_finalized) = latest_finalized {
        let threshold = latest_finalized.saturating_sub(history_depth);
        if incoming_height < threshold {
            tracing::info!(
                "🖧  ⛔ ignoring incoming p2p event {} for height {incoming_height} because latest \
                 finalized height is {latest_finalized} and history depth is {history_depth}",
                event.type_name()
            );
            return Ok(true);
        }
    } else {
        // Fallback to main database if no finalized blocks in consensus DB yet
        let latest_committed = db_tx
            .block_number(BlockId::Latest)
            .context("Failed to query latest committed block for outdated event check")?;

        if let Some(latest_committed) = latest_committed {
            let threshold = latest_committed.get().saturating_sub(history_depth);
            if incoming_height < threshold {
                tracing::info!(
                    "🖧  ⛔ ignoring incoming p2p event {} for height {incoming_height} because \
                     latest committed block is {latest_committed} and history depth is \
                     {history_depth}",
                    event.type_name()
                );
                return Ok(true);
            }
        } else {
            tracing::debug!(
                "🖧  No committed blocks found in database, cannot determine if event {} for \
                 height {incoming_height} is outdated",
                event.type_name()
            );
        }
    }

    Ok(false)
}

/// Send a proposal for a given height and round to the consensus engine.
async fn send_proposal_to_consensus(
    tx_to_consensus: &mpsc::Sender<ConsensusTaskEvent>,
    height_and_round: HeightAndRound,
    commitment: ProposalCommitmentWithOrigin,
) {
    let ProposalCommitmentWithOrigin {
        proposal_commitment,
        proposer_address,
        pol_round,
    } = commitment;
    let proposal = Proposal {
        height: height_and_round.height(),
        round: height_and_round.round().into(),
        value: ConsensusValue(proposal_commitment),
        pol_round,
        proposer: proposer_address,
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

/// Handles an incoming proposal part received from the P2P network. Returns
/// `Ok(Some((proposal_commitment, proposer_address)))` if the proposal is
/// complete and has been executed. Otherwise returns `Ok(None)`, which means
/// that either:
/// - an incomplete proposal has been received but all of the received parts
///   have been executed,
/// - an incomplete proposal has been received but it cannot be executed yet,
///   because the previous block is not committed yet,
/// - a complete proposal has been received but it cannot be executed yet.
///
/// Returns `Err` if there was an error processing the proposal part.
///
/// # Important
///
/// We always enforce the following order of proposal parts:
/// 1. Proposal Init
/// 2. Block Info for non-empty proposals (or Proposal Fin for empty proposals)
/// 3. In random order: at least one Transaction Batch, ExecutedTransactionCount
/// 4. Proposal Fin
///
/// The [spec](https://github.com/starknet-io/starknet-p2p-specs/blob/main/p2p/proto/consensus/consensus.md#order-of-messages) is more restrictive.
#[allow(clippy::too_many_arguments)]
fn handle_incoming_proposal_part<E: BlockExecutorExt, T: TransactionExt>(
    chain_id: ChainId,
    validator_address: ContractAddress,
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    mut validator_cache: ValidatorCache<E>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    main_readonly_storage: Storage,
    proposals_db: &ConsensusProposals<'_>,
    batch_execution_manager: &mut BatchExecutionManager,
    data_directory: &Path,
    inject_failure_config: Option<InjectFailureConfig>,
) -> Result<Option<ProposalCommitmentWithOrigin>, ProposalHandlingError> {
    let mut parts_for_height_and_round = proposals_db
        .foreign_parts(
            height_and_round.height(),
            height_and_round.round(),
            &validator_address,
        )?
        .unwrap_or_default();

    let has_executed_txn_count = parts_for_height_and_round
        .iter()
        .any(|part| matches!(part, ProposalPart::ExecutedTransactionCount(_)));

    // Does nothing in production builds.
    integration_testing::debug_fail_on_proposal_part(
        &proposal_part,
        height_and_round.height(),
        inject_failure_config,
        data_directory,
    );

    match proposal_part {
        ProposalPart::Init(ref prop_init) => {
            if !parts_for_height_and_round.is_empty() {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Unexpected proposal Init for height and round {} at position {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                ));
            }

            // If this is a valid proposal, then this may be an empty proposal:
            // - [x] Proposal Init
            // - [ ] Proposal Fin
            // or the first part of a non-empty proposal:
            // - [x] Proposal Init
            // - [ ] Block Info
            // (...)
            let proposal_init = prop_init.clone();
            parts_for_height_and_round.push(proposal_part);
            let proposer_address = ContractAddress(proposal_init.proposer.0);
            let updated = proposals_db.persist_parts(
                height_and_round.height(),
                height_and_round.round(),
                &proposer_address,
                &parts_for_height_and_round,
            )?;
            assert!(!updated);
            let validator = ValidatorBlockInfoStage::new(chain_id, proposal_init)?;
            validator_cache.insert(height_and_round, ValidatorStage::BlockInfo(validator));
            Ok(None)
        }
        ProposalPart::BlockInfo(ref block_info) => {
            if parts_for_height_and_round.len() != 1 {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Unexpected proposal BlockInfo for height and round {} at position {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                ));
            }

            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // (...)
            let validator_stage = validator_cache.remove(&height_and_round)?;

            let validator = validator_stage
                .try_into_block_info_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

            let block_info = block_info.clone();
            append_and_persist_part(
                height_and_round,
                proposal_part,
                proposals_db,
                &mut parts_for_height_and_round,
            )?;

            let new_validator =
                validator.validate_consensus_block_info(block_info, main_readonly_storage)?;
            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(Box::new(new_validator)),
            );
            Ok(None)
        }
        ProposalPart::TransactionBatch(ref tx_batch) => {
            // TODO check if there is a length limit for the batch at network level
            if parts_for_height_and_round.len() < 2 {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Unexpected proposal TransactionBatch for height and round {} at \
                             position {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                ));
            }

            if tx_batch.is_empty() {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Received empty TransactionBatch for height and round {} at position \
                             {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                ));
            }

            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // - [ ] in any order:
            //      - [x] at least one Transaction Batch
            //      - [?] Executed Transaction Count
            // - [ ] Proposal Fin
            tracing::debug!(
                "🖧  ⚙️ executing transaction batch for height and round {height_and_round}..."
            );

            let validator_stage = validator_cache.remove(&height_and_round)?;

            let mut validator = validator_stage
                .try_into_transaction_batch_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

            let tx_batch = tx_batch.clone();
            append_and_persist_part(
                height_and_round,
                proposal_part,
                proposals_db,
                &mut parts_for_height_and_round,
            )?;

            let mut main_db_conn = main_readonly_storage.connection()?;
            let main_db_tx = main_db_conn.transaction()?;
            // Use BatchExecutionManager to handle optimistic execution with checkpoints and
            // deferral
            batch_execution_manager.process_batch_with_deferral::<E, T>(
                height_and_round,
                tx_batch,
                &mut validator,
                &main_db_tx,
                &mut deferred_executions.lock().unwrap(),
            )?;

            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(validator),
            );

            Ok(None)
        }
        ProposalPart::Fin(ProposalFin {
            proposal_commitment,
        }) => {
            tracing::debug!(
                "🖧  ⚙️ finalizing consensus for height and round {height_and_round}..."
            );

            match parts_for_height_and_round.len() {
                1 if parts_for_height_and_round
                    .first()
                    .expect("part 1 to exist")
                    .is_proposal_init() =>
                {
                    // Looks like an empty proposal:
                    // - [x] Proposal Init
                    // - [x] Proposal Fin
                    proposals_db.persist_consensus_finalized_block(
                        height_and_round.height(),
                        height_and_round.round(),
                        create_empty_block(height_and_round.height()),
                    )?;

                    let proposer_address = append_and_persist_part(
                        height_and_round,
                        proposal_part,
                        proposals_db,
                        &mut parts_for_height_and_round,
                    )?;

                    let valid_round =
                        valid_round_from_parts(&parts_for_height_and_round, &height_and_round)?;
                    let proposal_commitment = Some(ProposalCommitmentWithOrigin {
                        proposal_commitment: ProposalCommitment(proposal_commitment.0),
                        proposer_address,
                        pol_round: valid_round.map(Round::new).unwrap_or(Round::nil()),
                    });

                    // We don't retrieve the validator from cache here, it'll be retrieved for
                    // block finalization
                    Ok(proposal_commitment)
                }
                4.. if parts_for_height_and_round
                    .get(1)
                    .expect("part 1 to exist")
                    .is_block_info() =>
                {
                    // Looks like a non-empty proposal:
                    // - [x] Proposal Init
                    // - [x] Block Info
                    // - [ ] in any order:
                    //      - [?] at least one Transaction Batch
                    //      - [?] Executed Transaction Count
                    // - [x] Proposal Fin
                    let validator_stage = validator_cache.remove(&height_and_round)?;
                    let validator = validator_stage
                        .try_into_transaction_batch_stage()
                        .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

                    let proposer_address = append_and_persist_part(
                        height_and_round,
                        proposal_part,
                        proposals_db,
                        &mut parts_for_height_and_round,
                    )?;

                    let valid_round =
                        valid_round_from_parts(&parts_for_height_and_round, &height_and_round)?;
                    let mut main_db_conn = main_readonly_storage.connection()?;
                    let main_db_tx = main_db_conn.transaction()?;
                    let proposal_commitment = defer_or_execute_proposal_fin::<E, T>(
                        height_and_round,
                        proposal_commitment,
                        proposer_address,
                        valid_round,
                        &main_db_tx,
                        validator,
                        deferred_executions,
                        batch_execution_manager,
                        proposals_db,
                        &mut validator_cache,
                    )
                    // Note: We classify as recoverable by default, but storage errors in the
                    // chain are automatically detected and converted to fatal.
                    .map_err(ProposalHandlingError::recoverable)?;

                    Ok(proposal_commitment)
                }
                _ => Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Unexpected proposal ProposalFin for height and round {} at position \
                             {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                )),
            }
        }
        ProposalPart::ExecutedTransactionCount(executed_txn_count) => {
            tracing::debug!(
                "🖧  ⚙️ handling ExecutedTransactionCount for height and round \
                 {height_and_round}..."
            );

            if !parts_for_height_and_round
                .get(1)
                .is_some_and(|p| p.is_block_info())
            {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Unexpected proposal ExecutedTransactionCount for height and round {} \
                             at position {}",
                            height_and_round,
                            parts_for_height_and_round.len()
                        ),
                    },
                ));
            }

            if has_executed_txn_count {
                return Err(ProposalHandlingError::Recoverable(
                    ProposalError::UnexpectedProposalPart {
                        message: format!(
                            "Duplicate ExecutedTransactionCount for height and round \
                             {height_and_round}",
                        ),
                    },
                ));
            }
            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // - [ ] in any order:
            //      - [?] at least one Transaction Batch
            //      - [x] Executed Transaction Count
            // - [ ] Proposal Fin
            append_and_persist_part(
                height_and_round,
                proposal_part.clone(),
                proposals_db,
                &mut parts_for_height_and_round,
            )?;

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let mut validator = validator_stage
                .try_into_transaction_batch_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

            // Check if execution has started
            let execution_started = batch_execution_manager.is_executing(&height_and_round);

            if !execution_started {
                // Execution hasn't started - store ExecutedTransactionCount for later
                // processing This can happen if:
                // 1. Transactions are deferred (deferred entry already exists)
                // 2. ExecutedTransactionCount arrives before execution starts (need to create
                //    deferred entry)
                // Note: With message ordering guarantees, ExecutedTransactionCount should
                // always arrive after all TransactionBatches, but execution may not have
                // started yet if batches were deferred.
                let mut dex = deferred_executions.lock().unwrap();

                let deferred = dex.entry(height_and_round).or_default();
                deferred.executed_transaction_count = Some(executed_txn_count);
                tracing::debug!(
                    "ExecutedTransactionCount for {height_and_round} is deferred - storing for \
                     later processing (execution not started yet)"
                );
            } else {
                // Execution has started - process ExecutedTransactionCount immediately
                batch_execution_manager.process_executed_transaction_count::<E, T>(
                    height_and_round,
                    executed_txn_count,
                    &mut validator,
                )?;

                // After processing ExecutedTransactionCount, check if ProposalFin was deferred
                // and should now be finalized
                let mut dex = deferred_executions.lock().unwrap();
                if let Some(deferred) = dex.get_mut(&height_and_round) {
                    if let Some(deferred_commitment) = deferred.commitment.take() {
                        drop(dex);
                        // ExecutedTransactionCount is now processed, we can finalize the proposal
                        let block = validator
                            .consensus_finalize(deferred_commitment.proposal_commitment)?;
                        tracing::debug!(
                            "🖧  ⚙️ finalizing deferred ProposalFin for height and round \
                             {height_and_round} after ExecutedTransactionCount was processed"
                        );

                        proposals_db.persist_consensus_finalized_block(
                            height_and_round.height(),
                            height_and_round.round(),
                            block,
                        )?;

                        return Ok(Some(deferred_commitment));
                    }
                }
            }

            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(validator),
            );

            Ok(None)
        }
    }
}

fn append_and_persist_part(
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    proposals_db: &ConsensusProposals<'_>,
    parts: &mut Vec<ProposalPart>,
) -> Result<ContractAddress, ProposalHandlingError> {
    parts.push(proposal_part);
    let proposer_address = proposer_address_from_parts(parts, &height_and_round)?;
    let updated = proposals_db.persist_parts(
        height_and_round.height(),
        height_and_round.round(),
        &proposer_address,
        parts,
    )?;
    assert!(updated);
    Ok(proposer_address)
}

/// Either defer or execute the proposal finalization depending on whether
/// the previous block is committed yet. If execution is deferred, the proposal
/// commitment and proposer address are stored for later finalization. If
/// execution is performed, any previously deferred transactions for the height
/// and round are executed first, then the proposal is finalized.
#[allow(clippy::too_many_arguments)]
fn defer_or_execute_proposal_fin<E: BlockExecutorExt, T: TransactionExt>(
    height_and_round: HeightAndRound,
    proposal_commitment: Hash,
    proposer_address: ContractAddress,
    valid_round: Option<u32>,
    main_db_tx: &Transaction<'_>,
    mut validator: Box<crate::validator::ValidatorTransactionBatchStage<E>>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    proposals_db: &ConsensusProposals<'_>,
    validator_cache: &mut ValidatorCache<E>,
) -> anyhow::Result<Option<ProposalCommitmentWithOrigin>> {
    let commitment = ProposalCommitmentWithOrigin {
        proposal_commitment: ProposalCommitment(proposal_commitment.0),
        proposer_address,
        pol_round: valid_round.map(Round::new).unwrap_or(Round::nil()),
    };

    if should_defer_execution(height_and_round, main_db_tx)? {
        // The proposal cannot be finalized yet, because the previous
        // block is not committed yet. Defer its finalization.
        tracing::debug!(
            "🖧  ⚙️ consensus finalize for height and round {height_and_round} is deferred"
        );

        let mut deferred_executions = deferred_executions.lock().unwrap();
        deferred_executions
            .entry(height_and_round)
            .or_default()
            .commitment = Some(commitment);
        validator_cache.insert(
            height_and_round,
            ValidatorStage::TransactionBatch(validator),
        );
        Ok(None)
    } else {
        // The proposal can be finalized now, because the previous
        // block is committed. First execute any deferred transactions
        // for the height and round, if any, then finalize the proposal.
        let deferred = {
            let mut dex = deferred_executions.lock().unwrap();
            dex.remove(&height_and_round)
        };
        let deferred_txns_len = deferred.as_ref().map_or(0, |d| d.transactions.len());

        if let Some(deferred) = deferred {
            if !deferred.transactions.is_empty() {
                batch_execution_manager.execute_batch::<E, T>(
                    height_and_round,
                    deferred.transactions,
                    &mut validator,
                )?;
            }

            // Process deferred ExecutedTransactionCount if it was stored
            if let Some(executed_transaction_count) = deferred.executed_transaction_count {
                tracing::debug!(
                    "🖧  ⚙️ processing deferred ExecutedTransactionCount for height and round \
                     {height_and_round}"
                );
                // Execution has started at this point (from execute_batch),
                // so we can process ExecutedTransactionCount immediately
                batch_execution_manager.process_executed_transaction_count::<E, T>(
                    height_and_round,
                    executed_transaction_count,
                    &mut validator,
                )?;
            }

            // Process deferred commitment if it was stored (use it instead of the new one)
            // (they should match, but the deferred one was received earlier)
            if let Some(deferred_commitment) = deferred.commitment {
                tracing::debug!(
                    "🖧  ⚙️ using deferred commitment for height and round {height_and_round}"
                );
                // We've executed all transactions at the height, we can now finalize the
                // proposal.
                let block =
                    validator.consensus_finalize(deferred_commitment.proposal_commitment)?;
                tracing::debug!(
                    "🖧  ⚙️ consensus finalization for height and round {height_and_round} is \
                     complete, additionally {deferred_txns_len} previously deferred transactions \
                     were executed",
                );
                proposals_db.persist_consensus_finalized_block(
                    height_and_round.height(),
                    height_and_round.round(),
                    block,
                )?;
                return Ok(Some(deferred_commitment));
            }
        }

        // Check if execution has started but ExecutedTransactionCount hasn't been
        // processed yet If so, defer ProposalFin until ExecutedTransactionCount
        // arrives
        if batch_execution_manager.should_defer_proposal_fin(&height_and_round) {
            tracing::debug!(
                "🖧  ⚙️ consensus finalize for height and round {height_and_round} is deferred \
                 because ExecutedTransactionCount hasn't been processed yet"
            );

            let mut deferred_executions = deferred_executions.lock().unwrap();
            deferred_executions
                .entry(height_and_round)
                .or_default()
                .commitment = Some(commitment);
            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(validator),
            );
            return Ok(None);
        }

        let block = validator.consensus_finalize(commitment.proposal_commitment)?;

        tracing::debug!(
            "🖧  ⚙️ consensus finalization for height and round {height_and_round} is complete, \
             additionally {deferred_txns_len} previously deferred transactions were executed",
        );

        proposals_db.persist_consensus_finalized_block(
            height_and_round.height(),
            height_and_round.round(),
            block,
        )?;

        Ok(Some(commitment))
    }
}

/// Convert a vote from `p2p_proto` format to `pathfinder_consensus`` format.
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
        value: vote
            .proposal_commitment
            .map(|h| ConsensusValue(ProposalCommitment(h.0))),
        validator_address: ContractAddress(vote.voter.0),
    }
}

/// Convert a vote from `pathfinder_consensus` format to `p2p_proto` format.
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
        proposal_commitment: vote.value.map(|v| Hash(v.0 .0)),
        voter: Address(vote.validator_address.0),
    }
}

/// Extract the proposer address from the proposal parts.
fn proposer_address_from_parts(
    parts: &[ProposalPart],
    height_and_round: &HeightAndRound,
) -> Result<ContractAddress, ProposalHandlingError> {
    let ProposalPart::Init(ProposalInit { proposer, .. }) =
        parts
            .first()
            .ok_or(ProposalHandlingError::Fatal(anyhow::anyhow!(
                "Proposal parts list is empty for {height_and_round} - logic error"
            )))?
    else {
        return Err(ProposalHandlingError::Fatal(anyhow::anyhow!(
            "First proposal part is not Init for {height_and_round} - logic error"
        )));
    };
    Ok(ContractAddress(proposer.0))
}

/// Extract the valid round from the proposal parts.
fn valid_round_from_parts(
    parts: &[ProposalPart],
    height_and_round: &HeightAndRound,
) -> Result<Option<u32>, ProposalHandlingError> {
    let ProposalPart::Init(ProposalInit { valid_round, .. }) =
        parts
            .first()
            .ok_or(ProposalHandlingError::Fatal(anyhow::anyhow!(
                "Proposal parts list is empty for {height_and_round} - logic error"
            )))?
    else {
        return Err(ProposalHandlingError::Fatal(anyhow::anyhow!(
            "First proposal part is not Init for {height_and_round} - logic error"
        )));
    };
    Ok(*valid_round)
}
