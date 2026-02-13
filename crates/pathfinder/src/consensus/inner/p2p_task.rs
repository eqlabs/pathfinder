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
    consensus_info,
    BlockId,
    BlockNumber,
    ChainId,
    ConsensusFinalizedL2Block,
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
use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};
use pathfinder_storage::{Storage, Transaction, TransactionBehavior};
use tokio::sync::{mpsc, watch};

use super::gossip_retry::{GossipHandler, GossipRetryConfig};
use super::proposal_validator::{ProposalPartsValidator, ValidationResult};
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
use crate::gas_price::L1GasPriceProvider;
use crate::validator::{
    ProdTransactionMapper,
    TransactionExt,
    ValidatorBlockInfoStage,
    ValidatorStage,
    ValidatorWorkerPool,
};
use crate::SyncMessageToConsensus;

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
    info_watch_tx: watch::Sender<consensus_info::ConsensusInfo>,
    main_storage: Storage,
    mut finalized_blocks: HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    data_directory: &Path,
    verify_tree_hashes: bool,
    gas_price_provider: Option<L1GasPriceProvider>,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure: Option<InjectFailureConfig>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let validator_address = config.my_validator_address;
    // Contains transaction batches and proposal finalizations that are
    // waiting for previous block to be committed before they can be executed.
    let deferred_executions = Arc::new(Mutex::new(HashMap::new()));
    // Create worker pool for concurrent transaction execution
    let worker_pool: ValidatorWorkerPool =
        ExecutorWorkerPool::<ConcurrentStateReader>::auto().get();
    // Manages batch execution with concurrent execution support
    let mut batch_execution_manager =
        BatchExecutionManager::new(gas_price_provider.clone(), worker_pool.clone());
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
        let gossip_handler = GossipHandler::new(validator_address, GossipRetryConfig::default());

        let validator_cache = ValidatorCache::new();
        let mut incoming_proposals = HashMap::new();
        let mut own_proposal_parts = HashMap::new();
        let mut decided_blocks = HashMap::<u64, (u32, ConsensusFinalizedL2Block)>::new();

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
                    match from_consensus {
                        Some(command) => command,
                        None => {
                            tracing::warn!("Consensus command receiver was dropped, exiting P2P task");
                            anyhow::bail!("Consensus command receiver was dropped, exiting P2P task");
                        }
                    }
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

                let success = match p2p_task_event {
                    P2PTaskEvent::P2PEvent(event) => {
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
                            &incoming_proposals,
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
                                let result = handle_incoming_proposal_part::<ProdTransactionMapper>(
                                    chain_id,
                                    height_and_round,
                                    proposal_part,
                                    &mut incoming_proposals,
                                    &mut finalized_blocks,
                                    vcache,
                                    dex,
                                    main_readonly_storage.clone(),
                                    &mut batch_execution_manager,
                                    &data_directory,
                                    gas_price_provider.clone(),
                                    inject_failure,
                                    worker_pool.clone(),
                                );
                                match result {
                                    Ok(Some(commitment)) => {
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
                                            // Purge the proposal
                                            incoming_proposals.remove(&height_and_round);
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
                                // If we're the proposer we could have a false positive here, which
                                // we avoid by having the decided block marked, so we only return
                                // a block that is both finalized and decided upon or nothing.
                                let resp = decided_blocks
                                    .get(&number.get())
                                    .map(|(_, block)| Box::new(block.clone()));

                                if resp.is_none() {
                                    tracing::trace!(
                                        %number, "🖧  ❌ {validator_address} no finalized and decided upon block found"
                                    );
                                }

                                reply
                                    .send(resp)
                                    .map_err(|_| anyhow::anyhow!("Reply channel closed"))?;

                                Ok(ComputationSuccess::Continue)
                            }
                            // Sync confirms that the block at given height has been committed to
                            // storage.
                            SyncMessageToConsensus::ConfirmBlockCommitted { number } => {
                                tracing::trace!(
                                    %number, "🖧  📥 {validator_address} confirm finalized block committed"
                                );

                                integration_testing::debug_fail_on_proposal_committed(
                                    number.get(),
                                    inject_failure,
                                    &data_directory,
                                );

                                // There are 2 scenarios here:
                                // 1. Consensus is used by sync to get the tip because the FGw is
                                //    naturally lagging behind sync as it's just duplicating
                                //    whatever consensus provides.
                                // 2. A rare but still possible scenario where the FGw is ahead of
                                //    consensus for some nodes due to low network latency and their
                                //    consensus engines not notifying those nodes internally fast
                                //    enough that the executed proposal has been decided upon. In
                                //    such case the sync algo will choose to download the block from
                                //    the FGw because supposedly the proposal has not been decided
                                //    upon.
                                let success = on_finalized_block_committed(
                                    validator_address,
                                    &validator_cache,
                                    deferred_executions.clone(),
                                    &mut batch_execution_manager,
                                    main_readonly_storage.clone(),
                                    &mut decided_blocks,
                                    &mut finalized_blocks,
                                    number,
                                    gas_price_provider.clone(),
                                    worker_pool.clone(),
                                )?;
                                Ok(success)
                            }
                            SyncMessageToConsensus::ValidateBlock { block, reply, .. } => {
                                use pathfinder_common::StateCommitment;
                                use pathfinder_merkle_tree::starknet_state::update_starknet_state;

                                use crate::validator;

                                let starknet_version = block.header.starknet_version;
                                let state_commitment = update_starknet_state(
                                    &main_db_tx,
                                    block.state_update.as_ref(),
                                    verify_tree_hashes,
                                    block.header.number,
                                    main_readonly_storage.clone(),
                                )
                                .context("Updating Starknet state")
                                .map(|(storage, class)| {
                                    StateCommitment::calculate(storage, class, starknet_version)
                                });

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

                        let duplicate_encountered = own_proposal_parts
                            .insert(height_and_round, proposal_parts)
                            .is_some();
                        finalized_blocks.insert(height_and_round, finalized_block);

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

                            let proposal_parts = own_proposal_parts
                                .get(&height_and_round)
                                .context(format!(
                                    "Getting own proposal parts for {height_and_round}"
                                ))?
                                .clone();

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
                        // We do not have to commit these blocks to the main database
                        // anymore because they are being stored by the sync task (if enabled).
                        //
                        // TODO: Once we are ready to get rid of fake proposals, consider storing
                        // recently decided-upon blocks in memory (instead of a database) as
                        // "decided".
                        //
                        // NOTE: The main database still gets the state updates via consensus,
                        // which is the only reason why we still need the main database here at
                        // all. I could get it to work with only the consensus database in all
                        // scenarios except for when the node is chosen as a proposer and needs
                        // to cache the proposal for later.
                        tracing::info!(
                            "🖧  💾 {validator_address} Finalizing and committing block at \
                             {height_and_round} to the database ...",
                        );
                        let stopwatch = std::time::Instant::now();

                        let block = finalized_blocks.remove(&height_and_round);

                        // The block will not be in the consensus DB if it has already been
                        // downloaded from the feeder gateway and committed to the main DB by the
                        // sync task. This can happen in fast local testnets where the FGw is
                        // sometimes serving blocks from the proposers faster than the consensus
                        // engine internally notifies Pathfinder about a positive decision on the
                        // executed proposal.
                        if let Some(block) = block {
                            assert_eq!(
                                value.0 .0, block.header.state_diff_commitment.0,
                                "Proposal commitment mismatch"
                            );

                            decided_blocks.insert(
                                height_and_round.height(),
                                (height_and_round.round(), block),
                            );
                        }

                        tracing::info!(
                            "🖧  💾 {validator_address} Finalized and prepared block for \
                             committing to the database at {height_and_round} in {} ms",
                            stopwatch.elapsed().as_millis()
                        );

                        // Remove all finalized blocks for previous rounds at this height
                        // because they will not be committed to the main DB. Do not remove the
                        // block, which has just been marked as decided upon, and will be
                        // committed by the sync task until it is confirmed that the block was
                        // indeed committed.
                        finalized_blocks.retain(|hnr, _| hnr.height() != height_and_round.height());

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
                        incoming_proposals
                            .retain(|hnr, _| hnr.height() != height_and_round.height());
                        own_proposal_parts
                            .retain(|hnr, _| hnr.height() != height_and_round.height());
                        tracing::debug!(
                            "🖧  🗑️ {validator_address} removed my proposal parts for height {}",
                            height_and_round.height()
                        );

                        update_info_watch(
                            height_and_round,
                            value,
                            &incoming_proposals,
                            &own_proposal_parts,
                            &finalized_blocks,
                            &decided_blocks,
                            &info_watch_tx,
                        )?;

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
                                main_readonly_storage.clone(),
                                &mut decided_blocks,
                                &mut finalized_blocks,
                                block_number,
                                gas_price_provider.clone(),
                                worker_pool.clone(),
                            )?;

                            Ok(success)
                        } else {
                            Ok(ComputationSuccess::Continue)
                        }
                    }
                }?;

                main_db_tx.commit()?;
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
                    integration_testing::debug_fail_on_proposal_finalized(
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
#[allow(clippy::too_many_arguments)]
fn on_finalized_block_committed(
    validator_address: ContractAddress,
    validator_cache: &ValidatorCache,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    main_db: Storage,
    decided_blocks: &mut HashMap<u64, (u32, ConsensusFinalizedL2Block)>,
    finalized_blocks: &mut HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    number: BlockNumber,
    gas_price_provider: Option<L1GasPriceProvider>,
    worker_pool: ValidatorWorkerPool,
) -> Result<ComputationSuccess, anyhow::Error> {
    decided_blocks.remove(&number.get());

    tracing::debug!(
        "🖧  🗑️ {validator_address} removed finalized block for last round at height {} after \
         commit confirmation",
        number.get()
    );
    let exec_success = execute_deferred_for_next_height::<ProdTransactionMapper>(
        number.get(),
        validator_cache.clone(),
        deferred_executions.clone(),
        batch_execution_manager,
        main_db,
        finalized_blocks,
        gas_price_provider,
        worker_pool,
    )?;

    let success = match exec_success {
        Some((hnr, commitment)) => {
            ComputationSuccess::PreviouslyDeferredProposalIsFinalized(hnr, commitment)
        }
        None => ComputationSuccess::Continue,
    };
    Ok(success)
}

struct ValidatorCache(Arc<Mutex<HashMap<HeightAndRound, ValidatorStage>>>);

impl Clone for ValidatorCache {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl ValidatorCache {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn insert(&self, hnr: HeightAndRound, stage: ValidatorStage) {
        let mut cache = self.0.lock().unwrap();
        cache.insert(hnr, stage);
    }

    fn remove(&self, hnr: &HeightAndRound) -> Result<ValidatorStage, ProposalHandlingError> {
        let mut cache = self.0.lock().unwrap();
        cache.remove(hnr).ok_or_else(|| {
            ProposalHandlingError::Recoverable(ProposalError::ValidatorStageNotFound {
                height_and_round: hnr.to_string(),
            })
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_deferred_for_next_height<T: TransactionExt>(
    height: u64,
    validator_cache: ValidatorCache,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    main_db: Storage,
    finalized_blocks: &mut HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    gas_price_provider: Option<L1GasPriceProvider>,
    worker_pool: ValidatorWorkerPool,
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

        let block_info = deferred.block_info.expect(
            "BlockInfo must be present if a deferred execution exists for height and round",
        );
        let validator_stage = validator_cache.remove(&hnr)?;
        let mut validator = validator_stage
            .try_into_block_info_stage()
            .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
            .validate_block_info(
                block_info,
                main_db,
                gas_price_provider,
                None, // TODO: Add L1ToFriValidator when oracle is available
                worker_pool,
            )
            .map(Box::new)?;

        // Execute deferred transactions first.
        let opt_commitment = {
            // Parent block is now committed, so we can execute directly without deferral
            // checks
            if !deferred.transactions.is_empty() {
                batch_execution_manager.execute_batch::<T>(
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
                batch_execution_manager.process_executed_transaction_count::<T>(
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

                finalized_blocks.insert(hnr, block);
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
    incoming_proposals: &HashMap<HeightAndRound, ProposalPartsValidator>,
) -> anyhow::Result<bool> {
    // Ignore messages that refer to already committed blocks.
    let incoming_height = event.height();

    // Check the consensus database for the latest finalized height, which
    // represents blocks that consensus has decided upon (even if not yet
    // committed to main DB).
    let latest_finalized = incoming_proposals.keys().map(|hnr| hnr.height()).max();

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
/// We enforce the following order of proposal parts via
/// [ProposalPartsValidator]
/// 1. Proposal Init
/// 2. Block Info for non-empty proposals (or Proposal Fin for empty proposals)
/// 3. In random order: at least one Transaction Batch, ExecutedTransactionCount
/// 4. Proposal Fin
///
/// The [spec](https://github.com/starknet-io/starknet-p2p-specs/blob/main/p2p/proto/consensus/consensus.md#order-of-messages) is more restrictive.
#[allow(clippy::too_many_arguments)]
fn handle_incoming_proposal_part<T: TransactionExt>(
    chain_id: ChainId,
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    incoming_proposals: &mut HashMap<HeightAndRound, ProposalPartsValidator>,
    finalized_blocks: &mut HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    mut validator_cache: ValidatorCache,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    main_readonly_storage: Storage,
    batch_execution_manager: &mut BatchExecutionManager,
    data_directory: &Path,
    gas_price_provider: Option<L1GasPriceProvider>,
    inject_failure_config: Option<InjectFailureConfig>,
    worker_pool: ValidatorWorkerPool,
) -> Result<Option<ProposalCommitmentWithOrigin>, ProposalHandlingError> {
    let proposal_validator = incoming_proposals
        .entry(height_and_round)
        .or_insert_with(|| ProposalPartsValidator::new(height_and_round));

    // Does nothing in production builds.
    integration_testing::debug_fail_on_proposal_part(
        &proposal_part,
        height_and_round.height(),
        inject_failure_config,
        data_directory,
    );

    let result = proposal_validator.accept_part(&proposal_part)?;

    match (result, proposal_part) {
        (ValidationResult::Accepted, ProposalPart::Init(init)) => {
            let validator = ValidatorBlockInfoStage::new(chain_id, init)?;
            validator_cache.insert(height_and_round, ValidatorStage::BlockInfo(validator));
            Ok(None)
        }
        (ValidationResult::Accepted, ProposalPart::BlockInfo(block_info)) => {
            let validator_stage = validator_cache.remove(&height_and_round)?;

            let validator = validator_stage
                .try_into_block_info_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

            let defer = {
                let mut db_conn = main_readonly_storage.connection().context(
                    "Creating database connection for deferral check in block info validation",
                )?;
                let db_tx = db_conn.transaction().context(
                    "Creating DB transaction for deferral check in block info validation",
                )?;
                should_defer_validation(block_info.height, &db_tx)?
            };
            if defer {
                tracing::debug!(
                    "🖧  ⚙️ deferring block info validation for height and round \
                     {height_and_round}..."
                );
                let mut dex = deferred_executions.lock().unwrap();
                let deferred = dex.entry(height_and_round).or_default();
                deferred.block_info = Some(block_info);
                validator_cache.insert(height_and_round, ValidatorStage::BlockInfo(validator));
                return Ok(None);
            }

            let new_validator = validator.validate_block_info(
                block_info,
                main_readonly_storage,
                gas_price_provider,
                None, // TODO: Add L1ToFriValidator when oracle is available
                worker_pool,
            )?;
            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(Box::new(new_validator)),
            );
            Ok(None)
        }
        (ValidationResult::Accepted, ProposalPart::TransactionBatch(tx_batch)) => {
            tracing::debug!(
                "🖧  ⚙️ executing transaction batch for height and round {height_and_round}..."
            );

            let validator_stage = validator_cache.remove(&height_and_round)?;

            let next_stage = batch_execution_manager.process_batch_with_deferral::<T>(
                height_and_round,
                tx_batch,
                validator_stage,
                main_readonly_storage.clone(),
                &mut deferred_executions.lock().unwrap(),
            )?;
            validator_cache.insert(height_and_round, next_stage);

            Ok(None)
        }
        (
            ValidationResult::Accepted,
            ProposalPart::ExecutedTransactionCount(executed_txn_count),
        ) => {
            tracing::debug!(
                "🖧  ⚙️ handling ExecutedTransactionCount for height and round \
                 {height_and_round}..."
            );

            let execution_started = batch_execution_manager.is_executing(&height_and_round);

            if !execution_started {
                // Execution hasn't started - store ExecutedTransactionCount for later
                // processing. This can happen if:
                // - Transactions are deferred (deferred entry already exists)
                // - ExecutedTransactionCount arrives before execution starts
                let mut dex = deferred_executions.lock().unwrap();

                let deferred = dex.entry(height_and_round).or_default();
                deferred.executed_transaction_count = Some(executed_txn_count);
                tracing::debug!(
                    "ExecutedTransactionCount for {height_and_round} is deferred - storing for \
                     later processing (execution not started yet)"
                );
            } else {
                let validator_stage = validator_cache.remove(&height_and_round)?;
                let mut validator = validator_stage
                    .try_into_transaction_batch_stage()
                    .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?;

                batch_execution_manager.process_executed_transaction_count::<T>(
                    height_and_round,
                    executed_txn_count,
                    &mut validator,
                )?;

                // Check if ProposalFin was deferred and should now be finalized
                let mut dex = deferred_executions.lock().unwrap();
                if let Some(deferred) = dex.get_mut(&height_and_round) {
                    if let Some(deferred_commitment) = deferred.commitment.take() {
                        drop(dex);
                        let block = validator
                            .consensus_finalize(deferred_commitment.proposal_commitment)?;
                        tracing::debug!(
                            "🖧  ⚙️ finalizing deferred ProposalFin for height and round \
                             {height_and_round} after ExecutedTransactionCount was processed"
                        );

                        finalized_blocks.insert(height_and_round, block);

                        return Ok(Some(deferred_commitment));
                    }
                }

                validator_cache.insert(
                    height_and_round,
                    ValidatorStage::TransactionBatch(validator),
                );
            }

            Ok(None)
        }
        (
            ValidationResult::EmptyProposal,
            ProposalPart::Fin(ProposalFin {
                proposal_commitment,
            }),
        ) => {
            tracing::debug!(
                "🖧  ⚙️ finalizing consensus for height and round {height_and_round} (empty \
                 proposal)..."
            );

            finalized_blocks.insert(
                height_and_round,
                create_empty_block(height_and_round.height()),
            );

            let proposer_address = proposal_validator.proposer_address().ok_or_else(|| {
                ProposalHandlingError::Fatal(anyhow::anyhow!(
                    "proposer_address not set after accepting empty proposal for \
                     {height_and_round}"
                ))
            })?;

            Ok(Some(ProposalCommitmentWithOrigin {
                proposal_commitment: ProposalCommitment(proposal_commitment.0),
                proposer_address,
                pol_round: proposal_validator
                    .valid_round()
                    .map(Round::new)
                    .unwrap_or(Round::nil()),
            }))
        }
        (
            ValidationResult::NonEmptyProposal,
            ProposalPart::Fin(ProposalFin {
                proposal_commitment,
            }),
        ) => {
            tracing::debug!(
                "🖧  ⚙️ finalizing consensus for height and round {height_and_round}..."
            );

            let proposer_address = proposal_validator.proposer_address().ok_or_else(|| {
                ProposalHandlingError::Fatal(anyhow::anyhow!(
                    "proposer_address not set after accepting proposal for {height_and_round}"
                ))
            })?;
            let valid_round = proposal_validator.valid_round();

            Ok(defer_or_execute_proposal_fin::<T>(
                height_and_round,
                proposal_commitment,
                proposer_address,
                valid_round,
                main_readonly_storage.clone(),
                deferred_executions,
                batch_execution_manager,
                finalized_blocks,
                &mut validator_cache,
                gas_price_provider.clone(),
                worker_pool,
            )
            // Note: We classify as recoverable by default. If there's a storage error in the
            // chain, it will be automatically detected and converted to fatal.
            .map_err(ProposalHandlingError::recoverable)?)
        }
        _ => unreachable!("Invalid result/part combination after validation"),
    }
}

/// Determine whether validation of proposal parts for the given height should
/// be deferred because the previous block is not committed yet.
fn should_defer_validation(
    height: u64,
    main_db_tx: &Transaction<'_>,
) -> Result<bool, ProposalHandlingError> {
    let parent_block = height.checked_sub(1);
    let defer = if let Some(parent_block) = parent_block {
        let parent_block = BlockNumber::new(parent_block)
            .context("Block number is larger than i64::MAX")
            .map_err(ProposalHandlingError::Fatal)?;
        let parent_block = BlockId::Number(parent_block);
        let parent_committed = main_db_tx
            .block_exists(parent_block)
            .map_err(ProposalHandlingError::Fatal)?;
        !parent_committed
    } else {
        false
    };
    Ok(defer)
}

/// Either defer or execute the proposal finalization depending on whether
/// the previous block is committed yet. If execution is deferred, the proposal
/// commitment and proposer address are stored for later finalization. If
/// execution is performed, any previously deferred transactions for the height
/// and round are executed first, then the proposal is finalized.
#[allow(clippy::too_many_arguments)]
fn defer_or_execute_proposal_fin<T: TransactionExt>(
    height_and_round: HeightAndRound,
    proposal_commitment: Hash,
    proposer_address: ContractAddress,
    valid_round: Option<u32>,
    main_db: Storage,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
    finalized_blocks: &mut HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    validator_cache: &mut ValidatorCache,
    gas_price_provider: Option<L1GasPriceProvider>,
    worker_pool: ValidatorWorkerPool,
) -> anyhow::Result<Option<ProposalCommitmentWithOrigin>> {
    let commitment = ProposalCommitmentWithOrigin {
        proposal_commitment: ProposalCommitment(proposal_commitment.0),
        proposer_address,
        pol_round: valid_round.map(Round::new).unwrap_or(Round::nil()),
    };

    let mut main_db_conn = main_db.connection()?;
    let main_db_tx = main_db_conn.transaction()?;

    if should_defer_execution(height_and_round, &main_db_tx)? {
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

        let validator = if let Some(deferred) = deferred {
            let mut validator = if let Some(block_info) = deferred.block_info {
                validator_cache
                    .remove(&height_and_round)?
                    .try_into_block_info_stage()
                    .expect("ValidatorStage to be BlockInfo if BlockInfo is deferred")
                    .validate_block_info(
                        block_info,
                        main_db.clone(),
                        gas_price_provider,
                        None, // TODO: Add L1ToFriValidator when oracle is available
                        worker_pool,
                    )
                    .map(Box::new)?
            } else {
                validator_cache
                    .remove(&height_and_round)?
                    .try_into_transaction_batch_stage()
                    .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
            };

            // Execute deferred transactions first.
            if !deferred.transactions.is_empty() {
                tracing::debug!(
                    "🖧  ⚙️ executing {deferred_txns_len} deferred transactions for height and \
                     round {height_and_round} before finalizing proposal..."
                );
            }

            if !deferred.transactions.is_empty() {
                batch_execution_manager.execute_batch::<T>(
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
                batch_execution_manager.process_executed_transaction_count::<T>(
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
                finalized_blocks.insert(height_and_round, block);
                return Ok(Some(deferred_commitment));
            }

            validator
        } else {
            validator_cache
                .remove(&height_and_round)?
                .try_into_transaction_batch_stage()
                .map_err(|e| ProposalHandlingError::Recoverable(e.into()))?
        };

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

        finalized_blocks.insert(height_and_round, block);

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

/// Publish a snapshot of the current consensus state for observability.
fn update_info_watch(
    hnr: HeightAndRound,
    value: ConsensusValue,
    incoming_proposals: &HashMap<HeightAndRound, ProposalPartsValidator>,
    own_proposal_parts: &HashMap<HeightAndRound, Vec<ProposalPart>>,
    finalized_blocks: &HashMap<HeightAndRound, ConsensusFinalizedL2Block>,
    decided_blocks: &HashMap<u64, (u32, ConsensusFinalizedL2Block)>,
    info_watch_tx: &watch::Sender<consensus_info::ConsensusInfo>,
) -> Result<(), ProposalHandlingError> {
    let mut cached = BTreeMap::<u64, consensus_info::CachedAtHeight>::new();
    for (hnr, proposal) in incoming_proposals.iter() {
        cached
            .entry(hnr.height())
            .or_default()
            .proposals
            .push(consensus_info::ProposalParts {
                round: hnr.round(),
                proposer: proposal.proposer_address().unwrap_or_default(),
                parts_len: proposal.parts().len(),
            });
    }
    own_proposal_parts.iter().try_for_each(
        |(hnr, parts)| -> Result<(), ProposalHandlingError> {
            cached
                .entry(hnr.height())
                .or_default()
                .proposals
                .push(consensus_info::ProposalParts {
                    round: hnr.round(),
                    proposer: proposer_address_from_parts(parts, hnr)?,
                    parts_len: parts.len(),
                });
            Ok(())
        },
    )?;
    finalized_blocks.keys().for_each(|hnr| {
        cached
            .entry(hnr.height())
            .or_default()
            .blocks
            .push(consensus_info::FinalizedBlock {
                round: hnr.round(),
                is_decided: false,
            })
    });
    decided_blocks.iter().for_each(|(h, (r, _))| {
        cached
            .entry(*h)
            .or_default()
            .blocks
            .push(consensus_info::FinalizedBlock {
                round: *r,
                is_decided: true,
            })
    });

    info_watch_tx.send_modify(move |info| {
        info.highest_decision = Some(consensus_info::Decision {
            height: BlockNumber::new_or_panic(hnr.height()),
            round: hnr.round(),
            value: value.0,
        });
        info.cached = cached;
    });
    Ok(())
}

#[cfg(test)]
mod tests {

    use std::num::NonZeroUsize;
    use std::path::PathBuf;

    use pathfinder_common::{BlockHash, ConsensusFinalizedL2Block, StateCommitment};
    use pathfinder_crypto::Felt;
    use pathfinder_executor::{ConcurrentStateReader, ExecutorWorkerPool};
    use pathfinder_storage::StorageBuilder;

    use super::*;
    use crate::consensus::inner::dummy_proposal::{create, ProposalCreationConfig};
    use crate::validator::ValidatorWorkerPool;

    /// Creates a worker pool for tests.
    fn create_test_worker_pool() -> ValidatorWorkerPool {
        ExecutorWorkerPool::<ConcurrentStateReader>::new(1).get()
    }

    /// Requirements to reproduce:
    /// - `H >= 10`
    /// - rollback to batch `B`, `B > 0`
    #[test]
    fn regression_rollback_to_nonzero_batch_from_h10_onwards_clears_system_contract_0x1() {
        let main_storage = StorageBuilder::in_tempdir().unwrap();
        let worker_pool = create_test_worker_pool();
        let mut batch_execution_manager = BatchExecutionManager::new(None, worker_pool.clone());
        let dummy_data_dir = PathBuf::new();

        let mut incoming_proposals = HashMap::new();
        let mut finalized_blocks = HashMap::new();
        let validator_cache = ValidatorCache::new();
        let deferred_executions = Arc::new(Mutex::new(HashMap::new()));

        for h in 0..20 {
            let (proposal_parts, block) = create(
                h,
                Round::new(0),
                ContractAddress::ZERO,
                main_storage.clone(),
                // The smallest config that reproduced the issue until it was fixed
                Some(ProposalCreationConfig {
                    num_batches: NonZeroUsize::new(3).unwrap(),
                    batch_len: NonZeroUsize::new(1).unwrap(),
                    num_executed_txns: NonZeroUsize::new(2).unwrap(),
                }),
            )
            .unwrap();

            for proposal_part in proposal_parts {
                let is_fin = proposal_part.is_proposal_fin();
                let proposal_commitment = handle_incoming_proposal_part::<ProdTransactionMapper>(
                    ChainId::SEPOLIA_TESTNET,
                    HeightAndRound::new(h, 0),
                    proposal_part,
                    &mut incoming_proposals,
                    &mut finalized_blocks,
                    validator_cache.clone(),
                    deferred_executions.clone(),
                    main_storage.clone(),
                    &mut batch_execution_manager,
                    &dummy_data_dir,
                    None,
                    None,
                    worker_pool.clone(),
                )
                .unwrap();
                if is_fin {
                    assert_eq!(
                        proposal_commitment.unwrap().proposal_commitment.0,
                        block.header.state_diff_commitment.0,
                        "height={h}"
                    );
                }
            }

            // Commit block at `h`, otherwise h+1 will be deferred
            let mut main_db_conn = main_storage.connection().unwrap();
            let main_db_tx = main_db_conn.transaction().unwrap();
            let ConsensusFinalizedL2Block {
                header,
                state_update,
                ..
            } = block;
            // Fake trie updates - we don't care about actual trie state in this test
            let header = header.compute_hash(
                BlockHash(Felt::from_u64(h.saturating_sub(1))),
                StateCommitment::ZERO,
                |_| BlockHash(Felt::from_u64(h)),
            );

            main_db_tx.insert_block_header(&header).unwrap();
            main_db_tx
                .insert_state_update_data(header.number, &state_update)
                .unwrap();
            main_db_tx.commit().unwrap();
        }
    }
}
