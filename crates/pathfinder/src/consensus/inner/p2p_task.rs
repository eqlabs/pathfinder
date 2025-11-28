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
use std::time::Duration;

use anyhow::Context;
use p2p::consensus::{Client, Event, HeightAndRound};
use p2p::libp2p::gossipsub::PublishError;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{BlockId, ChainId, ContractAddress, ProposalCommitment};
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
use pathfinder_storage::{Storage, Transaction, TransactionBehavior};
use tokio::sync::mpsc;

use super::{integration_testing, ConsensusTaskEvent, P2PTaskConfig, P2PTaskEvent};
use crate::config::integration_testing::InjectFailureConfig;
use crate::consensus::inner::batch_execution::{
    should_defer_execution,
    BatchExecutionManager,
    DeferredExecution,
    ProposalCommitmentWithOrigin,
};
use crate::consensus::inner::persist_proposals::ConsensusProposals;
use crate::consensus::inner::ConsensusValue;
use crate::validator::{
    FinalizedBlock,
    ProdTransactionMapper,
    TransactionExt,
    ValidatorBlockInfoStage,
    ValidatorStage,
};

#[cfg(test)]
mod handler_proptest;
#[cfg(test)]
mod p2p_task_tests;

// Successful result of handling an incoming message in a dedicated
// thread; carried data are used for async handling (e.g. gossiping).
enum ComputationSuccess {
    Continue,
    IncomingProposalCommitment(HeightAndRound, ProposalCommitmentWithOrigin),
    EventVote(p2p_proto::consensus::Vote),
    ProposalGossip(HeightAndRound, Vec<ProposalPart>),
    GossipVote(p2p_proto::consensus::Vote),
    ConfirmedProposalCommitment(HeightAndRound, ProposalCommitmentWithOrigin),
}

const EVENT_CHANNEL_SIZE_LIMIT: usize = 1024;

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    chain_id: ChainId,
    config: P2PTaskConfig,
    p2p_client: Client,
    storage: Storage,
    mut p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    tx_to_consensus: mpsc::Sender<ConsensusTaskEvent>,
    mut rx_from_consensus: mpsc::Receiver<P2PTaskEvent>,
    consensus_storage: Storage,
    data_directory: &Path,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure: Option<InjectFailureConfig>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let validator_address = config.my_validator_address;
    // TODO validators are long-lived but not persisted
    let validator_cache = ValidatorCache::<BlockExecutor>::new();
    // Contains transaction batches and proposal finalizations that are
    // waiting for previous block to be committed before they can be executed.
    let deferred_executions = Arc::new(Mutex::new(HashMap::new()));
    // Manages batch execution with checkpoint-based rollback for TransactionsFin
    // support
    let mut batch_execution_manager = BatchExecutionManager::new();
    // Keep track of whether we've already emitted a warning about the
    // event channel size exceeding the limit, to avoid spamming the logs.
    let mut channel_size_warning_emitted = false;

    let data_directory = data_directory.to_path_buf();

    util::task::spawn(async move {
        let readonly_storage = storage.clone();
        let mut db_conn = storage
            .connection()
            .context("Creating database connection")?;
        let mut cons_conn = consensus_storage
            .connection()
            .context("Creating consensus database connection")?;
        loop {
            let p2p_task_event = tokio::select! {
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
            };

            let success = tokio::task::block_in_place(|| {
                tracing::debug!("creating DB txs");
                let mut db_tx = db_conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .context("Create database transaction")?;
                let mut cons_tx = cons_conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .context("Create database transaction")?;
                let mut proposals_db = ConsensusProposals::new(&cons_tx);

                let success = match p2p_task_event {
                    P2PTaskEvent::P2PEvent(event) => {
                        tracing::info!("🖧  💌 {validator_address} incoming p2p event: {event:?}");

                        // Even though rebroadcast certificates are not implemented yet, it still
                        // does make sense to keep `history_depth` nonzero. This is due to race
                        // conditions that occur between the current height, which is being
                        // committed and the next height which is being proposed. For example: we
                        // may have 3 nodes, from which ours has already committed H, while the
                        // other 2 have not. If we fall over and respawn, the other nodes will still
                        // be voting for H, while we are at H+1 and we are actively discarding votes
                        // for H, so the other 2 nodes will not make any progress at H. And since
                        // we're not keeping any historical engines (ie. including for H), we will
                        // not help the other 2 nodes in the voting process.
                        if is_outdated_p2p_event(&db_tx, &event, config.history_depth)? {
                            // TODO consider punishing the sender if the event is too old
                            return Ok(ComputationSuccess::Continue);
                        }

                        match event {
                            Event::Proposal(height_and_round, proposal_part) => {
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
                                    &db_tx,
                                    readonly_storage.clone(),
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
                                        tracing::warn!(
                                            "Error handling incoming proposal part for \
                                             {height_and_round}: {error:#?}"
                                        );
                                        anyhow::bail!(
                                            "Error handling incoming proposal part for \
                                             {height_and_round}: {error:#?}"
                                        );
                                    }
                                }
                            }

                            Event::Vote(vote) => {
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
                        proposals_db.persist_finalized_block(
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
                                // we gossip a proposal from a
                                // previous round.
                                // For now we just choose the proposal from the previous round, and
                                // the rest are kept for debugging
                                // purposes.
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
                            tracing::info!("🖧  ✋ {validator_address} Gossiping vote {vote:?} ...");
                            Ok(ComputationSuccess::GossipVote(consensus_vote_to_p2p_vote(
                                vote,
                            )))
                        }
                    },
                    P2PTaskEvent::CommitBlock(height_and_round, value) => {
                        {
                            let storage = readonly_storage.clone();
                            let mut validator_cache = validator_cache.clone();
                            tracing::info!(
                                "🖧  💾 {validator_address} Finalizing and committing block at \
                                 {height_and_round} to the database ...",
                            );
                            let stopwatch = std::time::Instant::now();

                            let finalized_block = match proposals_db.read_finalized_block(
                                height_and_round.height(),
                                height_and_round.round(),
                            )? {
                                // Our own proposal is already executed and finalized.
                                Some(block) => block,
                                // Incoming proposal has been executed and needs to be finalized
                                // now.
                                None => {
                                    let validator_stage =
                                        validator_cache.remove(&height_and_round)?;
                                    let validator = validator_stage.try_into_finalize_stage()?;
                                    let block = validator.finalize(db_tx, storage)?;
                                    db_tx = db_conn
                                        .transaction_with_behavior(TransactionBehavior::Immediate)
                                        .context("Create database transaction")?;
                                    block
                                }
                            };

                            assert_eq!(value.0 .0, finalized_block.header.state_diff_commitment.0);

                            commit_finalized_block(&db_tx, finalized_block.clone())?;
                            db_tx.commit().context("Committing database transaction")?;

                            // Does nothing in production builds.
                            integration_testing::debug_fail_on_proposal_committed(
                                height_and_round.height(),
                                inject_failure,
                                &data_directory,
                            );

                            db_tx = db_conn
                                .transaction()
                                .context("Create unused database transaction")?;
                            // Necessary for proper fake proposal creation at next heights.
                            commit_finalized_block(&cons_tx, finalized_block)?;
                            cons_tx
                                .commit()
                                .context("Committing database transaction")?;
                            cons_tx = cons_conn
                                .transaction_with_behavior(TransactionBehavior::Immediate)
                                .context("Create consensus database transaction")?;
                            // Recreate proposals_db wrapper with new transaction
                            proposals_db = ConsensusProposals::new(&cons_tx);
                            tracing::info!(
                                "🖧  💾 {validator_address} Finalized and committed block at \
                                 {height_and_round} to the database in {} ms",
                                stopwatch.elapsed().as_millis()
                            );

                            proposals_db.remove_finalized_blocks(height_and_round.height())?;
                            tracing::debug!(
                                "🖧  🗑️ {validator_address} removed my finalized blocks for height \
                                 {}",
                                height_and_round.height()
                            );

                            // Clean up batch execution state for this height
                            batch_execution_manager.cleanup(&height_and_round);
                            tracing::debug!(
                                "🖧  🗑️ {validator_address} cleaned up batch execution state for \
                                 height {}",
                                height_and_round.height()
                            );
                            proposals_db.remove_parts(height_and_round.height(), None)?;

                            anyhow::Ok(())
                        }?;

                        let exec_success = execute_deferred_for_next_height::<
                            BlockExecutor,
                            ProdTransactionMapper,
                        >(
                            height_and_round,
                            validator_cache.clone(),
                            deferred_executions.clone(),
                            &mut batch_execution_manager,
                        )?;
                        // If we finalized the proposal, we can now inform the consensus engine
                        // about it. Otherwise the rest of the transaction batches could be still be
                        // coming from the network, definitely the proposal fin is still missing for
                        // sure.
                        let success = match exec_success {
                            Some((hnr, commitment)) => {
                                ComputationSuccess::ConfirmedProposalCommitment(hnr, commitment)
                            }
                            None => ComputationSuccess::Continue,
                        };
                        Ok(success)
                    }
                }?;

                db_tx.commit()?;
                cons_tx.commit()?;
                tracing::debug!("DB txs committed");
                Ok(success)
            })?;

            match success {
                ComputationSuccess::Continue => (),
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
                    loop {
                        tracing::info!(
                            "🖧  🚀 {validator_address} Gossiping proposal for {height_and_round} \
                             ..."
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
                ComputationSuccess::GossipVote(vote) => {
                    loop {
                        match p2p_client.gossip_vote(vote.clone()).await {
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
                ComputationSuccess::ConfirmedProposalCommitment(hnr, commitment) => {
                    send_proposal_to_consensus(&tx_to_consensus, hnr, commitment).await;
                }
            }
        }
    })
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

    fn remove(&mut self, hnr: &HeightAndRound) -> anyhow::Result<ValidatorStage<E>> {
        let mut cache = self.0.lock().unwrap();
        cache
            .remove(hnr)
            .context(format!("No ValidatorStage for height and round {hnr}"))
    }
}

fn execute_deferred_for_next_height<E: BlockExecutorExt, T: TransactionExt>(
    height_and_round: HeightAndRound,
    mut validator_cache: ValidatorCache<E>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
) -> anyhow::Result<Option<(HeightAndRound, ProposalCommitmentWithOrigin)>> {
    // Retrieve and execute any deferred transactions or proposal finalizations
    // for the next height, if any. Sort by (height, round) in ascending order.
    let deferred = {
        let mut dex = deferred_executions.lock().unwrap();
        dex.extract_if(|hnr, _| hnr.height() == height_and_round.height() + 1)
            .collect::<BTreeMap<_, _>>()
    };

    // Execute deferred transactions and proposal finalization only for the last
    // stored deferred round in the height, because if there are any deferred
    // transactions or proposal finalization for lower rounds, they are already
    // outdated and can be discarded. `deferred_executions` is sorted by (height,
    // round) in ascending order, so we can just take the last entry.
    if let Some((hnr, deferred)) = deferred.into_iter().next_back() {
        tracing::debug!("🖧  ⚙️ executing deferred proposal for height and round {hnr}");

        let validator_stage = validator_cache.remove(&hnr)?;
        let mut validator = validator_stage.try_into_transaction_batch_stage()?;

        // Execute deferred transactions first.
        let (validator, opt_commitment) = {
            // Parent block is now committed, so we can execute directly without deferral
            // checks
            if !deferred.transactions.is_empty() {
                batch_execution_manager.execute_batch::<E, T>(
                    hnr,
                    deferred.transactions,
                    &mut validator,
                )?;
            }

            // Process deferred TransactionsFin
            if let Some(transactions_fin) = deferred.transactions_fin {
                tracing::debug!(
                    "🖧  ⚙️ processing deferred TransactionsFin for height and round {hnr}"
                );
                // Execution has started at this point (from execute_batch above, if
                // transactions were non-empty). If transactions were empty,
                // execute_batch handles marking execution as started, so we can
                // process TransactionsFin immediately.
                batch_execution_manager.process_transactions_fin::<E, T>(
                    hnr,
                    transactions_fin,
                    &mut validator,
                )?;
            }

            // Process deferred commitment
            if let Some(commitment) = deferred.commitment {
                // We've executed all transactions at the height, we can now
                // finalize the proposal.
                let validator = validator.consensus_finalize(commitment.proposal_commitment)?;
                tracing::debug!(
                    "🖧  ⚙️ executed deferred finalized consensus for height and round {hnr}"
                );

                (
                    ValidatorStage::Finalize(Box::new(validator)),
                    Some(commitment),
                )
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
                (ValidatorStage::TransactionBatch(validator), None)
            }
        };

        validator_cache.insert(hnr, validator);
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
    event: &Event,
    history_depth: u64,
) -> anyhow::Result<bool> {
    // Ignore messages that refer to already committed blocks.
    let incoming_height = event.height();
    let latest_committed = db_tx.block_number(BlockId::Latest)?;
    if let Some(latest_committed) = latest_committed {
        if incoming_height < latest_committed.get().saturating_sub(history_depth) {
            tracing::info!(
                "🖧  ⛔ ignoring incoming p2p event {} for height {incoming_height} because latest \
                 committed block is {latest_committed} and history depth is {history_depth}",
                event.type_name()
            );
            return Ok(true);
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

/// Commit the given finalized block to the database.
fn commit_finalized_block(
    db_txn: &Transaction<'_>,
    finalized_block: FinalizedBlock,
) -> anyhow::Result<()> {
    let FinalizedBlock {
        header,
        state_update,
        transactions_and_receipts,
        events,
    } = finalized_block;

    let block_number = header.number;
    db_txn
        .insert_block_header(&header)
        .context("Inserting block header")?;
    db_txn
        .insert_state_update_data(block_number, &state_update)
        .context("Inserting state update")?;
    db_txn
        .insert_transaction_data(block_number, &transactions_and_receipts, Some(&events))
        .context("Inserting transactions, receipts and events")?;

    Ok(())
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
/// 2. Block Info for non-empty proposals (or Proposal Commitment for empty
///    proposals)
///
/// The rest can come in any order. The [spec](https://github.com/starknet-io/starknet-p2p-specs/blob/main/p2p/proto/consensus/consensus.md#order-of-messages).
/// is more restrictive.
#[allow(clippy::too_many_arguments)]
fn handle_incoming_proposal_part<E: BlockExecutorExt, T: TransactionExt>(
    chain_id: ChainId,
    validator_address: ContractAddress,
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    mut validator_cache: ValidatorCache<E>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    db_tx: &Transaction<'_>,
    storage: Storage,
    proposals_db: &ConsensusProposals<'_>,
    batch_execution_manager: &mut BatchExecutionManager,
    data_directory: &Path,
    inject_failure_config: Option<InjectFailureConfig>,
) -> anyhow::Result<Option<ProposalCommitmentWithOrigin>> {
    let mut parts = proposals_db
        .foreign_parts(
            height_and_round.height(),
            height_and_round.round(),
            &validator_address,
        )?
        .unwrap_or_default();

    let has_txns_fin = parts
        .iter()
        .any(|part| matches!(part, ProposalPart::TransactionsFin(_)));
    let has_commitment = parts
        .iter()
        .any(|part| matches!(part, ProposalPart::ProposalCommitment(_)));

    // Does nothing in production builds.
    integration_testing::debug_fail_on_proposal_part(
        &proposal_part,
        height_and_round.height(),
        inject_failure_config,
        data_directory,
    );

    match proposal_part {
        ProposalPart::Init(ref prop_init) => {
            if !parts.is_empty() {
                anyhow::bail!(
                    "Unexpected proposal Init for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }
            // If this is a valid proposal, then this may be an empty proposal:
            // - [x] Proposal Init
            // - [ ] Proposal Commitment
            // - [ ] Proposal Fin
            // or the first part of a non-empty proposal:
            // - [x] Proposal Init
            // - [ ] Block Info
            // (...)
            let proposal_init = prop_init.clone();
            parts.push(proposal_part);
            let proposer_address = ContractAddress(proposal_init.proposer.0);
            let updated = proposals_db.persist_parts(
                height_and_round.height(),
                height_and_round.round(),
                &proposer_address,
                &parts,
            )?;
            assert!(!updated);
            let validator = ValidatorBlockInfoStage::new(chain_id, proposal_init)?;
            validator_cache.insert(height_and_round, ValidatorStage::BlockInfo(validator));
            Ok(None)
        }
        ProposalPart::BlockInfo(ref block_info) => {
            if parts.len() != 1 {
                anyhow::bail!(
                    "Unexpected proposal BlockInfo for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }
            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // (...)
            let validator_stage = validator_cache.remove(&height_and_round)?;
            let validator = validator_stage.try_into_block_info_stage()?;

            let block_info = block_info.clone();
            append_and_persist_part(height_and_round, proposal_part, proposals_db, &mut parts)?;

            let new_validator = validator.validate_consensus_block_info(block_info, storage)?;
            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(Box::new(new_validator)),
            );
            Ok(None)
        }
        ProposalPart::TransactionBatch(ref tx_batch) => {
            // TODO check if there is a length limit for the batch at network level
            if parts.len() < 2 {
                anyhow::bail!(
                    "Unexpected proposal TransactionBatch for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }

            if tx_batch.is_empty() {
                anyhow::bail!(
                    "Received empty TransactionBatch for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }
            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // - [ ] in any order:
            //      - [x] at least one Transaction Batch
            //      - [?] Transactions Fin
            //      - [?] Proposal Commitment
            // - [ ] Proposal Fin
            tracing::debug!(
                "🖧  ⚙️ executing transaction batch for height and round {height_and_round}..."
            );

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let mut validator = validator_stage.try_into_transaction_batch_stage()?;

            let tx_batch = tx_batch.clone();
            append_and_persist_part(height_and_round, proposal_part, proposals_db, &mut parts)?;

            // Use BatchExecutionManager to handle optimistic execution with checkpoints and
            // deferral
            batch_execution_manager.process_batch_with_deferral::<E, T>(
                height_and_round,
                tx_batch,
                &mut validator,
                db_tx,
                &mut deferred_executions.lock().unwrap(),
            )?;

            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(validator),
            );

            Ok(None)
        }
        ProposalPart::ProposalCommitment(ref proposal_commitment) => {
            match parts.len() {
                1 => {
                    // Looks like this could be an empty proposal:
                    // - [x] Proposal Init
                    // - [x] Proposal Commitment
                    // - [ ] Proposal Fin
                    append_and_persist_part(
                        height_and_round,
                        proposal_part.clone(),
                        proposals_db,
                        &mut parts,
                    )?;

                    let validator_stage = validator_cache.remove(&height_and_round)?;
                    let validator = validator_stage.try_into_block_info_stage()?;
                    let validator = validator.verify_proposal_commitment(proposal_commitment)?;
                    let validator =
                        ValidatorStage::Finalize(Box::new(validator.consensus_finalize()));
                    validator_cache.insert(height_and_round, validator);
                    Ok(None)
                }
                2.. => {
                    if has_commitment {
                        anyhow::bail!(
                            "Duplicate ProposalCommitment for height and round {height_and_round}",
                        );
                    }

                    // Looks like a non-empty proposal:
                    // - [x] Proposal Init
                    // - [x] Block Info
                    // - [ ] in any order:
                    //      - [?] at least one Transaction Batch
                    //      - [?] Transactions Fin
                    //      - [x] Proposal Commitment
                    // - [ ] Proposal Fin
                    append_and_persist_part(
                        height_and_round,
                        proposal_part.clone(),
                        proposals_db,
                        &mut parts,
                    )?;

                    let validator_stage = validator_cache.remove(&height_and_round)?;
                    let mut validator = validator_stage.try_into_transaction_batch_stage()?;

                    validator.record_proposal_commitment(proposal_commitment)?;
                    validator_cache.insert(
                        height_and_round,
                        ValidatorStage::TransactionBatch(validator),
                    );
                    Ok(None)
                }
                _ => {
                    anyhow::bail!(
                        "Unexpected proposal ProposalCommitment for height and round {} at \
                         position {}",
                        height_and_round,
                        parts.len()
                    );
                }
            }
        }
        ProposalPart::Fin(ProposalFin {
            proposal_commitment,
        }) => {
            tracing::debug!(
                "🖧  ⚙️ finalizing consensus for height and round {height_and_round}..."
            );

            match parts.len() {
                2 if parts
                    .get(1)
                    .expect("part 1 to exist")
                    .is_proposal_commitment() =>
                {
                    // Looks like an empty proposal:
                    // - [x] Proposal Init
                    // - [x] Proposal Commitment
                    // - [x] Proposal Fin
                    let proposer_address = append_and_persist_part(
                        height_and_round,
                        proposal_part,
                        proposals_db,
                        &mut parts,
                    )?;

                    let valid_round = valid_round_from_parts(&parts)?;
                    let proposal_commitment = Some(ProposalCommitmentWithOrigin {
                        proposal_commitment: ProposalCommitment(proposal_commitment.0),
                        proposer_address,
                        pol_round: valid_round.map(Round::new).unwrap_or(Round::nil()),
                    });

                    // We don't retrieve the validator from cache here, it'll be retrieved for
                    // block finalization
                    Ok(proposal_commitment)
                }
                5.. if parts.get(1).expect("part 1 to exist").is_block_info() => {
                    // Looks like a non-empty proposal:
                    // - [x] Proposal Init
                    // - [x] Block Info
                    // - [ ] in any order:
                    //      - [?] at least one Transaction Batch
                    //      - [?] Transactions Fin
                    //      - [?] Proposal Commitment
                    // - [x] Proposal Fin
                    let validator_stage = validator_cache.remove(&height_and_round)?;
                    let validator = validator_stage.try_into_transaction_batch_stage()?;

                    if !validator.has_proposal_commitment() {
                        anyhow::bail!(
                            "Transaction batch missing proposal commitment for height and round \
                             {height_and_round}"
                        );
                    }

                    let proposer_address = append_and_persist_part(
                        height_and_round,
                        proposal_part,
                        proposals_db,
                        &mut parts,
                    )?;

                    let valid_round = valid_round_from_parts(&parts)?;
                    let (validator, proposal_commitment) = defer_or_execute_proposal_fin::<E, T>(
                        height_and_round,
                        proposal_commitment,
                        proposer_address,
                        valid_round,
                        db_tx,
                        validator,
                        deferred_executions,
                        batch_execution_manager,
                    )?;

                    validator_cache.insert(height_and_round, validator);
                    Ok(proposal_commitment)
                }
                _ => {
                    anyhow::bail!(
                        "Unexpected proposal ProposalFin for height and round {} at position {}",
                        height_and_round,
                        parts.len()
                    );
                }
            }
        }
        ProposalPart::TransactionsFin(ref transactions_fin) => {
            tracing::debug!(
                "🖧  ⚙️ handling TransactionsFin for height and round {height_and_round}..."
            );

            if !parts.get(1).map(|p| p.is_block_info()).unwrap_or_default() {
                anyhow::bail!(
                    "Unexpected proposal TransactionsFin for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }

            if has_txns_fin {
                anyhow::bail!("Duplicate TransactionsFin for height and round {height_and_round}",);
            }
            // Looks like a non-empty proposal:
            // - [x] Proposal Init
            // - [x] Block Info
            // - [ ] in any order:
            //      - [?] at least one Transaction Batch
            //      - [x] Transactions Fin
            //      - [?] Proposal Commitment
            // - [ ] Proposal Fin
            append_and_persist_part(
                height_and_round,
                proposal_part.clone(),
                proposals_db,
                &mut parts,
            )?;

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let mut validator = validator_stage.try_into_transaction_batch_stage()?;

            // Check if execution has started
            let execution_started = batch_execution_manager.is_executing(&height_and_round);

            if !execution_started {
                // Execution hasn't started - store TransactionsFin for later processing
                // This can happen if:
                // 1. Transactions are deferred (deferred entry already exists)
                // 2. TransactionsFin arrives before execution starts (need to create deferred
                //    entry)
                // Note: With message ordering guarantees, TransactionsFin should always arrive
                // after all TransactionBatches, but execution may not have started yet if
                // batches were deferred.
                let mut dex = deferred_executions.lock().unwrap();

                let deferred = dex.entry(height_and_round).or_default();
                deferred.transactions_fin = Some(*transactions_fin);
                tracing::debug!(
                    "TransactionsFin for {height_and_round} is deferred - storing for later \
                     processing (execution not started yet)"
                );
            } else {
                // Execution has started - process TransactionsFin immediately
                batch_execution_manager.process_transactions_fin::<E, T>(
                    height_and_round,
                    *transactions_fin,
                    &mut validator,
                )?;

                // After processing TransactionsFin, check if ProposalFin was deferred
                // and should now be finalized
                let mut dex = deferred_executions.lock().unwrap();
                if let Some(deferred) = dex.get_mut(&height_and_round) {
                    if let Some(deferred_commitment) = deferred.commitment.take() {
                        drop(dex);
                        // TransactionsFin is now processed, we can finalize the proposal
                        let validator = validator
                            .consensus_finalize(deferred_commitment.proposal_commitment)?;
                        tracing::debug!(
                            "🖧  ⚙️ finalizing deferred ProposalFin for height and round \
                             {height_and_round} after TransactionsFin was processed"
                        );
                        validator_cache.insert(
                            height_and_round,
                            ValidatorStage::Finalize(Box::new(validator)),
                        );
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
) -> Result<ContractAddress, anyhow::Error> {
    parts.push(proposal_part);
    let proposer_address = proposer_address_from_parts(parts)?;
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
    db_tx: &Transaction<'_>,
    mut validator: Box<crate::validator::ValidatorTransactionBatchStage<E>>,
    deferred_executions: Arc<Mutex<HashMap<HeightAndRound, DeferredExecution>>>,
    batch_execution_manager: &mut BatchExecutionManager,
) -> anyhow::Result<(ValidatorStage<E>, Option<ProposalCommitmentWithOrigin>)> {
    let commitment = ProposalCommitmentWithOrigin {
        proposal_commitment: ProposalCommitment(proposal_commitment.0),
        proposer_address,
        pol_round: valid_round.map(Round::new).unwrap_or(Round::nil()),
    };

    if should_defer_execution(height_and_round, db_tx)? {
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
        Ok((ValidatorStage::TransactionBatch(validator), None))
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

            // Process deferred TransactionsFin if it was stored
            if let Some(transactions_fin) = deferred.transactions_fin {
                tracing::debug!(
                    "🖧  ⚙️ processing deferred TransactionsFin for height and round \
                     {height_and_round}"
                );
                // Execution has started at this point (from execute_batch),
                // so we can process TransactionsFin immediately
                batch_execution_manager.process_transactions_fin::<E, T>(
                    height_and_round,
                    transactions_fin,
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
                let validator =
                    validator.consensus_finalize(deferred_commitment.proposal_commitment)?;
                tracing::debug!(
                    "🖧  ⚙️ consensus finalization for height and round {height_and_round} is \
                     complete, additionally {deferred_txns_len} previously deferred transactions \
                     were executed",
                );
                return Ok((
                    ValidatorStage::Finalize(Box::new(validator)),
                    Some(deferred_commitment),
                ));
            }
        }

        // Check if execution has started but TransactionsFin hasn't been processed yet
        // If so, defer ProposalFin until TransactionsFin arrives
        if batch_execution_manager.should_defer_proposal_fin(&height_and_round) {
            tracing::debug!(
                "🖧  ⚙️ consensus finalize for height and round {height_and_round} is deferred \
                 because TransactionsFin hasn't been processed yet"
            );

            let mut deferred_executions = deferred_executions.lock().unwrap();
            deferred_executions
                .entry(height_and_round)
                .or_default()
                .commitment = Some(commitment);
            return Ok((ValidatorStage::TransactionBatch(validator), None));
        }

        let validator = validator.consensus_finalize(commitment.proposal_commitment)?;

        tracing::debug!(
            "🖧  ⚙️ consensus finalization for height and round {height_and_round} is complete, \
             additionally {deferred_txns_len} previously deferred transactions were executed",
        );

        Ok((
            ValidatorStage::Finalize(Box::new(validator)),
            Some(commitment),
        ))
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
        height: vote.block_number,
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
        block_number: vote.height,
        round: vote.round.as_u32().expect("Round not to be Nil"),
        proposal_commitment: vote.value.map(|v| Hash(v.0 .0)),
        voter: Address(vote.validator_address.0),
    }
}

/// Extract the proposer address from the proposal parts.
fn proposer_address_from_parts(parts: &[ProposalPart]) -> anyhow::Result<ContractAddress> {
    let ProposalPart::Init(ProposalInit { proposer, .. }) =
        parts.first().context("Proposal part list is empty")?
    else {
        anyhow::bail!("First proposal part is not ProposalInit");
    };
    Ok(ContractAddress(proposer.0))
}

/// Extract the valid round from the proposal parts.
fn valid_round_from_parts(parts: &[ProposalPart]) -> anyhow::Result<Option<u32>> {
    let ProposalPart::Init(ProposalInit { valid_round, .. }) =
        parts.first().context("Proposal part list is empty")?
    else {
        anyhow::bail!("First proposal part is not ProposalInit");
    };
    Ok(*valid_round)
}
