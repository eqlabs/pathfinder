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
use std::time::Duration;

use anyhow::Context;
use futures::future::Either;
use p2p::consensus::{Client, Event, HeightAndRound};
use p2p::libp2p::gossipsub::PublishError;
use p2p_proto::common::{Address, Hash};
use p2p_proto::consensus::{ProposalFin, ProposalInit, ProposalPart};
use pathfinder_common::{BlockId, BlockNumber, ChainId, ContractAddress, ProposalCommitment};
use pathfinder_consensus::{
    ConsensusCommand,
    NetworkMessage,
    Proposal,
    Round,
    Signature,
    SignedProposal,
    SignedVote,
};
use pathfinder_storage::{Storage, TransactionBehavior};
use tokio::sync::mpsc;

use super::{ConsensusTaskEvent, P2PTaskEvent};
use crate::consensus::inner::ConsensusValue;
use crate::validator::{FinalizedBlock, ValidatorBlockInfoStage, ValidatorStage};

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    chain_id: ChainId,
    validator_address: ContractAddress,
    p2p_client: Client,
    storage: Storage,
    mut p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    tx_to_consensus: mpsc::Sender<ConsensusTaskEvent>,
    mut rx_from_consensus: mpsc::Receiver<P2PTaskEvent>,
    fake_proposals_storage: Storage,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    // Cache for proposals that we created and are waiting to be gossiped upon a
    // command from the consensus engine. Once the proposal is gossiped, it is
    // removed from the cache.
    let mut my_proposals_cache = HashMap::new();
    // Cache for finalized blocks that we created from our proposals and are
    // waiting to be committed to the database once consensus is reached.
    let mut my_finalized_blocks_cache = HashMap::new();
    // Cache for proposals that we received from other validators and may need to be
    // proposed by us in another round at the same height. The proposals are removed
    // either when we gossip them or when decision is made at the same height.
    let mut incoming_proposals_cache = BTreeMap::new();
    // TODO validators are long-lived but not persisted
    let mut validator_cache = ValidatorCache::new();
    // Contains transaction batches and proposal finalizations that are
    // waiting for previous block to be committed before they can be executed.
    let mut deferred_executions = HashMap::new();

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

                    if is_outdated_p2p_event(storage.clone(), &event).await? {
                        // TODO consider punishing the sender if the event is too old
                        continue;
                    }

                    match event {
                        Event::Proposal(height_and_round, proposal_part) => {
                            match handle_incoming_proposal_part(
                                chain_id,
                                height_and_round,
                                proposal_part,
                                &mut incoming_proposals_cache,
                                &mut validator_cache,
                                &mut deferred_executions,
                                storage.clone(),
                            )
                            .await
                            {
                                Ok(Some(commitment)) => {
                                    send_proposal_to_consensus(
                                        &tx_to_consensus,
                                        height_and_round,
                                        commitment,
                                    )
                                    .await;
                                }
                                Ok(None) => {
                                    // Still waiting for more parts to complete
                                    // the proposal or the proposal is complete
                                    // but cannot be executed yet, because the
                                    // previous block is not committed yet.
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
                P2PTaskEvent::CacheProposal(height_and_round, proposal_parts, finalized_block) => {
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
                    my_finalized_blocks_cache.insert(height_and_round, finalized_block);

                    if duplicate_encountered {
                        tracing::warn!("Duplicate proposal cache request for {height_and_round}!");
                    }
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
                            // always yields re-proposing the same
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
                P2PTaskEvent::CommitBlock(height_and_round, value) => {
                    finalize_and_commit_block(
                        validator_address,
                        height_and_round,
                        value,
                        storage.clone(),
                        fake_proposals_storage.clone(),
                        &mut my_finalized_blocks_cache,
                        &mut incoming_proposals_cache,
                        &mut validator_cache,
                    )
                    .await?;

                    execute_deferred_for_next_height(
                        height_and_round,
                        &tx_to_consensus,
                        &mut validator_cache,
                        &mut deferred_executions,
                    )
                    .await?;
                }
            }
        }
    })
}

struct ValidatorCache(HashMap<HeightAndRound, ValidatorStage>);

impl ValidatorCache {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(&mut self, hnr: HeightAndRound, stage: ValidatorStage) {
        self.0.insert(hnr, stage);
    }

    fn remove(&mut self, hnr: &HeightAndRound) -> anyhow::Result<ValidatorStage> {
        self.0
            .remove(hnr)
            .context(format!("No ValidatorStage for height and round {hnr}"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_and_commit_block(
    validator_address: ContractAddress,
    height_and_round: HeightAndRound,
    value: ConsensusValue,
    storage: Storage,
    fake_proposals_storage: Storage,
    my_finalized_blocks_cache: &mut HashMap<HeightAndRound, FinalizedBlock>,
    incoming_proposals_cache: &mut BTreeMap<u64, BTreeMap<Round, Vec<ProposalPart>>>,
    validator_cache: &mut ValidatorCache,
) -> anyhow::Result<()> {
    tracing::info!(
        "🖧  💾 {validator_address} Finalizing and committing block at {height_and_round} to the \
         database ...",
    );
    let stopwatch = std::time::Instant::now();

    let finalized_block = match my_finalized_blocks_cache.remove(&height_and_round) {
        // Our own proposal is already executed and finalized.
        Some(block) => Either::Left(block),
        // Incoming proposal has been executed and needs to be finalized now.
        None => {
            let validator_stage = validator_cache.remove(&height_and_round)?;
            let validator = validator_stage.try_into_finalize_stage()?;
            Either::Right(validator)
        }
    };

    let storage = storage.clone();
    let fake_proposals_storage = fake_proposals_storage.clone();

    util::task::spawn_blocking(move |_| {
        let finalized_block = match finalized_block {
            Either::Left(block) => block,
            Either::Right(validator) => validator.finalize(storage.clone())?,
        };

        assert_eq!(value.0 .0, finalized_block.header.state_diff_commitment.0);

        commit_finalized_block(storage, finalized_block.clone())?;
        // Necessary for proper fake proposal creation at next heights.
        commit_finalized_block(fake_proposals_storage, finalized_block)?;

        anyhow::Ok(())
    })
    .await??;
    tracing::info!(
        "🖧  💾 {validator_address} Finalized and committed block at {height_and_round} to the \
         database in {} ms",
        stopwatch.elapsed().as_millis()
    );

    let removed = my_finalized_blocks_cache
        .iter()
        .filter_map(|(hnr, _)| (hnr.height() == height_and_round.height()).then_some(hnr.round()))
        .collect::<Vec<_>>();
    my_finalized_blocks_cache.retain(|hnr, _| hnr.height() != height_and_round.height());
    tracing::debug!(
        "🖧  🗑️ {validator_address} removed my finalized blocks from cache for height {} and \
         rounds: {removed:?}",
        height_and_round.height()
    );

    let removed = incoming_proposals_cache
        .remove(&height_and_round.height())
        .unwrap_or_default()
        .into_keys()
        .map(|round| round.as_u32().expect("Round not to be None"))
        .collect::<Vec<_>>();
    tracing::debug!(
        "🖧  🗑️ {validator_address} removed incoming proposals from cache for height {} and \
         rounds: {removed:?}",
        height_and_round.height()
    );

    Ok(())
}

async fn execute_deferred_for_next_height(
    height_and_round: HeightAndRound,
    tx_to_consensus: &mpsc::Sender<ConsensusTaskEvent>,
    validator_cache: &mut ValidatorCache,
    deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
) -> anyhow::Result<()> {
    // Retrieve and execute any deferred transactions or proposal finalizations
    // for the next height, if any. Sort by (height, round) in ascending order.
    let deferred = deferred_executions
        .extract_if(|hnr, _| hnr.height() == height_and_round.height() + 1)
        .collect::<BTreeMap<_, _>>();

    // Execute deferred transactions and proposal finalization only for the last
    // stored deferred round in the height, because if there are any deferred
    // transactions or proposal finalization for lower rounds, they are already
    // outdated and can be discarded. `deferred_executions` is sorted by (height,
    // round) in ascending order, so we can just take the last entry.
    if let Some((hnr, deferred)) = deferred.into_iter().next_back() {
        tracing::debug!("🖧  ⚙️ executing deferred proposal for height and round {hnr}");

        let validator_stage = validator_cache.remove(&hnr)?;
        let mut validator = validator_stage.try_into_transaction_batch_stage()?;

        let (validator, commitment) = util::task::spawn_blocking(move |_| {
            // Execute deferred transactions first.
            validator.execute_transactions(deferred.transactions)?;

            anyhow::Ok(if let Some(commitment) = deferred.commitment {
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
            })
        })
        .await??;

        validator_cache.insert(hnr, validator);

        // If we finalized the proposal, we can now inform the consensus engine
        // about it. Otherwise the rest of the transaction batches could be still be
        // coming from the network, definitely the proposal fin is still missing for
        // sure.
        if let Some(commitment) = commitment {
            send_proposal_to_consensus(tx_to_consensus, hnr, commitment).await;
        }
    }

    Ok(())
}

/// Check whether the incoming p2p event is outdated, i.e. it refers to a block
/// that is already committed to the database. If so, log it and return `true`,
/// otherwise return `false`.
async fn is_outdated_p2p_event(storage: Storage, event: &Event) -> anyhow::Result<bool> {
    // Ignore messages that refer to already committed blocks.
    let incoming_height = event.height();
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;
    let db_txn = db_conn
        .transaction()
        .context("Creating database transaction")?;
    let latest_committed = db_txn.block_number(BlockId::Latest)?;
    if let Some(latest_committed) = latest_committed {
        if incoming_height <= latest_committed.get() {
            tracing::info!(
                "🖧  ⛔ ignoring incoming p2p event {} for height {incoming_height} because latest \
                 committed block is {latest_committed}",
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
    } = commitment;
    let proposal = Proposal {
        height: height_and_round.height(),
        round: height_and_round.round().into(),
        value: ConsensusValue(proposal_commitment),
        pol_round: Round::nil(),
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
fn commit_finalized_block(storage: Storage, finalized_block: FinalizedBlock) -> anyhow::Result<()> {
    let FinalizedBlock {
        header,
        state_update,
        transactions_and_receipts,
        events,
    } = finalized_block;

    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;
    let db_txn = db_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("Creating database transaction")?;
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
    db_txn.commit().context("Committing database transaction")?;

    Ok(())
}

/// Represents transactions received from the network that are waiting for
/// previous block to be committed before they can be executed. Also holds
/// optional proposal commitment and proposer address in case that the entire
/// proposal has been received.
#[derive(Debug, Clone, Default)]
struct DeferredExecution {
    pub transactions: Vec<p2p_proto::consensus::Transaction>,
    pub commitment: Option<ProposalCommitmentWithOrigin>,
}

/// Proposal commitment and the address of its proposer.
#[derive(Debug, Copy, Clone, Default)]
struct ProposalCommitmentWithOrigin {
    pub proposal_commitment: ProposalCommitment,
    pub proposer_address: ContractAddress,
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
async fn handle_incoming_proposal_part(
    chain_id: ChainId,
    height_and_round: HeightAndRound,
    proposal_part: ProposalPart,
    incoming_proposals_cache: &mut BTreeMap<u64, BTreeMap<Round, Vec<ProposalPart>>>,
    validator_cache: &mut ValidatorCache,
    deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
    storage: Storage,
) -> anyhow::Result<Option<ProposalCommitmentWithOrigin>> {
    let height = height_and_round.height();
    let round = height_and_round.round().into();
    let proposals_at_height = incoming_proposals_cache.entry(height).or_default();
    let parts = proposals_at_height.entry(round).or_default();
    match proposal_part {
        ProposalPart::Init(ref prop_init) => {
            if !parts.is_empty() {
                anyhow::bail!(
                    "Unexpected proposal Init for height and round {} at position {}",
                    height_and_round,
                    parts.len()
                );
            }

            let proposal_init = prop_init.clone();
            parts.push(proposal_part);
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

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let validator = validator_stage.try_into_block_info_stage()?;

            let block_info = block_info.clone();
            parts.push(proposal_part);
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

            tracing::debug!(
                "🖧  ⚙️ executing transaction batch for height and round {height_and_round}..."
            );

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let validator = validator_stage.try_into_transaction_batch_stage()?;

            let tx_batch = tx_batch.clone();
            parts.push(proposal_part);

            let validator = defer_or_execute_txn_batch(
                height_and_round,
                tx_batch,
                storage.clone(),
                validator,
                deferred_executions,
            )
            .await?;

            validator_cache.insert(
                height_and_round,
                ValidatorStage::TransactionBatch(validator),
            );
            Ok(None)
        }
        ProposalPart::ProposalCommitment(proposal_commitment) => {
            let validator_stage = validator_cache.remove(&height_and_round)?;
            let mut validator = validator_stage.try_into_transaction_batch_stage()?;

            validator.record_proposal_commitment(proposal_commitment)?;
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

            let validator_stage = validator_cache.remove(&height_and_round)?;
            let validator = validator_stage.try_into_transaction_batch_stage()?;

            if !validator.has_proposal_commitment() {
                anyhow::bail!(
                    "Transaction batch missing proposal commitment for height and round {}",
                    height_and_round
                );
            }

            parts.push(proposal_part);
            let ProposalPart::Init(ProposalInit { proposer, .. }) =
                parts.first().expect("Proposal Init")
            else {
                unreachable!("Proposal Init is inserted first");
            };

            let (validator, proposal_commitment) = defer_or_execute_proposal_fin(
                height_and_round,
                proposal_commitment,
                proposer,
                storage,
                validator,
                deferred_executions,
            )
            .await?;

            validator_cache.insert(height_and_round, validator);
            Ok(proposal_commitment)
        }
        ProposalPart::TransactionsFin(_transactions_fin) => {
            // TODO
            Ok(None)
        }
    }
}

/// Either defer or execute the given transaction batch depending on whether
/// the previous block is committed yet. If execution is deferred, the batch is
/// appended to the list of deferred transactions for the height and round. If
/// execution is performed, any previously deferred transactions for the height
/// and round are executed first, then the current batch is executed.
async fn defer_or_execute_txn_batch(
    height_and_round: HeightAndRound,
    tx_batch: Vec<p2p_proto::consensus::Transaction>,
    storage: Storage,
    mut validator: Box<crate::validator::ValidatorTransactionBatchStage>,
    deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
) -> Result<Box<crate::validator::ValidatorTransactionBatchStage>, anyhow::Error> {
    let validator = if should_defer_execution(height_and_round, storage).await? {
        tracing::debug!(
            "🖧  ⚙️ transaction batch execution for height and round {height_and_round} is deferred"
        );

        // The current transaction batch cannot be executed yet, because the
        // previous block is not committed yet. Defer its execution by appending
        // it to the list of deferred transactions for the height and round.
        deferred_executions
            .entry(height_and_round)
            .or_default()
            .transactions
            .extend(tx_batch);
        validator
    } else {
        // The current transaction batch can be executed now, because the
        // previous block is committed. First execute any deferred transactions
        // for the height and round, if any, then execute the current batch.
        let deferred = deferred_executions.remove(&height_and_round);
        let deferred_txns_len = deferred.as_ref().map_or(0, |d| d.transactions.len());

        // If there were deferred transactions, execute them first.
        let tx_batch = if let Some(DeferredExecution {
            mut transactions, ..
        }) = deferred
        {
            transactions.extend(tx_batch);
            transactions
        } else {
            tx_batch
        };

        let validator = util::task::spawn_blocking(move |_| {
            validator.execute_transactions(tx_batch)?;
            anyhow::Ok(validator)
        })
        .await??;

        tracing::debug!(
            "🖧  ⚙️ transaction batch execution for height and round {height_and_round} is \
             complete, additionally {deferred_txns_len} previously deferred transactions were \
             executed",
        );

        validator
    };
    Ok(validator)
}

/// Either defer or execute the proposal finalization depending on whether
/// the previous block is committed yet. If execution is deferred, the proposal
/// commitment and proposer address are stored for later finalization. If
/// execution is performed, any previously deferred transactions for the height
/// and round are executed first, then the proposal is finalized.
async fn defer_or_execute_proposal_fin(
    height_and_round: HeightAndRound,
    proposal_commitment: Hash,
    proposer: &Address,
    storage: Storage,
    mut validator: Box<crate::validator::ValidatorTransactionBatchStage>,
    deferred_executions: &mut HashMap<HeightAndRound, DeferredExecution>,
) -> anyhow::Result<(ValidatorStage, Option<ProposalCommitmentWithOrigin>)> {
    let commitment = ProposalCommitmentWithOrigin {
        proposal_commitment: ProposalCommitment(proposal_commitment.0),
        proposer_address: ContractAddress(proposer.0),
    };

    if should_defer_execution(height_and_round, storage).await? {
        // The proposal cannot be finalized yet, because the previous
        // block is not committed yet. Defer its finalization.
        tracing::debug!(
            "🖧  ⚙️ consensus finalize for height and round {height_and_round} is deferred"
        );

        deferred_executions
            .entry(height_and_round)
            .or_default()
            .commitment = Some(commitment);
        Ok((ValidatorStage::TransactionBatch(validator), None))
    } else {
        // The proposal can be finalized now, because the previous
        // block is committed. First execute any deferred transactions
        // for the height and round, if any, then finalize the proposal.
        let deferred = deferred_executions.remove(&height_and_round);
        let deferred_txns_len = deferred.as_ref().map_or(0, |d| d.transactions.len());

        let validator = util::task::spawn_blocking(move |_| {
            if let Some(DeferredExecution { transactions, .. }) = deferred {
                validator.execute_transactions(transactions)?;
            }
            let validator = validator.consensus_finalize(commitment.proposal_commitment)?;
            anyhow::Ok(validator)
        })
        .await??;

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

/// Determine whether execution of proposal parts for `height_and_round` should
/// be deferred because the previous block is not committed yet.
async fn should_defer_execution(
    height_and_round: HeightAndRound,
    storage: Storage,
) -> anyhow::Result<bool> {
    let defer = util::task::spawn_blocking(move |_| {
        let parent_block = height_and_round.height().checked_sub(1);
        let defer = if let Some(parent_block) = parent_block {
            let parent_block =
                BlockNumber::new(parent_block).context("Block number is larger than i64::MAX")?;
            let parent_block = BlockId::Number(parent_block);
            let mut db_conn = storage.connection()?;
            let db_txn = db_conn.transaction()?;
            let parent_committed = db_txn.block_exists(parent_block)?;
            !parent_committed
        } else {
            false
        };
        anyhow::Ok(defer)
    })
    .await??;
    Ok(defer)
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
