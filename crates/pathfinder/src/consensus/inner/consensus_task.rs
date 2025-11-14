//! This task:
//! 1. handles requests from the consensus engine, for example to propose a new
//!    block
//! 2. handles requests from the P2P task, for example a vote or a proposal has
//!    been received and needs to be processed by the consensus engine
//! 3. issues commands to the consensus engine, for example to start a new
//!    height, or a vote has been received from the P2P network and needs to be
//!    processed by the consensus engine
//! 4. issues commands to the P2P task, for example to gossip a proposal or a
//!    vote

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::vec;

use anyhow::Context;
use p2p::consensus::HeightAndRound;
use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
use p2p_proto::consensus::{
    BlockInfo,
    ProposalCommitment as ProposalCommitmentProto,
    ProposalFin,
    ProposalInit,
    ProposalPart,
};
use pathfinder_common::{
    BlockHash,
    BlockId,
    BlockNumber,
    ChainId,
    ConsensusInfo,
    ContractAddress,
    ProposalCommitment,
    StarknetVersion,
};
use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    NetworkMessage,
    Proposal,
    Round,
    SignedVote,
    ValidatorSet,
    ValidatorSetProvider,
};
use pathfinder_storage::{Storage, TransactionBehavior};
use tokio::sync::{mpsc, watch};

use super::fetch_proposers::L2ProposerSelector;
use super::fetch_validators::L2ValidatorSetProvider;
use super::{integration_testing, ConsensusTaskEvent, ConsensusValue, HeightExt, P2PTaskEvent};
use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;
use crate::state::block_hash::{
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
};
use crate::validator::{FinalizedBlock, ValidatorBlockInfoStage};

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    chain_id: pathfinder_common::ChainId,
    config: ConsensusConfig,
    wal_directory: PathBuf,
    tx_to_p2p: mpsc::Sender<P2PTaskEvent>,
    mut rx_from_p2p: mpsc::Receiver<ConsensusTaskEvent>,
    info_watch_tx: watch::Sender<Option<ConsensusInfo>>,
    storage: Storage,
    fake_proposals_storage: Storage,
    data_directory: &Path,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure: Option<InjectFailureConfig>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let data_directory = data_directory.to_path_buf();

    util::task::spawn(async move {
        let highest_finalized = highest_finalized(&storage)?;
        // Get the validator address and validator set provider
        let validator_address = config.my_validator_address;
        let validator_set_provider =
            L2ValidatorSetProvider::new(storage.clone(), chain_id, config.clone());

        // Get the proposer selector
        let proposer_selector = L2ProposerSelector::new(storage.clone(), chain_id, config.clone());

        let mut consensus =
            Consensus::<ConsensusValue, ContractAddress, L2ProposerSelector>::recover_with_proposal_selector(
                Config::new(validator_address)
                    .with_wal_dir(wal_directory),
                // TODO use a dynamic validator set provider, once fetching the validator set from
                // the staking contract is implemented. Related issue: https://github.com/eqlabs/pathfinder/issues/2936
                Arc::new(validator_set_provider.clone()),
                proposer_selector,
                highest_finalized,
            )?;

        // Compute the next height to work on using all available information:
        // - max_active_height: highest incomplete/active height being tracked
        // - last_decided_height: highest decided height (even if not actively tracked)
        // - highest_finalized + 1: next height after what's been committed to DB
        let mut next_height = [
            consensus.max_active_height().unwrap_or(0),
            consensus.last_decided_height().unwrap_or(0),
            highest_finalized.map(|h| h + 1).unwrap_or(0),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        // A validator that joins the consensus network and is lagging behind will vote
        // Nil for its current height, because the consensus network is already at a
        // higher height. This is a workaround for the missing sync/catch-up mechanism.
        // Related issue: https://github.com/eqlabs/pathfinder/issues/2934
        let mut last_nil_vote_height = None;

        // TODO FIXME this should be taken from WAL & DB
        // This set is used to make sure we only start each height once and is used when
        // a new height needs to be started upon a proposal or vote for H arriving
        // before H-1 has been decided upon. Such race conditions occur very often in a
        // network with low latency.
        let mut started_heights = HashSet::new();

        start_height(
            &mut consensus,
            &mut started_heights,
            next_height,
            validator_set_provider.get_validator_set(next_height)?,
        );

        loop {
            let consensus_task_event = tokio::select! {
                consensus_event = consensus.next_event() => {
                    match consensus_event {
                        Some(event) => ConsensusTaskEvent::Event(event),
                        None => {
                            continue;
                        }
                    }
                }
                from_p2p = rx_from_p2p.recv() => {
                    from_p2p.expect("Consensus task event receiver not to be dropped")
                }
            };

            match consensus_task_event {
                ConsensusTaskEvent::Event(event) => {
                    tracing::info!("🧠 ℹ️  {validator_address} consensus event: {event:?}");

                    match event {
                        // The consensus engine wants us to propose a block for the given height and
                        // round. We create a proposal, feed its commitment back to the engine, and
                        // cache the proposal for gossiping when the engine requests so.
                        ConsensusEvent::RequestProposal { height, round, .. } => {
                            tracing::info!(
                                "🧠 🔍 {validator_address} is proposing at height {height}, round \
                                 {round}",
                            );

                            let fake_proposals_storage = fake_proposals_storage.clone();
                            let (wire_proposal, finalized_block) =
                                util::task::spawn_blocking(move |_| {
                                    create_empty_proposal(
                                        chain_id,
                                        height,
                                        round.into(),
                                        validator_address,
                                        fake_proposals_storage,
                                    )
                                })
                                .await?
                                .context("Creating empty proposal")?;

                            let ProposalFin {
                                proposal_commitment,
                            } = wire_proposal.last().and_then(ProposalPart::as_fin).expect(
                                "Proposals produced by our node are always coherent and complete",
                            );

                            let value = ConsensusValue(ProposalCommitment(proposal_commitment.0));

                            tx_to_p2p
                                .send(P2PTaskEvent::CacheProposal(
                                    HeightAndRound::new(height, round),
                                    wire_proposal,
                                    finalized_block,
                                ))
                                .await
                                .expect("Cache proposal receiver not to be dropped");

                            let proposal = Proposal {
                                height,
                                round: round.into(),
                                proposer: validator_address,
                                pol_round: Round::nil(),
                                value,
                            };

                            tracing::info!(
                                "🧠 ⚙️  {validator_address} handling command Propose({proposal:?})"
                            );

                            consensus.handle_command(ConsensusCommand::Propose(proposal));
                        }
                        // The consensus engine wants us to gossip a message via the P2P consensus
                        // network.
                        ConsensusEvent::Gossip(msg) => {
                            // TODO Sometimes the engine requests gossiping votes for heights that
                            // are a few steps behind the current height and have already been
                            // decided upon. This is due to the fact that `history_depth` in config
                            // is > 0 and we're not supporting round certificates yet. Setting
                            // history depth to a low value (or 0) should mitigate this issue for
                            // now.
                            if msg.height() >= next_height {
                                // Record the highest height at which we voted Nil as it may be an
                                // indication that we're lagging behind the consensus network.
                                if let NetworkMessage::Vote(SignedVote { vote, .. }) = &msg {
                                    if vote.is_nil() {
                                        last_nil_vote_height = Some(
                                            vote.height
                                                .max(last_nil_vote_height.unwrap_or_default()),
                                        );
                                    }
                                }

                                tx_to_p2p
                                    .send(P2PTaskEvent::GossipRequest(msg))
                                    .await
                                    .expect("Gossip request receiver not to be dropped");
                            } else {
                                tracing::debug!(
                                    "🧠 🤷 Ignoring gossip request for height {} < {next_height}",
                                    msg.height()
                                );
                            }
                        }
                        // Consensus has been reached for the given height and value.
                        ConsensusEvent::Decision {
                            height,
                            round,
                            value,
                        } => {
                            tracing::info!(
                                "🧠 ✅ {validator_address} decided on {value} at height {height} \
                                 round {round}",
                            );

                            // Does nothing in production builds.
                            integration_testing::debug_fail_on_decided(
                                height,
                                inject_failure,
                                &data_directory,
                            );

                            let height_and_round = HeightAndRound::new(height, round);

                            tx_to_p2p
                                .send(P2PTaskEvent::CommitBlock(height_and_round, value.clone()))
                                .await
                                .expect("Commit block receiver not to be dropped");

                            info_watch_tx.send_if_modified(|info| {
                                let do_update = match info {
                                    Some(info) => {
                                        height > info.highest_decided_height.get()
                                            || value.0 != info.highest_decided_value
                                    }
                                    None => true,
                                };
                                if do_update {
                                    if let Some(height) = BlockNumber::new(height) {
                                        *info = Some(ConsensusInfo {
                                            highest_decided_height: height,
                                            highest_decided_value: value.0,
                                        });
                                    } else {
                                        tracing::error!(
                                            "Height {height} is out of range for BlockNumber"
                                        );
                                        *info = None;
                                    }
                                }
                                do_update
                            });

                            assert!(started_heights.remove(&height));

                            if height == next_height {
                                next_height = next_height
                                    .checked_add(1)
                                    .expect("Height never reaches i64::MAX");
                                start_height(
                                    &mut consensus,
                                    &mut started_heights,
                                    next_height,
                                    validator_set_provider.get_validator_set(next_height)?,
                                );
                            }
                        }
                        ConsensusEvent::Error(error) => {
                            // TODO are all of these errors fatal or recoverable?
                            // What is the best way to handle them?
                            tracing::error!("🧠 ❌ {validator_address} consensus error: {error:?}");
                            // Bail out, stop the consensus
                            return Err(error);
                        }
                    }
                }
                ConsensusTaskEvent::CommandFromP2P(cmd) => {
                    tracing::info!("🧠 ⚙️  {validator_address} handling command {cmd:?}");

                    let cmd_height = cmd.height();
                    match &cmd {
                        // There were no p2p messages for a height higher than the current height,
                        // so we did start a new height upon successful decision, before any p2p
                        // messages for the new height were received.
                        ConsensusCommand::StartHeight(..) | ConsensusCommand::Propose(_) => {
                            assert!(cmd_height >= next_height);
                            assert!(started_heights.contains(&cmd_height));
                        }
                        // Sometimes messages for the next height are received before the engine
                        // decides upon the current height. In such case we need to ensure that a
                        // consensus engine is already started for this new height carried in those
                        // messages.
                        ConsensusCommand::Proposal(_) | ConsensusCommand::Vote(_) => {
                            // TODO catch up with the current height of the consensus network using
                            // sync, for the time being just observe the height in the rebroadcasted
                            // votes or in the proposals.
                            let last_nil = last_nil_vote_height.take();

                            if let Some(last_nil) = last_nil {
                                if cmd_height > next_height && cmd_height > last_nil {
                                    tracing::info!(
                                        "🧠 ⏩  {validator_address} catching up current height \
                                         {next_height} -> {cmd_height}",
                                    );
                                    next_height = cmd_height;
                                } else {
                                    last_nil_vote_height = Some(last_nil);
                                }
                            }

                            start_height(
                                &mut consensus,
                                &mut started_heights,
                                cmd_height,
                                validator_set_provider.get_validator_set(cmd_height)?,
                            );
                        }
                    }

                    consensus.handle_command(cmd);
                }
            }

            // Malachite is coroutine based, otherwise we starve other futures
            // in the outer select.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

fn highest_finalized(storage: &Storage) -> anyhow::Result<Option<u64>> {
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;
    let db_txn = db_conn
        .transaction()
        .context("Creating database transaction")?;
    let highest_finalized = db_txn.block_number(BlockId::Latest)?.map(|x| x.get());
    Ok(highest_finalized)
}

fn start_height(
    consensus: &mut Consensus<ConsensusValue, ContractAddress, L2ProposerSelector>,
    started_heights: &mut HashSet<u64>,
    height: u64,
    validator_set: ValidatorSet<ContractAddress>,
) {
    if !started_heights.contains(&height) {
        started_heights.insert(height);
        consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
    }
}

/// Create an empty proposal for the given height and round. Returns
/// proposal parts that can be gossiped via P2P network and the
/// finalized block that corresponds to this proposal.
fn create_empty_proposal(
    chain_id: ChainId,
    height: u64,
    round: Round,
    proposer: ContractAddress,
    storage: Storage,
) -> anyhow::Result<(Vec<ProposalPart>, FinalizedBlock)> {
    let round = round.as_u32().expect("Round not to be Nil???");
    let proposer = Address(proposer.0);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let proposal_init = ProposalInit {
        block_number: height,
        round,
        valid_round: None,
        proposer,
    };
    let block_info = BlockInfo {
        block_number: height,
        timestamp,
        builder: proposer,
        l1_da_mode: L1DataAvailabilityMode::Calldata,
        l2_gas_price_fri: 1,
        l1_gas_price_wei: 1_000_000_000,
        l1_data_gas_price_wei: 1,
        eth_to_strk_rate: 1_000_000_000,
    };
    let current_block = BlockNumber::new(height).context("Invalid height")?;
    let parent_proposal_commitment_hash = if let Some(parent_number) = current_block.parent() {
        let mut db_conn = storage
            .connection()
            .context("Creating database connection")?;
        let db_txn = db_conn
            .transaction()
            .context("Create database transaction")?;
        // TODO it should probably be not a block hash but the state diff commitment of
        // the parent block
        let hash = db_txn.block_hash(parent_number.into())?.unwrap_or_default();
        db_txn.commit()?;
        hash
    } else {
        BlockHash::ZERO
    };

    let validator = ValidatorBlockInfoStage::new(chain_id, proposal_init.clone())?
        .validate_consensus_block_info(block_info.clone(), storage.clone())?;
    let validator = validator.consensus_finalize0()?;
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;
    let db_txn = db_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("Create database transaction")?;
    let finalized_block = validator.finalize(db_txn, storage.clone())?;
    let proposal_commitment_hash = Hash(finalized_block.header.state_diff_commitment.0);

    // The only version handled by consensus, so far
    let starknet_version = StarknetVersion::new(0, 14, 0, 0);
    let transactions = vec![];
    let transaction_commitment = calculate_transaction_commitment(&transactions, starknet_version)?;
    let transaction_events = vec![];
    let event_commitment = calculate_event_commitment(&transaction_events, starknet_version)?;
    let receipts = vec![];
    let receipt_commitment = calculate_receipt_commitment(&receipts)?;
    let proposal_commitment = ProposalCommitmentProto {
      block_number: height,
        parent_commitment: Hash(parent_proposal_commitment_hash.0),
        builder: proposer,
        timestamp,
        protocol_version: starknet_version.to_string(),
        old_state_root: Default::default(), // not used by 0.14.0
        version_constant_commitment: Default::default(), // TODO
        state_diff_commitment: proposal_commitment_hash,
        transaction_commitment: Hash(transaction_commitment.0),
        event_commitment: Hash(event_commitment.0),
        receipt_commitment: Hash(receipt_commitment.0),
        concatenated_counts: Default::default(), // should be the sum of lengths of inputs to *_commitment
        l1_gas_price_fri: 1000,
        l1_data_gas_price_fri: 2000,
        l2_gas_price_fri: 3000,
        l2_gas_used: 4000,
        next_l2_gas_price_fri: 3000,
        l1_da_mode: L1DataAvailabilityMode::Calldata,
    };

    Ok((
        vec![
            ProposalPart::Init(proposal_init),
            ProposalPart::BlockInfo(block_info),
            // Note: Per spec, empty proposals skip TransactionBatch entirely.
            ProposalPart::ProposalCommitment(proposal_commitment),
            ProposalPart::Fin(ProposalFin {
                proposal_commitment: proposal_commitment_hash,
            }),
        ],
        finalized_block,
    ))
}

#[cfg(test)]
mod tests {
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;

    use super::*;

    /// Tests that create_empty_proposal successfully creates an empty proposal
    /// and finalizes it without requiring an executor.
    #[test]
    fn test_create_empty_proposal() {
        let storage = StorageBuilder::in_tempdir().expect("Failed to create temp database");
        let chain_id = ChainId::SEPOLIA_TESTNET;
        let height = 0u64;
        let round = Round::new(0);
        let proposer = ContractAddress::new_or_panic(Felt::from_hex_str("0x1").unwrap());

        // Create an empty proposal - this should succeed without an executor
        let (proposal_parts, finalized_block) =
            create_empty_proposal(chain_id, height, round, proposer, storage)
                .expect("create_empty_proposal should succeed for empty proposals");

        // Verify proposal structure
        assert!(
            proposal_parts.len() >= 4,
            "Empty proposal should have at least Init, BlockInfo, ProposalCommitment, and Fin"
        );

        // Verify it starts with Init
        assert!(
            matches!(proposal_parts[0], ProposalPart::Init(_)),
            "First part should be ProposalInit"
        );

        // Verify it has BlockInfo
        assert!(
            matches!(proposal_parts[1], ProposalPart::BlockInfo(_)),
            "Second part should be BlockInfo"
        );

        // Verify it ends with Fin
        let last_part = proposal_parts.last().expect("Proposal should have parts");
        assert!(
            matches!(last_part, ProposalPart::Fin(_)),
            "Last part should be ProposalFin"
        );

        // Verify finalized block has empty state
        assert_eq!(
            finalized_block.header.transaction_count, 0,
            "Empty proposal should have 0 transaction count"
        );
        assert_eq!(
            finalized_block.header.event_count, 0,
            "Empty proposal should have 0 event count"
        );
        assert_eq!(
            finalized_block.state_update.contract_updates.len(),
            0,
            "Empty proposal should have no contract updates"
        );
        assert_eq!(
            finalized_block.state_update.system_contract_updates.len(),
            0,
            "Empty proposal should have no system contract updates"
        );
        assert_eq!(
            finalized_block.transactions_and_receipts.len(),
            0,
            "Empty proposal should have no transactions"
        );
    }
}
