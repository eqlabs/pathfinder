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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::vec;

use anyhow::Context;
use p2p::consensus::HeightAndRound;
use p2p_proto::common::{Address, Hash, L1DataAvailabilityMode};
use p2p_proto::consensus::{
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
    ContractAddress,
    L2Block,
    ProposalCommitment,
    StarknetVersion,
};
use pathfinder_consensus::{
    Config,
    Consensus,
    ConsensusCommand,
    ConsensusEvent,
    Proposal,
    Round,
    ValidatorSet,
    ValidatorSetProvider,
};
use pathfinder_storage::{Storage, TransactionBehavior};
use tokio::sync::mpsc;

use super::fetch_proposers::L2ProposerSelector;
use super::fetch_validators::L2ValidatorSetProvider;
use super::{integration_testing, ConsensusTaskEvent, ConsensusValue, HeightExt, P2PTaskEvent};
use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;
use crate::validator::ValidatorBlockInfoStage;

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    chain_id: pathfinder_common::ChainId,
    config: ConsensusConfig,
    wal_directory: PathBuf,
    tx_to_p2p: mpsc::Sender<P2PTaskEvent>,
    mut rx_from_p2p: mpsc::Receiver<ConsensusTaskEvent>,
    main_storage: Storage,
    data_directory: &Path,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure: Option<InjectFailureConfig>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let data_directory = data_directory.to_path_buf();

    util::task::spawn(async move {
        let highest_committed = highest_committed(&main_storage)
            .context("Failed to read highest committed block at startup")?;
        // Get the validator address and validator set provider
        let validator_address = config.my_validator_address;
        let validator_set_provider =
            L2ValidatorSetProvider::new(main_storage.clone(), chain_id, config.clone());

        // Get the proposer selector
        let proposer_selector =
            L2ProposerSelector::new(main_storage.clone(), chain_id, config.clone());

        let mut consensus =
            Consensus::<ConsensusValue, ContractAddress, L2ProposerSelector>::recover_with_proposal_selector(
                Config::new(validator_address)
                    .with_history_depth(config.history_depth)
                    .with_wal_dir(wal_directory),
                // TODO use a dynamic validator set provider, once fetching the validator set from
                // the staking contract is implemented. Related issue: https://github.com/eqlabs/pathfinder/issues/2936
                Arc::new(validator_set_provider.clone()),
                proposer_selector,
                highest_committed,
            )?;

        // Compute the next height to work on using all available information:
        // - max_active_height: highest incomplete/active height being tracked
        // - last_decided_height: highest decided height (even if not actively tracked)
        // - highest_committed + 1: next height after what's been committed to main DB
        let mut next_height = [
            consensus.max_active_height().unwrap_or(0),
            consensus.last_decided_height().unwrap_or(0),
            highest_committed.map(|h| h + 1).unwrap_or(0),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        tracing::trace!(%next_height, "consensus task started with");

        start_height(
            &mut consensus,
            next_height,
            validator_set_provider
                .get_validator_set(next_height)
                .context("Failed to get validator set at startup")?,
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

                            let main_storage = main_storage.clone();
                            match util::task::spawn_blocking(move |_| {
                                create_empty_proposal(
                                    chain_id,
                                    height,
                                    round.into(),
                                    validator_address,
                                    main_storage,
                                )
                            })
                            .await
                            .context("Task join error during proposal creation")
                            .and_then(|result| result.context("Failed to create empty proposal"))
                            {
                                Ok((wire_proposal, finalized_block)) => {
                                    let ProposalFin {
                                        proposal_commitment,
                                    } = wire_proposal
                                        .last()
                                        .and_then(ProposalPart::as_fin)
                                        .context(format!(
                                            "Proposal for height {height} round {round} is \
                                             missing ProposalFin part"
                                        ))?;

                                    let value =
                                        ConsensusValue(ProposalCommitment(proposal_commitment.0));

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
                                        "🧠 ⚙️  {validator_address} handling command \
                                         Propose({proposal:?})"
                                    );

                                    consensus.handle_command(ConsensusCommand::Propose(proposal));
                                }
                                Err(e) => {
                                    // Proposal creation failed - skip this round but continue
                                    // consensus (we can still vote on other validators' proposals)
                                    //
                                    // NOTE: The consensus engine is event-driven and doesn't block
                                    // waiting for our proposal. If we're the designated proposer
                                    // and don't propose, the round will timeout and move to the
                                    // next round.
                                    tracing::warn!(
                                        validator = %validator_address,
                                        height = height,
                                        round = round,
                                        error = %e,
                                        "Failed to create proposal - skipping this round."
                                    );
                                }
                            }
                        }
                        // The consensus engine wants us to gossip a message via the P2P consensus
                        // network.
                        ConsensusEvent::Gossip(msg) => {
                            // TODO Sometimes the engine requests gossiping votes for heights that
                            // are a few steps behind the current height and have already been
                            // decided upon. This is due to the fact that `history_depth` in config
                            // is > 0 and we're not supporting round certificates yet. Once round
                            // certificates are supported this check can be removed.
                            if msg.height() >= next_height {
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
                        // Consensus has been reached for the given height and value.s
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

                            let old_next_height = next_height;
                            // Either move to the next height, or catch up if the decided height
                            // is ahead of our current next_height.
                            next_height = next_height
                                .max(height)
                                .checked_add(1)
                                .expect("Height never reaches i64::MAX");
                            if old_next_height != next_height {
                                tracing::trace!(%next_height, from_height=%old_next_height, "changing height to moving to");

                                start_height(
                                    &mut consensus,
                                    next_height,
                                    validator_set_provider
                                        .get_validator_set(next_height)
                                        .context("Failed to get validator set")?,
                                );
                            }
                        }
                        ConsensusEvent::Error(error) => {
                            if error.is_recoverable() {
                                // Recoverable errors: log and continue
                                // - WAL entry errors: can skip corrupted entries
                                // - Invalid peer messages: engine should handle, we continue
                                tracing::warn!(
                                    validator = %validator_address,
                                    error = %error,
                                    error_chain = %format!("{:#}", error),
                                    "Recoverable consensus error - continuing operation"
                                );
                                // Continue to next event - don't restart task
                            } else {
                                tracing::error!(
                                    validator = %validator_address,
                                    error = %error,
                                    error_chain = %format!("{:#}", error),
                                    "Fatal consensus error"
                                );
                                // Bail out, stop the consensus
                                return Err(
                                    anyhow::Error::from(error).context("Fatal consensus error")
                                );
                            }
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
                            // Commands from P2P should always be for current or future heights.
                            assert!(
                                cmd_height >= next_height,
                                "Received command for height {cmd_height} < current height \
                                 {next_height}"
                            );
                        }
                        // Sometimes messages for the next height are received before the engine
                        // decides upon the current height. In such case we need to ensure that a
                        // consensus engine is already started for this new height carried in those
                        // messages.
                        ConsensusCommand::Proposal(_) | ConsensusCommand::Vote(_) => {
                            // Make sure we don't start older heights that have already been decided
                            // upon, or are still in progress due to race conditions, or are too old
                            // to fit in history depth anyway.
                            let is_decided = consensus
                                .last_decided_height()
                                .is_some_and(|last_decided| cmd_height <= last_decided);
                            if is_decided {
                                tracing::debug!(
                                    lower_height=%cmd_height, %next_height, "🧠 🤷  Skipping start consensus for"
                                );
                            } else {
                                start_height(
                                    &mut consensus,
                                    cmd_height,
                                    validator_set_provider
                                        .get_validator_set(cmd_height)
                                        .context("Failed to get validator set")?,
                                );
                            }
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

/// Reads the highest committed block number from main storage.
fn highest_committed(main_storage: &Storage) -> anyhow::Result<Option<u64>> {
    let mut db_conn = main_storage
        .connection()
        .context("Failed to create database connection for reading highest committed block")?;
    let db_txn = db_conn
        .transaction()
        .context("Failed to create database transaction for reading highest committed block")?;
    let highest_committed = db_txn
        .block_number(BlockId::Latest)
        .context("Failed to query latest block number")?
        .map(|x| x.get());
    Ok(highest_committed)
}

/// Starts consensus for the given height if not already active.
fn start_height(
    consensus: &mut Consensus<ConsensusValue, ContractAddress, L2ProposerSelector>,
    height: u64,
    validator_set: ValidatorSet<ContractAddress>,
) {
    if !consensus.is_height_active(height) {
        tracing::trace!(%height, "🧠 🚀  Starting consensus for");
        consensus.handle_command(ConsensusCommand::StartHeight(height, validator_set));
    } else {
        tracing::trace!(%height, "🧠 🤷  Consensus already active for");
    }
}

/// Create an empty proposal for the given height and round. Returns proposal
/// parts that can be gossiped via P2P network and the finalized block that
/// corresponds to this proposal.
///
/// https://github.com/starknet-io/starknet-p2p-specs/blob/main/p2p/proto/consensus/consensus.md#empty-proposals
pub(crate) fn create_empty_proposal(
    chain_id: ChainId,
    height: u64,
    round: Round,
    proposer: ContractAddress,
    main_storage: Storage,
) -> anyhow::Result<(Vec<ProposalPart>, L2Block)> {
    let round = round.as_u32().context(format!(
        "Attempted to create proposal with Nil round at height {height}"
    ))?;
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
    let current_block = BlockNumber::new(height).context("Invalid height")?;
    let parent_proposal_commitment_hash = if let Some(parent_number) = current_block.parent() {
        let mut db_conn = main_storage
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

    // The only version handled by consensus, so far
    let starknet_version = StarknetVersion::new(0, 14, 0, 0);

    // Empty proposal is strictly defined in the spec:
    // https://github.com/starknet-io/starknet-p2p-specs/blob/main/p2p/proto/consensus/consensus.md#empty-proposals
    let proposal_commitment = ProposalCommitmentProto {
        block_number: height,
        parent_commitment: Hash(parent_proposal_commitment_hash.0),
        builder: proposer,
        timestamp,
        protocol_version: starknet_version.to_string(),
        // TODO required by the spec
        old_state_root: Default::default(),
        // TODO required by the spec
        version_constant_commitment: Default::default(),
        state_diff_commitment: Hash::ZERO,
        transaction_commitment: Hash::ZERO,
        event_commitment: Hash::ZERO,
        receipt_commitment: Hash::ZERO,
        // TODO should contain len of version_constant_commitment
        concatenated_counts: Default::default(),
        l1_gas_price_fri: 0,
        l1_data_gas_price_fri: 0,
        l2_gas_price_fri: 0,
        l2_gas_used: 0,
        // TODO keep the value from the last block as per spec
        next_l2_gas_price_fri: 0,
        // Equivalent to zero on the wire
        l1_da_mode: L1DataAvailabilityMode::default(),
    };

    let validator = ValidatorBlockInfoStage::new(chain_id, proposal_init.clone())
        .context("Failed to create validator block info stage")?
        .verify_proposal_commitment(&proposal_commitment)
        .context("Failed to verify proposal commitment")?;
    let mut db_conn = main_storage
        .connection()
        .context("Creating database connection")?;
    let db_txn = db_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("Create database transaction")?;
    let readonly_storage = main_storage.clone();
    let finalized_block = validator
        .finalize(
            &db_txn,
            readonly_storage,
            false, // Do not verify hashes for empty proposals
        )
        .context("Failed to finalize block")?;
    db_txn
        .commit()
        .context("Failed to commit finalized block")?;
    let proposal_commitment_hash = Hash(finalized_block.header.state_diff_commitment.0);

    Ok((
        vec![
            ProposalPart::Init(proposal_init),
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
            proposal_parts.len() == 3,
            "Empty proposal should have exactly Init, ProposalCommitment, and Fin"
        );

        // Verify it starts with Init
        assert!(
            matches!(proposal_parts[0], ProposalPart::Init(_)),
            "First part should be ProposalInit"
        );

        // Verify it has ProposalCommitment
        assert!(
            matches!(proposal_parts[1], ProposalPart::ProposalCommitment(_)),
            "Second part should be ProposalCommitment"
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
