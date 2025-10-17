mod batch_execution;
mod consensus_task;
mod conv;
mod dto;
mod fetch_proposers;
mod fetch_validators;
mod p2p_task;
mod persist_proposals;

#[cfg(test)]
mod test_helpers;

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::Context;
use p2p::consensus::{Event, HeightAndRound};
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::{ChainId, ContractAddress, ProposalCommitment};
use pathfinder_consensus::{ConsensusCommand, ConsensusEvent, NetworkMessage};
use pathfinder_storage::pruning::BlockchainHistoryMode;
use pathfinder_storage::{JournalMode, Storage, TriePruneMode};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use super::{ConsensusChannels, ConsensusTaskHandles};
use crate::config::ConsensusConfig;
use crate::sync::catch_up::BlockData;
use crate::validator::FinalizedBlock;

#[allow(clippy::too_many_arguments)]
pub fn start(
    config: ConsensusConfig,
    storage: Storage,
    chain_id: ChainId,
    p2p_consensus_client: p2p::consensus::Client,
    p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    wal_directory: PathBuf,
    data_directory: &Path,
    verify_tree_hashes: bool,
) -> ConsensusTaskHandles {
    // Events that are produced by the P2P task and consumed by the consensus task.
    // TODO determine sufficient buffer size. 1 is not enough.
    let (tx_to_consensus, rx_from_p2p) = mpsc::channel::<ConsensusTaskEvent>(10);
    // Events that are produced by the consensus task and consumed by the P2P task.
    // TODO determine sufficient buffer size. 1 is not enough.
    let (tx_to_p2p, rx_from_consensus) = mpsc::channel::<P2PTaskEvent>(10);
    // Channel between the P2P and catch-up sync task. Sync task sends synced block
    // data to the P2P task to store them. Done this way to keep consensus
    // related database writes in a single task (P2P).
    let (store_synced_block_tx, store_synced_block_rx) = mpsc::channel::<BlockData>(10);

    let consensus_storage =
        open_consensus_storage(data_directory).expect("Consensus storage cannot be opened");

    let consensus_p2p_event_processing_handle = p2p_task::spawn(
        chain_id,
        config.my_validator_address,
        p2p_consensus_client,
        storage.clone(),
        p2p_event_rx,
        store_synced_block_rx,
        tx_to_consensus,
        rx_from_consensus,
        consensus_storage.clone(),
        verify_tree_hashes,
    );

    let (catch_up_tx, catch_up_rx) = watch::channel(None);
    let (info_watch_tx, consensus_info_watch) = watch::channel(None);

    let consensus_engine_handle = consensus_task::spawn(
        chain_id,
        config,
        wal_directory,
        tx_to_p2p,
        rx_from_p2p,
        catch_up_tx,
        info_watch_tx,
        consensus_storage,
        storage,
    );

    ConsensusTaskHandles {
        consensus_p2p_event_processing_handle,
        consensus_engine_handle,
        consensus_channels: Some(ConsensusChannels {
            consensus_info_watch,
            catch_up_rx,
            store_synced_block_tx,
        }),
    }
}

fn open_consensus_storage(data_directory: &Path) -> anyhow::Result<Storage> {
    let storage_manager =
        pathfinder_storage::StorageBuilder::file(data_directory.join("consensus.sqlite")) // TODO: https://github.com/eqlabs/pathfinder/issues/3047
            .journal_mode(JournalMode::WAL)
            .trie_prune_mode(Some(TriePruneMode::Archive))
            .blockchain_history_mode(Some(BlockchainHistoryMode::Archive))
            .migrate()?;
    let available_parallelism = std::thread::available_parallelism()?;
    let consensus_storage = storage_manager
        .create_pool(NonZeroU32::new(5 + available_parallelism.get() as u32).unwrap())?;
    let mut db_conn = consensus_storage
        .connection()
        .context("Creating database connection")?;
    let db_tx = db_conn
        .transaction()
        .context("Creating database transaction")?;
    db_tx.ensure_consensus_proposals_table_exists()?;
    db_tx.commit()?;
    Ok(consensus_storage)
}

/// Events handled by the consensus task.
enum ConsensusTaskEvent {
    /// The consensus engine informs us about an event that it wants us to
    /// handle.
    Event(ConsensusEvent<ConsensusValue, ContractAddress>),
    /// We received an event from the P2P network which has impact on
    /// consensus, so we issue a command to the consensus engine.
    CommandFromP2P(ConsensusCommand<ConsensusValue, ContractAddress>),
}

/// Events handled by the p2p task.
#[allow(clippy::large_enum_variant)]
enum P2PTaskEvent {
    /// An event coming from the P2P network (from the consensus P2P network
    /// main loop).
    P2PEvent(Event),
    /// The consensus engine requested that we produce a proposal, so we
    /// create it, feed it back to the consensus engine, and we must
    /// cache it for gossiping when the engine requests so.
    CacheProposal(HeightAndRound, Vec<ProposalPart>, FinalizedBlock),
    /// Consensus requested that we gossip a message via the P2P network.
    GossipRequest(NetworkMessage<ConsensusValue, ContractAddress>),
    /// Commit the given block and state update to the database. All proposals
    /// for this height are removed from the cache.
    CommitBlock(HeightAndRound, ConsensusValue),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ConsensusValue(ProposalCommitment);

impl std::fmt::Display for ConsensusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

trait HeightExt {
    fn height(&self) -> u64;
}

impl HeightExt for NetworkMessage<ConsensusValue, ContractAddress> {
    fn height(&self) -> u64 {
        match self {
            NetworkMessage::Proposal(proposal) => proposal.proposal.height,
            NetworkMessage::Vote(vote) => vote.vote.height,
        }
    }
}
