mod consensus_task;
mod p2p_task;

use std::path::PathBuf;

use p2p::consensus::{Client, Event, HeightAndRound};
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::{ChainId, ContractAddress};
use pathfinder_consensus::{ConsensusCommand, ConsensusEvent, NetworkMessage};
use pathfinder_storage::Storage;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use super::ConsensusTaskHandles;
use crate::config::ConsensusConfig;

pub fn start(
    config: ConsensusConfig,
    chain_id: ChainId,
    storage: Storage,
    wal_directory: PathBuf,
    p2p_client: Client,
    p2p_event_rx: mpsc::UnboundedReceiver<Event>,
) -> ConsensusTaskHandles {
    // Events that are produced by the P2P task and consumed by the consensus task.
    // TODO determine sufficient buffer size. 1 is not enough.
    let (tx_to_consensus, rx_from_p2p) = mpsc::channel::<ConsensusTaskEvent>(10);
    // Events that are produced by the consensus task and consumed by the P2P task.
    // TODO determine sufficient buffer size. 1 is not enough.
    let (tx_to_p2p, rx_from_consensus) = mpsc::channel::<P2PTaskEvent>(10);

    let consensus_p2p_event_processing_handle = p2p_task::spawn(
        chain_id,
        config.my_validator_address,
        p2p_client,
        storage,
        p2p_event_rx,
        tx_to_consensus,
        rx_from_consensus,
    );

    let (info_watch_tx, consensus_info_watch) = watch::channel(None);

    let consensus_engine_handle =
        consensus_task::spawn(config, wal_directory, tx_to_p2p, rx_from_p2p, info_watch_tx);

    ConsensusTaskHandles {
        consensus_p2p_event_processing_handle,
        consensus_engine_handle,
        consensus_info_watch: Some(consensus_info_watch),
    }
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
    CacheProposal(HeightAndRound, Vec<ProposalPart>),
    /// The consensus engine decided on the given height and we can finally
    /// remove the proposal that was cached for this height.
    RemoveProposal(u64),
    /// Consensus requested that we gossip a message via the P2P network.
    GossipRequest(NetworkMessage<ConsensusValue, ContractAddress>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ConsensusValue(p2p_proto::common::Hash);

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
