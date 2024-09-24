#![deny(rust_2018_idioms)]
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::channel::mpsc::{Receiver as ResponseReceiver, Sender as ResponseSender};
use ipnet::IpNet;
use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::kad::RecordKey;
use libp2p::{Multiaddr, PeerId};
use main_loop::MainLoop;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse, NewBlock};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::{BlockHash, BlockNumber, ChainId};
use peers::Peer;
use tokio::sync::{mpsc, oneshot};

mod behaviour;
mod builder;
pub mod client;
mod main_loop;
mod peer_data;
mod peers;
mod secret;
mod sync;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
mod transport;

pub use behaviour::kademlia_protocol_name;
use builder::Builder;
use client::peer_aware::Client;
pub use libp2p;
pub use peer_data::PeerData;
pub use sync::protocol::PROTOCOLS;

pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> (Client, EventReceiver, MainLoop) {
    Builder::new(keypair, cfg, chain_id).build()
}

/// P2P limitations.
#[derive(Debug, Clone)]
pub struct Config {
    /// A direct (not relayed) peer can only connect once in this period.
    pub direct_connection_timeout: Duration,
    /// A relayed peer can only connect once in this period.
    pub relay_connection_timeout: Duration,
    /// Maximum number of direct (non-relayed) inbound peers.
    pub max_inbound_direct_peers: usize,
    /// Maximum number of relayed inbound peers.
    pub max_inbound_relayed_peers: usize,
    /// Maximum number of outbound peers.
    pub max_outbound_peers: usize,
    /// How long to prevent evicted peers from reconnecting.
    pub eviction_timeout: Duration,
    pub ip_whitelist: Vec<IpNet>,
    /// If the number of peers is below the low watermark, the node will attempt
    /// periodic bootstrapping at this interval.
    pub bootstrap_period: Duration,
    pub inbound_connections_rate_limit: RateLimit,
    /// Custom protocol name for Kademlia
    pub kad_name: Option<String>,
    /// Request timeout for p2p-stream
    pub stream_timeout: Duration,
    /// Applies to each of the p2p-stream protocols separately
    pub max_concurrent_streams: usize,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub max: usize,
    pub interval: Duration,
}

pub type HeadTx = tokio::sync::watch::Sender<Option<(BlockNumber, BlockHash)>>;
pub type HeadRx = tokio::sync::watch::Receiver<Option<(BlockNumber, BlockHash)>>;

type EmptyResultSender = oneshot::Sender<anyhow::Result<()>>;

#[derive(Debug)]
enum Command {
    StarListening {
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    Dial {
        peer_id: PeerId,
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    Disconnect {
        peer_id: PeerId,
        sender: EmptyResultSender,
    },
    ProvideCapability {
        capability: String,
        sender: EmptyResultSender,
    },
    GetCapabilityProviders {
        capability: String,
        sender: mpsc::Sender<anyhow::Result<HashSet<PeerId>>>,
    },
    GetClosestPeers {
        peer: PeerId,
        sender: mpsc::Sender<anyhow::Result<Vec<PeerId>>>,
    },
    SubscribeTopic {
        topic: IdentTopic,
        sender: EmptyResultSender,
    },
    SendHeadersSyncRequest {
        peer_id: PeerId,
        request: BlockHeadersRequest,
        sender: oneshot::Sender<
            anyhow::Result<ResponseReceiver<std::io::Result<BlockHeadersResponse>>>,
        >,
    },
    SendClassesSyncRequest {
        peer_id: PeerId,
        request: ClassesRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<ClassesResponse>>>>,
    },
    SendStateDiffsSyncRequest {
        peer_id: PeerId,
        request: StateDiffsRequest,
        sender:
            oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<StateDiffsResponse>>>>,
    },
    SendTransactionsSyncRequest {
        peer_id: PeerId,
        request: TransactionsRequest,
        sender: oneshot::Sender<
            anyhow::Result<ResponseReceiver<std::io::Result<TransactionsResponse>>>,
        >,
    },
    SendEventsSyncRequest {
        peer_id: PeerId,
        request: EventsRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<EventsResponse>>>>,
    },
    PublishPropagationMessage {
        topic: IdentTopic,
        new_block: NewBlock,
        sender: EmptyResultSender,
    },
    NotUseful {
        peer_id: PeerId,
        sender: oneshot::Sender<()>,
    },
    /// For testing purposes only
    _Test(TestCommand),
}

#[derive(Debug)]
pub enum TestCommand {
    GetPeersFromDHT(oneshot::Sender<HashSet<PeerId>>),
    GetConnectedPeers(oneshot::Sender<HashMap<PeerId, Peer>>),
}

#[derive(Debug)]
pub enum Event {
    SyncPeerConnected {
        peer_id: PeerId,
    },
    InboundHeadersSyncRequest {
        from: PeerId,
        request: BlockHeadersRequest,
        channel: ResponseSender<BlockHeadersResponse>,
    },
    InboundClassesSyncRequest {
        from: PeerId,
        request: ClassesRequest,
        channel: ResponseSender<ClassesResponse>,
    },
    InboundStateDiffsSyncRequest {
        from: PeerId,
        request: StateDiffsRequest,
        channel: ResponseSender<StateDiffsResponse>,
    },
    InboundTransactionsSyncRequest {
        from: PeerId,
        request: TransactionsRequest,
        channel: ResponseSender<TransactionsResponse>,
    },
    InboundEventsSyncRequest {
        from: PeerId,
        request: EventsRequest,
        channel: ResponseSender<EventsResponse>,
    },
    BlockPropagation {
        from: PeerId,
        new_block: NewBlock,
    },
    /// For testing purposes only
    Test(TestEvent),
}

#[derive(Debug)]
pub enum TestEvent {
    NewListenAddress(Multiaddr),
    KademliaBootstrapStarted,
    KademliaBootstrapCompleted(Result<PeerId, PeerId>),
    StartProvidingCompleted(Result<RecordKey, RecordKey>),
    ConnectionEstablished { outbound: bool, remote: PeerId },
    ConnectionClosed { remote: PeerId },
    Subscribed { remote: PeerId, topic: String },
    PeerAddedToDHT { remote: PeerId },
    Dummy,
}

pub type EventReceiver = mpsc::Receiver<Event>;
