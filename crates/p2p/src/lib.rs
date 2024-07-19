#![deny(rust_2018_idioms)]
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::channel::mpsc::{Receiver as ResponseReceiver, Sender as ResponseSender};
use ipnet::IpNet;
use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::kad::RecordKey;
use libp2p::{swarm, Multiaddr, PeerId, Swarm};
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse, NewBlock};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::{BlockHash, BlockNumber, ChainId};
use peers::Peer;
use tokio::sync::{mpsc, oneshot};

mod behaviour;
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
use client::peer_aware::Client;
pub use libp2p;
use main_loop::MainLoop;
pub use peer_data::PeerData;
pub use sync::protocol::PROTOCOLS;

pub fn new(keypair: Keypair, cfg: Config, chain_id: ChainId) -> (Client, EventReceiver, MainLoop) {
    let local_peer_id = keypair.public().to_peer_id();

    let (command_sender, command_receiver) = mpsc::channel(1);
    let client = Client::new(command_sender, local_peer_id);

    let (behaviour, relay_transport) =
        behaviour::Behaviour::new(&keypair, chain_id, client.clone(), cfg.clone());

    let swarm = Swarm::new(
        transport::create(&keypair, relay_transport),
        behaviour,
        local_peer_id,
        swarm::Config::with_tokio_executor().with_idle_connection_timeout(Duration::MAX),
    );

    let (event_sender, event_receiver) = mpsc::channel(1);

    (
        client,
        event_receiver,
        MainLoop::new(swarm, command_receiver, event_sender, cfg, chain_id),
    )
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
    /// The minimum number of peers to maintain. If the number of outbound peers
    /// drops below this number, the node will attempt to connect to more
    /// peers.
    pub low_watermark: usize,
    /// How long to prevent evicted peers from reconnecting.
    pub eviction_timeout: Duration,
    pub ip_whitelist: Vec<IpNet>,
    pub bootstrap: BootstrapConfig,
    pub inbound_connections_rate_limit: RateLimit,
    /// Alternative protocol names for Kademlia
    pub kad_names: Vec<String>,
    /// Request timeout for p2p-stream
    /// TODO change the semantics to timeout since last response
    pub stream_timeout: Duration,
    /// Applies to each of the p2p-stream protocols separately
    pub max_concurrent_streams: usize,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub max: usize,
    pub interval: Duration,
}

#[derive(Copy, Clone, Debug)]
pub struct BootstrapConfig {
    pub start_offset: Duration,
    pub period: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            start_offset: Duration::from_secs(5),
            period: Duration::from_secs(2 * 60),
        }
    }
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
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<BlockHeadersResponse>>>,
    },
    SendClassesSyncRequest {
        peer_id: PeerId,
        request: ClassesRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<ClassesResponse>>>,
    },
    SendStateDiffsSyncRequest {
        peer_id: PeerId,
        request: StateDiffsRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<StateDiffsResponse>>>,
    },
    SendTransactionsSyncRequest {
        peer_id: PeerId,
        request: TransactionsRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<TransactionsResponse>>>,
    },
    SendEventsSyncRequest {
        peer_id: PeerId,
        request: EventsRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<EventsResponse>>>,
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
