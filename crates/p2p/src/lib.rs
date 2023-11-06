#![deny(rust_2018_idioms)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::kad::RecordKey;
use libp2p::request_response::ResponseChannel;
use libp2p::swarm::Config;
use libp2p::{Multiaddr, PeerId, Swarm};
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponseList, BlockHeadersRequest, BlockHeadersResponse,
    NewBlock,
};
use p2p_proto::event::{EventsRequest, EventsResponseList};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponseList};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponseList};
use pathfinder_common::{BlockHash, BlockNumber};
use tokio::sync::{mpsc, oneshot, RwLock};

mod behaviour;
pub mod client;
mod main_loop;
mod peers;
mod sync;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
mod transport;

pub use libp2p;
pub use peers::Peers;
pub use sync::protocol::PROTOCOLS;

use client::peer_aware::Client;
use main_loop::MainLoop;

pub fn new(
    keypair: Keypair,
    peers: Arc<RwLock<peers::Peers>>,
    periodic_cfg: PeriodicTaskConfig,
) -> (Client, EventReceiver, MainLoop) {
    let local_peer_id = keypair.public().to_peer_id();

    let (behaviour, relay_transport) = behaviour::Behaviour::new(&keypair);

    let swarm = Swarm::new(
        transport::create(&keypair, relay_transport),
        behaviour,
        local_peer_id,
        // libp2p v0.52 related change: `libp2p::swarm::keep_alive`` has been deprecated and
        // it is advised to set the idle connection timeout to maximum value instead.
        //
        // TODO but ultimately do we really need keep_alive?
        // 1. sync status message was removed in the latest spec, but as we used it partially to
        //    maintain connection with peers, we're using keep alive instead
        // 2. I'm not sure if we really need keep alive, as connections should be closed when not used
        //    because they consume resources, and in general we should be managing connections in a wiser manner,
        //    the deprecated `libp2p::swarm::keep_alive::Behaviour` was supposed to be mostly used for testing anyway.
        Config::with_tokio_executor().with_idle_connection_timeout(Duration::MAX),
    );

    let (command_sender, command_receiver) = mpsc::channel(1);
    let (event_sender, event_receiver) = mpsc::channel(1);

    (
        Client::new(command_sender, local_peer_id),
        event_receiver,
        MainLoop::new(swarm, command_receiver, event_sender, peers, periodic_cfg),
    )
}

#[derive(Copy, Clone, Debug)]
pub struct PeriodicTaskConfig {
    pub bootstrap: BootstrapConfig,
}

#[derive(Copy, Clone, Debug)]
pub struct BootstrapConfig {
    pub start_offset: Duration,
    pub period: Duration,
}

impl Default for PeriodicTaskConfig {
    fn default() -> Self {
        Self {
            bootstrap: BootstrapConfig {
                start_offset: Duration::from_secs(5),
                period: Duration::from_secs(10 * 60),
            },
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
    ProvideCapability {
        capability: String,
        sender: EmptyResultSender,
    },
    GetCapabilityProviders {
        capability: String,
        sender: mpsc::Sender<anyhow::Result<HashSet<PeerId>>>,
    },
    SubscribeTopic {
        topic: IdentTopic,
        sender: EmptyResultSender,
    },
    SendHeadersSyncRequest {
        peer_id: PeerId,
        request: BlockHeadersRequest,
        sender: oneshot::Sender<anyhow::Result<BlockHeadersResponse>>,
    },
    SendBodiesSyncRequest {
        peer_id: PeerId,
        request: BlockBodiesRequest,
        sender: oneshot::Sender<anyhow::Result<BlockBodiesResponseList>>,
    },
    SendTransactionsSyncRequest {
        peer_id: PeerId,
        request: TransactionsRequest,
        sender: oneshot::Sender<anyhow::Result<TransactionsResponseList>>,
    },
    SendReceiptsSyncRequest {
        peer_id: PeerId,
        request: ReceiptsRequest,
        sender: oneshot::Sender<anyhow::Result<ReceiptsResponseList>>,
    },
    SendEventsSyncRequest {
        peer_id: PeerId,
        request: EventsRequest,
        sender: oneshot::Sender<anyhow::Result<EventsResponseList>>,
    },
    SendHeadersSyncResponse {
        channel: ResponseChannel<BlockHeadersResponse>,
        response: BlockHeadersResponse,
    },
    SendBodiesSyncResponse {
        channel: ResponseChannel<BlockBodiesResponseList>,
        response: BlockBodiesResponseList,
    },
    SendTransactionsSyncResponse {
        channel: ResponseChannel<TransactionsResponseList>,
        response: TransactionsResponseList,
    },
    SendReceiptsSyncResponse {
        channel: ResponseChannel<ReceiptsResponseList>,
        response: ReceiptsResponseList,
    },
    SendEventsSyncResponse {
        channel: ResponseChannel<EventsResponseList>,
        response: EventsResponseList,
    },
    PublishPropagationMessage {
        topic: IdentTopic,
        new_block: NewBlock,
        sender: EmptyResultSender,
    },
    /// For testing purposes only
    _Test(TestCommand),
}

#[derive(Debug)]
pub enum TestCommand {
    GetPeersFromDHT(oneshot::Sender<HashSet<PeerId>>),
}

#[derive(Debug)]
pub enum Event {
    SyncPeerConnected {
        peer_id: PeerId,
    },
    InboundHeadersSyncRequest {
        from: PeerId,
        request: BlockHeadersRequest,
        channel: ResponseChannel<BlockHeadersResponse>,
    },
    InboundBodiesSyncRequest {
        from: PeerId,
        request: BlockBodiesRequest,
        channel: ResponseChannel<BlockBodiesResponseList>,
    },
    InboundTransactionsSyncRequest {
        from: PeerId,
        request: TransactionsRequest,
        channel: ResponseChannel<TransactionsResponseList>,
    },
    InboundReceiptsSyncRequest {
        from: PeerId,
        request: ReceiptsRequest,
        channel: ResponseChannel<ReceiptsResponseList>,
    },
    InboundEventsSyncRequest {
        from: PeerId,
        request: EventsRequest,
        channel: ResponseChannel<EventsResponseList>,
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
    PeriodicBootstrapCompleted(Result<PeerId, PeerId>),
    StartProvidingCompleted(Result<RecordKey, RecordKey>),
    ConnectionEstablished { outbound: bool, remote: PeerId },
    Subscribed { remote: PeerId, topic: String },
    PeerAddedToDHT { remote: PeerId },
    Dummy,
}

pub type EventReceiver = mpsc::Receiver<Event>;
