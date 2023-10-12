#![deny(rust_2018_idioms)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::kad::record::Key;
use libp2p::request_response::ResponseChannel;
use libp2p::swarm::SwarmBuilder;
use libp2p::Multiaddr;
use libp2p::PeerId;
use pathfinder_common::{BlockHash, BlockNumber};
use tokio::sync::{mpsc, oneshot, RwLock};

mod behaviour;
pub mod client;
mod executor;
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

use client::peer_aware::Client;
use main_loop::MainLoop;

pub fn new(
    keypair: Keypair,
    peers: Arc<RwLock<peers::Peers>>,
    periodic_cfg: PeriodicTaskConfig,
) -> (Client, EventReceiver, MainLoop) {
    let local_peer_id = keypair.public().to_peer_id();

    let (behaviour, relay_transport) = behaviour::Behaviour::new(&keypair);

    let swarm = SwarmBuilder::with_executor(
        transport::create(&keypair, relay_transport),
        behaviour,
        local_peer_id,
        executor::TokioExecutor(),
    )
    .build();

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
    SendSyncRequest {
        peer_id: PeerId,
        request: p2p_proto_v0::sync::Request,
        sender: oneshot::Sender<anyhow::Result<p2p_proto_v0::sync::Response>>,
    },
    SendSyncResponse {
        channel: ResponseChannel<p2p_proto_v0::sync::Response>,
        response: p2p_proto_v0::sync::Response,
    },
    PublishPropagationMessage {
        topic: IdentTopic,
        message: Box<p2p_proto_v0::propagation::Message>,
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
    InboundSyncRequest {
        from: PeerId,
        request: p2p_proto_v0::sync::Request,
        channel: ResponseChannel<p2p_proto_v0::sync::Response>,
    },
    BlockPropagation {
        from: PeerId,
        message: Box<p2p_proto_v0::propagation::Message>,
    },
    /// For testing purposes only
    Test(TestEvent),
}

#[derive(Debug)]
pub enum TestEvent {
    NewListenAddress(Multiaddr),
    PeriodicBootstrapCompleted(Result<PeerId, PeerId>),
    StartProvidingCompleted(Result<Key, Key>),
    ConnectionEstablished { outbound: bool, remote: PeerId },
    Subscribed { remote: PeerId, topic: String },
    PeerAddedToDHT { remote: PeerId },
    Dummy,
}

pub type EventReceiver = mpsc::Receiver<Event>;
