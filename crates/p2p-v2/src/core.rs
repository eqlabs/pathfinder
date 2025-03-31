use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

pub mod behaviour;
pub mod client;
#[cfg(test)]
mod tests;

use crate::peers::Peer;
use crate::EmptyResultSender;

/// Commands that can be sent to the p2p network.
#[derive(Debug)]
pub enum Command<ApplicationCommand> {
    /// Listen for incoming connections on a specific address.
    Listen {
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    /// Dial a specific peer.
    Dial {
        peer_id: PeerId,
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    /// Disconnect from a specific peer.
    Disconnect {
        peer_id: PeerId,
        sender: EmptyResultSender,
    },
    /// Get the closest peers to a specific peer.
    GetClosestPeers {
        peer: PeerId,
        sender: mpsc::Sender<anyhow::Result<Vec<PeerId>>>,
    },
    /// Notify the p2p network that a peer is not useful.
    NotUseful {
        peer_id: PeerId,
        sender: oneshot::Sender<()>,
    },
    /// Application-specific command.
    Application(ApplicationCommand),
    /// For testing purposes only
    _Test(TestCommand),
}

#[derive(Debug)]
pub enum TestCommand {
    GetPeersFromDHT(oneshot::Sender<HashSet<PeerId>>),
    GetConnectedPeers(oneshot::Sender<HashMap<PeerId, Peer>>),
}

#[derive(Debug)]
pub enum TestEvent {
    NewListenAddress(Multiaddr),
    KademliaBootstrapStarted,
    KademliaBootstrapCompleted(Result<PeerId, PeerId>),
    ConnectionEstablished { outbound: bool, remote: PeerId },
    ConnectionClosed { remote: PeerId },
    PeerAddedToDHT { remote: PeerId },
}
