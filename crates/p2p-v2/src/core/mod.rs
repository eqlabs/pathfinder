use std::fmt::Debug;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

mod behaviour;
mod builder;

pub use behaviour::{Behaviour, CoreBehaviour};
pub use builder::Builder;

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
}

/// Events emitted by the p2p network.
pub use behaviour::Event;

/// State of the p2p network.
pub struct State {
    // TODO: state types go here
}
