use std::fmt::Debug;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

pub mod behaviour;
pub mod main_loop;

use crate::{EmptyResultSender, TestCommand, TestEvent};

/// Defines how an application-specific p2p protocol (like sync or consensus)
/// interacts with the network:
/// - Commands: Actions requested by the application to be executed by the
///   network
/// - Events: Notifications from the network that the application needs to
///   handle
/// - State: Data needed to track ongoing operations
///
/// This trait is implemented by application-specific network behaviors (like
/// sync, consensus) to define their p2p protocol logic.
pub trait P2PApplicationBehaviour {
    /// The type of commands that can be sent to the p2p network.
    type Command;
    /// The type of events that the p2p network can emit to the outside world.
    type Event;
    /// State needed to track pending network operations and their responses.
    type State;

    /// Handles a command from the outside world.
    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State);

    /// Handles an event from the inside of the p2p network.
    async fn handle_event(&mut self, event: Self::Event, state: &mut Self::State);
}

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
    // TODO test commands could also be split into core and application specific although I'm not
    // sure if it's necessary, maybe this comment should just be removed
    _Test(TestCommand),
}

/// Events that can be sent from the inside of the p2p network to the outside
/// world.
#[derive(Debug)]
pub enum Event<ApplicationEvent> {
    /// Application behaviour events (notifications) go here
    Application(ApplicationEvent),
    /// For testing purposes only
    Test(TestEvent),
}
