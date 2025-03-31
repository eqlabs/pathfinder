use libp2p::swarm::NetworkBehaviour;
use tokio::sync::{mpsc, oneshot};

pub mod config;
pub mod consensus;
pub mod core;
pub mod sync;

mod peers;
mod secret;

mod main_loop;

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
pub trait P2PApplicationBehaviour: NetworkBehaviour {
    /// The type of commands that can be sent to the p2p network.
    type Command;
    /// The type of events that the p2p network can emit to the outside world.
    type Event;
    /// State needed to track pending network operations and their responses.
    type State;

    /// Handles a command from the outside world.
    #[allow(async_fn_in_trait)]
    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State);

    /// Handles an event from the inside of the p2p network.
    #[allow(async_fn_in_trait)]
    async fn handle_event(
        &mut self,
        event: <Self as NetworkBehaviour>::ToSwarm,
        state: &mut Self::State,
        event_sender: mpsc::Sender<Self::Event>,
    );
}

type EmptyResultSender = oneshot::Sender<anyhow::Result<()>>;
