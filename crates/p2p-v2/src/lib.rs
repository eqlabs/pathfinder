use core::behaviour::Event;
use core::client::Client;
use std::future::Future;

use builder::Builder;
use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use main_loop::MainLoop;
use pathfinder_common::ChainId;
use tokio::sync::{mpsc, oneshot};

pub mod consensus;
pub mod core;
pub mod sync;

mod builder;
mod main_loop;
mod peers;
mod secret;
#[cfg(test)]
mod test_utils;
mod transport;

/* FIXME
pub fn new<B>(
    keypair: Keypair,
    cfg: Config,
    chain_id: ChainId,
) -> (
    Client<<B as P2PApplicationBehaviour>::Command>,
    mpsc::Receiver<Event<B>>,
    MainLoop<B>,
)
where
    B: P2PApplicationBehaviour<Event = Event<B>> + Default,
    <B as NetworkBehaviour>::ToSwarm: std::fmt::Debug,
    <B as P2PApplicationBehaviour>::State: Default,
{
    Builder::new(keypair, cfg, chain_id).build()
}
*/

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
    fn handle_command(
        &mut self,
        command: Self::Command,
        state: &mut Self::State,
    ) -> impl Future<Output = ()> + Send;

    /// Handles an event from the inside of the p2p network.
    fn handle_event(
        &mut self,
        event: <Self as NetworkBehaviour>::ToSwarm,
        state: &mut Self::State,
        event_sender: mpsc::Sender<Self::Event>,
    ) -> impl Future<Output = ()> + Send;
}

pub trait AppClientProvider {
    type Client;
    type Command;

    fn client(command_sender: mpsc::Sender<Self::Command>, local_peer_id: PeerId) -> Self::Client;
}

type EmptyResultSender = oneshot::Sender<anyhow::Result<()>>;
