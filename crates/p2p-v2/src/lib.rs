use std::future::Future;

use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviour;
use pathfinder_common::ChainId;
use tokio::sync::{mpsc, oneshot};

/// Application-specific p2p network behaviour. This one handles consensus.
pub mod consensus;
/// Core p2p network behaviour. This is the foundation for all the other
/// application-specific behaviours.
pub mod core;
/// Application-specific p2p network behaviour. This one handles sync.
pub mod sync;

mod builder;
mod main_loop;
mod peer_data;
mod peers;
mod secret;
#[cfg(test)]
mod test_utils;
mod transport;

pub use builder::Builder;
pub use libp2p;
pub use peer_data::PeerData;

pub fn new_sync(
    keypair: Keypair,
    core_config: core::Config,
    sync_config: sync::Config,
    chain_id: ChainId,
) -> (
    core::Client<sync::Command>,
    mpsc::Receiver<sync::Event>,
    main_loop::MainLoop<sync::Behaviour>,
) {
    Builder::new(keypair, core_config, chain_id)
        .app_behaviour(sync::Behaviour::new(sync_config))
        .build()
}

// TODO
pub fn new_consensus(
    keypair: Keypair,
    core_config: core::Config,
    _consensus_config: consensus::Config,
    chain_id: ChainId,
) -> (
    core::Client<sync::Command>,
    mpsc::Receiver<sync::Event>,
    main_loop::MainLoop<sync::Behaviour>,
) {
    // TODO remove allow when behaviour is built properly
    #[allow(unreachable_code)]
    Builder::new(keypair, core_config, chain_id)
        .app_behaviour(todo!())
        .build()
}

pub mod builder_phase {
    pub struct AppBehaviourUnset;
    pub struct AppBehaviourSet;
}

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
pub trait ApplicationBehaviour: NetworkBehaviour {
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

type EmptyResultSender = oneshot::Sender<anyhow::Result<()>>;
