use libp2p::gossipsub;
use libp2p::swarm::NetworkBehaviour;
use tokio::sync::mpsc;

use crate::{consensus, ApplicationBehaviour};

/// The consensus P2P network behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
}

impl ApplicationBehaviour for Behaviour {
    type Command = consensus::Command;
    type Event = consensus::Event;
    type State = consensus::State;

    async fn handle_command(&mut self, _command: Self::Command, _state: &mut Self::State) {
        todo!()
    }

    async fn handle_event(
        &mut self,
        _event: <Self as NetworkBehaviour>::ToSwarm,
        _state: &mut Self::State,
        _event_sender: mpsc::Sender<Self::Event>,
    ) {
        todo!()
    }
}
