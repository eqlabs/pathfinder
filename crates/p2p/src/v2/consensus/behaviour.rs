use libp2p::gossipsub;
use libp2p::swarm::NetworkBehaviour;

use crate::v2::core::P2PApplicationBehaviour;
use crate::v2::sync;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
}

impl P2PApplicationBehaviour for Behaviour {
    type Command = sync::Command;
    type Event = BehaviourEvent;
    type State = ();

    async fn handle_command(&mut self, _command: Self::Command, _state: &mut Self::State) {
        todo!()
    }

    async fn handle_event(&mut self, _event: Self::Event, _state: &mut Self::State) {
        todo!()
    }
}
