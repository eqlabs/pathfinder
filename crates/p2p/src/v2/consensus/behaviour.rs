use libp2p::gossipsub;
use libp2p::swarm::NetworkBehaviour;

use crate::v2::core::ApplicationMainLoopHandler;
use crate::v2::sync;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
}

impl ApplicationMainLoopHandler for Behaviour {
    type Command = sync::Command;
    type Event = BehaviourEvent;
    type PendingStuff = ();

    async fn handle_command(&mut self, _command: Self::Command, _pending: &mut Self::PendingStuff) {
        todo!()
    }

    async fn handle_event(&mut self, _event: Self::Event, _pending: &mut Self::PendingStuff) {
        todo!()
    }
}
