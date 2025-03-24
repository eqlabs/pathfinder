use libp2p::swarm::NetworkBehaviour;

use crate::sync::codec;
use crate::v2::core::P2PApplicationBehaviour;
use crate::v2::sync;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    header_sync: p2p_stream::Behaviour<codec::Headers>,
    class_sync: p2p_stream::Behaviour<codec::Classes>,
    state_diff_sync: p2p_stream::Behaviour<codec::StateDiffs>,
    transaction_sync: p2p_stream::Behaviour<codec::Transactions>,
    event_sync: p2p_stream::Behaviour<codec::Events>,
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
