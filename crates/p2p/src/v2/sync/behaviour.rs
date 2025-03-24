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
    type State = sync::State;

    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State) {
        use sync::Command::*;
        match command {
            HeadersSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending headers sync request");
                let request_id = self.header_sync.send_request(&peer_id, request);
                state.pending_queries.headers.insert(request_id, sender);
            }
            ClassesSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending classes sync request");
                let request_id = self.class_sync.send_request(&peer_id, request);
                state.pending_queries.classes.insert(request_id, sender);
            }
            StateDiffsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending state diffs sync request");
                let request_id = self.state_diff_sync.send_request(&peer_id, request);
                state.pending_queries.state_diffs.insert(request_id, sender);
            }
            TransactionsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending transactions sync request");
                let request_id = self.transaction_sync.send_request(&peer_id, request);
                state
                    .pending_queries
                    .transactions
                    .insert(request_id, sender);
            }
            EventsSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending events sync request");
                let request_id = self.event_sync.send_request(&peer_id, request);
                state.pending_queries.events.insert(request_id, sender);
            }
        }
    }

    async fn handle_event(&mut self, _event: Self::Event, _state: &mut Self::State) {
        todo!()
    }
}
