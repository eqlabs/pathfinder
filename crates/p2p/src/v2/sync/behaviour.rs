use libp2p::swarm::NetworkBehaviour;
use tokio::sync::mpsc;

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
    type Event = sync::Event;
    type State = sync::State;

    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State) {
        use sync::Command::*;
        match command {
            Headers {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending headers sync request");
                let request_id = self.header_sync.send_request(&peer_id, request);
                state.pending_requests.headers.insert(request_id, sender);
            }
            Classes {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending classes sync request");
                let request_id = self.class_sync.send_request(&peer_id, request);
                state.pending_requests.classes.insert(request_id, sender);
            }
            StateDiffs {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending state diffs sync request");
                let request_id = self.state_diff_sync.send_request(&peer_id, request);
                state
                    .pending_requests
                    .state_diffs
                    .insert(request_id, sender);
            }
            Transactions {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending transactions sync request");
                let request_id = self.transaction_sync.send_request(&peer_id, request);
                state
                    .pending_requests
                    .transactions
                    .insert(request_id, sender);
            }
            Events {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending events sync request");
                let request_id = self.event_sync.send_request(&peer_id, request);
                state.pending_requests.events.insert(request_id, sender);
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: BehaviourEvent,
        state: &mut Self::State,
        event_sender: mpsc::Sender<Self::Event>,
    ) {
        use p2p_stream::Event as P2PStreamEvent;
        match event {
            BehaviourEvent::HeaderSync(P2PStreamEvent::InboundRequest {
                request_id,
                request,
                peer,
                channel,
            }) => {
                tracing::debug!(?request, %peer, %request_id, "Received headers sync request");
                event_sender
                    .send(sync::Event::Headers {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            BehaviourEvent::HeaderSync(P2PStreamEvent::OutboundRequestSentAwaitingResponses {
                request_id,
                peer,
                channel,
            }) => {
                tracing::debug!(%peer, %request_id, "Headers sync request sent");
                let _ = state
                    .pending_requests
                    .headers
                    .remove(&request_id)
                    .expect("Header sync request still to be pending")
                    .send(Ok(channel));
            }
            BehaviourEvent::ClassSync(P2PStreamEvent::InboundRequest {
                request_id,
                request,
                peer,
                channel,
            }) => {
                tracing::debug!(?request, %peer, %request_id, "Received classes sync request");
                event_sender
                    .send(sync::Event::Classes {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            BehaviourEvent::ClassSync(P2PStreamEvent::OutboundRequestSentAwaitingResponses {
                request_id,
                peer,
                channel,
            }) => {
                tracing::debug!(%peer, %request_id, "Classes sync request sent");
                let _ = state
                    .pending_requests
                    .classes
                    .remove(&request_id)
                    .expect("Classes sync request still to be pending")
                    .send(Ok(channel));
            }
            BehaviourEvent::StateDiffSync(P2PStreamEvent::InboundRequest {
                request_id,
                request,
                peer,
                channel,
            }) => {
                tracing::debug!(?request, %peer, %request_id, "Received state diffs sync request");
                event_sender
                    .send(sync::Event::StateDiffs {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            BehaviourEvent::StateDiffSync(
                P2PStreamEvent::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            ) => {
                tracing::debug!(%peer, %request_id, "State diffs sync request sent");
                let _ = state
                    .pending_requests
                    .state_diffs
                    .remove(&request_id)
                    .expect("State diff sync request still to be pending")
                    .send(Ok(channel));
            }
            BehaviourEvent::TransactionSync(p2p_stream::Event::InboundRequest {
                request_id,
                request,
                peer,
                channel,
            }) => {
                tracing::debug!(?request, %peer, %request_id, "Received transaction sync request");
                event_sender
                    .send(sync::Event::Transactions {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            BehaviourEvent::TransactionSync(
                P2PStreamEvent::OutboundRequestSentAwaitingResponses {
                    request_id,
                    peer,
                    channel,
                },
            ) => {
                tracing::debug!(%peer, %request_id, "Transaction sync request sent");
                let _ = state
                    .pending_requests
                    .transactions
                    .remove(&request_id)
                    .expect("Transaction sync request still to be pending")
                    .send(Ok(channel));
            }
            BehaviourEvent::EventSync(P2PStreamEvent::InboundRequest {
                request_id,
                request,
                peer,
                channel,
            }) => {
                tracing::debug!(?request, %peer, %request_id, "Received event sync request");
                event_sender
                    .send(sync::Event::Events {
                        from: peer,
                        request,
                        channel,
                    })
                    .await
                    .expect("Event receiver not to be dropped");
            }
            BehaviourEvent::EventSync(P2PStreamEvent::OutboundRequestSentAwaitingResponses {
                request_id,
                peer,
                channel,
            }) => {
                tracing::debug!(%peer, %request_id, "Event sync request sent");
                let _ = state
                    .pending_requests
                    .events
                    .remove(&request_id)
                    .expect("Event sync request still to be pending")
                    .send(Ok(channel));
            }
            BehaviourEvent::HeaderSync(P2PStreamEvent::OutboundFailure {
                request_id,
                error,
                ..
            }) => {
                tracing::warn!(?request_id, ?error, "Outbound header sync request failed");
                if let Some(sender) = state.pending_requests.headers.remove(&request_id) {
                    let _ = sender.send(Err(error.into()));
                }
            }
            BehaviourEvent::ClassSync(P2PStreamEvent::OutboundFailure {
                request_id,
                error,
                ..
            }) => {
                tracing::warn!(?request_id, ?error, "Outbound classes sync request failed");
            }
            BehaviourEvent::StateDiffSync(P2PStreamEvent::OutboundFailure {
                request_id,
                error,
                ..
            }) => {
                tracing::warn!(
                    ?request_id,
                    ?error,
                    "Outbound state diffs sync request failed"
                );
                if let Some(sender) = state.pending_requests.state_diffs.remove(&request_id) {
                    let _ = sender.send(Err(error.into()));
                }
            }
            BehaviourEvent::TransactionSync(P2PStreamEvent::OutboundFailure {
                request_id,
                error,
                ..
            }) => {
                tracing::warn!(
                    ?request_id,
                    ?error,
                    "Outbound transaction sync request failed"
                );
                if let Some(sender) = state.pending_requests.transactions.remove(&request_id) {
                    let _ = sender.send(Err(error.into()));
                }
            }
            BehaviourEvent::EventSync(P2PStreamEvent::OutboundFailure {
                request_id,
                error,
                ..
            }) => {
                tracing::warn!(?request_id, ?error, "Outbound event sync request failed");
                if let Some(sender) = state.pending_requests.events.remove(&request_id) {
                    let _ = sender.send(Err(error.into()));
                }
            }
            _ => {
                tracing::warn!("Unhandled event: {:?}", event);
            }
        }
    }
}
