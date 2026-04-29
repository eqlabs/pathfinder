use libp2p::gossipsub::{self, Sha256Topic};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identity, PeerId};
use tokio::sync::mpsc;
use tracing::error;

use crate::preconfirmed::{EventKind, TOPIC_PRECONFIRMED_TRANSACTIONS};
use crate::{preconfirmed, ApplicationBehaviour};

/// The preconfirmed P2P network behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
}

impl ApplicationBehaviour for Behaviour {
    type Command = preconfirmed::Command;
    type Event = preconfirmed::Event;
    type TestEvent = preconfirmed::TestEvent;
    type State = preconfirmed::State;

    #[tracing::instrument(skip(self, _state))]
    async fn handle_command(&mut self, command: Self::Command, _state: &mut Self::State) {
        match command {
            #[cfg(test)]
            Self::Command::TestGossipPreconfirmedTransactions { done_tx } => {
                let topic = Sha256Topic::new(TOPIC_PRECONFIRMED_TRANSACTIONS);

                let tx_result = self
                    .gossipsub
                    // Note: we don't know the message structure yet, so we just send a single null
                    // byte
                    .publish(topic, vec![0])
                    .inspect_err(|e| {
                        error!("Failed to publish preconfirmed transaction message, error {e:?}");
                    })
                    .map(|_| ());

                done_tx
                    .send(tx_result)
                    .await
                    .expect("Receiver not to be dropped");
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn handle_event(
        &mut self,
        event: BehaviourEvent,
        state: &mut Self::State,
        event_sender: mpsc::UnboundedSender<Self::Event>,
        test_event_sender: mpsc::UnboundedSender<Self::TestEvent>,
    ) {
        use gossipsub::Event::*;
        let BehaviourEvent::Gossipsub(e) = event;

        tracing::trace!(event=?e, "Gossipsub event received");

        let topic_hash = Sha256Topic::new(TOPIC_PRECONFIRMED_TRANSACTIONS).hash();

        match e {
            Message {
                propagation_source,
                message_id,
                message,
            } => match message.topic {
                hash if hash == topic_hash => {
                    // Note: we don't know the message structure yet, so we just send a single null
                    // byte
                    if message.data == vec![0] {
                        let _ = event_sender.send(Self::Event {
                            source: propagation_source,
                            kind: EventKind::PreconfirmedTransactionsPlaceholder,
                        });
                    } else {
                        error!("Failed to parse message with id: {}", message_id);
                    }
                }
                _ => {}
            },
            Subscribed { peer_id, topic } => {
                tracing::debug!("Peer {} subscribed to topic {}", peer_id, topic);

                #[cfg(test)]
                {
                    let _ = test_event_sender.send(preconfirmed::TestEvent {
                        source: peer_id,
                        kind: preconfirmed::TestEventKind::Subscribed(topic),
                    });
                }
            }
            _ => {
                // TODO: Do we care about any other Gossipsub events?
            }
        }
    }

    fn domain() -> &'static str {
        "p2p_preconfirmed"
    }
}

impl Behaviour {
    /// Create a new preconfirmed behaviour.
    pub fn new(keypair: identity::Keypair) -> Self {
        let peer_id = PeerId::from(keypair.public());

        let gossipsub_config = gossipsub::Config::default();
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair),
            gossipsub_config,
        )
        .expect("Failed to create gossipsub behaviour");

        let topic = Sha256Topic::new(TOPIC_PRECONFIRMED_TRANSACTIONS);

        gossipsub
            .subscribe(&topic)
            .expect("Failed to subscribe to preconfirmed transactions topic");

        tracing::info!(
            "Preconfirmed network node started with peer ID: {}",
            peer_id
        );
        tracing::info!("Subscribed to topic: {}", topic);

        Behaviour { gossipsub }
    }
}
