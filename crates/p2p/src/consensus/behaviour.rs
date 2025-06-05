use libp2p::gossipsub::{self, IdentTopic};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identity, PeerId};
use p2p_proto::consensus::Vote;
use p2p_proto::ProtobufSerializable;
#[cfg(test)]
use rand::seq::SliceRandom;
use tokio::sync::mpsc;
use tracing::error;

use crate::consensus::stream::StreamMessage;
use crate::consensus::{
    create_outgoing_proposal_message,
    handle_incoming_proposal_message,
    Event,
    TOPIC_PROPOSALS,
    TOPIC_VOTES,
};
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

    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State) {
        use consensus::Command as ConsensusCommand;
        match command {
            ConsensusCommand::Proposal(height_and_round, proposal_part) => {
                let stream_msgs =
                    create_outgoing_proposal_message(state, height_and_round, proposal_part);
                for msg in stream_msgs {
                    let topic = IdentTopic::new(TOPIC_PROPOSALS);
                    if let Err(e) = self.gossipsub.publish(topic, msg.to_protobuf_bytes()) {
                        error!("Failed to publish proposal message: {}", e);
                    }
                }
            }
            ConsensusCommand::Vote(vote) => {
                let data = vote.to_protobuf_bytes();
                let topic = IdentTopic::new(TOPIC_VOTES);
                if let Err(e) = self.gossipsub.publish(topic, data) {
                    error!("Failed to publish vote message: {}", e);
                }
            }
            #[cfg(test)]
            ConsensusCommand::TestProposalStream(height_and_round, proposal_stream, shuffle) => {
                // This command is used to test out-of-order delivery of proposal streams.
                // The `message_id` must be assigned sequentially within
                // `create_outgoing_proposal_message`, so this test command
                // needs to live in the network layer rather than the application layer.
                let mut stream_msgs = Vec::new();
                for part in proposal_stream {
                    let msgs = create_outgoing_proposal_message(state, height_and_round, part);
                    stream_msgs.extend(msgs);
                }
                if shuffle {
                    stream_msgs.shuffle(&mut rand::thread_rng());
                }
                for msg in stream_msgs {
                    let topic = IdentTopic::new(TOPIC_PROPOSALS);
                    if let Err(e) = self.gossipsub.publish(topic, msg.to_protobuf_bytes()) {
                        error!("Failed to publish proposal message: {}", e);
                    }
                }
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: BehaviourEvent,
        state: &mut Self::State,
        event_sender: mpsc::Sender<Self::Event>,
    ) {
        use gossipsub::Event::*;
        let BehaviourEvent::Gossipsub(e) = event;
        match e {
            Message {
                propagation_source: _,
                message_id,
                message,
            } => match message.topic.as_str() {
                TOPIC_PROPOSALS => {
                    if let Ok(stream_msg) = StreamMessage::from_protobuf_bytes(&message.data) {
                        let events = handle_incoming_proposal_message(state, stream_msg);
                        for event in events {
                            let _ = event_sender.send(event).await;
                        }
                    } else {
                        error!("Failed to parse proposal message with id: {}", message_id);
                    }
                }
                TOPIC_VOTES => {
                    if let Ok(vote) = Vote::from_protobuf_bytes(&message.data) {
                        let _ = event_sender.send(Event::Vote(vote)).await;
                    } else {
                        error!("Failed to parse vote message with id: {}", message_id);
                    }
                }
                _ => {}
            },
            _ => {
                // TODO: Do we care about any other Gossipsub events?
            }
        }
    }
}

impl Behaviour {
    /// Create a new consensus behaviour.
    pub fn new(keypair: identity::Keypair) -> Self {
        let peer_id = PeerId::from(keypair.public());

        let gossipsub_config = gossipsub::Config::default();
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair),
            gossipsub_config,
        )
        .expect("Failed to create gossipsub behaviour");

        let proposals_topic = IdentTopic::new(TOPIC_PROPOSALS);
        let votes_topic = IdentTopic::new(TOPIC_VOTES);

        gossipsub
            .subscribe(&proposals_topic)
            .expect("Failed to subscribe to proposals topic");
        gossipsub
            .subscribe(&votes_topic)
            .expect("Failed to subscribe to votes topic");

        tracing::info!("Consensus node started with peer ID: {}", peer_id);
        tracing::info!("Subscribed to topics: {}, {}", proposals_topic, votes_topic);

        Behaviour { gossipsub }
    }
}
