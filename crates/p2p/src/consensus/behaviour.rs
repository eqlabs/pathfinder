use libp2p::gossipsub::{self, IdentTopic, Sha256Topic};
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

    #[tracing::instrument(skip(self, state))]
    async fn handle_command(&mut self, command: Self::Command, state: &mut Self::State) {
        use consensus::Command as ConsensusCommand;
        match command {
            ConsensusCommand::Proposal {
                height_and_round,
                proposal,
                done_tx,
            } => {
                let stream_msgs = proposal
                    .into_iter()
                    .flat_map(|proposal_part| {
                        create_outgoing_proposal_message(state, height_and_round, proposal_part)
                    })
                    .collect::<Vec<_>>();

                let mut tx_result = Ok(());
                for msg in stream_msgs {
                    let topic = IdentTopic::new(TOPIC_PROPOSALS);

                    if let Err(e) = self.gossipsub.publish(topic, msg.to_protobuf_bytes()) {
                        error!(
                            "Failed to publish proposal message, stream id {}, message id {}, \
                             error {e:?}",
                            msg.stream_id, msg.message_id
                        );
                        tx_result = Err(e);
                        break;
                    }
                }
                done_tx
                    .send(tx_result)
                    .await
                    .expect("Receiver not to be dropped");
            }
            ConsensusCommand::Vote { vote, done_tx } => {
                let cloned_vote = vote.clone();
                let data = vote.to_protobuf_bytes();
                let topic = IdentTopic::new(TOPIC_VOTES);

                let tx_result = self
                    .gossipsub
                    .publish(topic, data)
                    .inspect_err(|e| {
                        error!("Failed to publish vote message {cloned_vote:?}, error {e:?}");
                    })
                    .map(|_| ());

                done_tx
                    .send(tx_result)
                    .await
                    .expect("Receiver not to be dropped");
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

    #[tracing::instrument(skip(self))]
    async fn handle_event(
        &mut self,
        event: BehaviourEvent,
        state: &mut Self::State,
        event_sender: mpsc::UnboundedSender<Self::Event>,
    ) {
        use gossipsub::Event::*;
        let BehaviourEvent::Gossipsub(e) = event;

        tracing::trace!(event=?e, "Gossipsub event received");

        let topic_proposals_hash = Sha256Topic::new(TOPIC_PROPOSALS).hash();
        let topic_votes_hash = Sha256Topic::new(TOPIC_VOTES).hash();

        match e {
            Message {
                propagation_source: _,
                message_id,
                message,
            } => match message.topic {
                hash if hash == topic_proposals_hash => {
                    match StreamMessage::from_protobuf_bytes(&message.data) {
                        Ok(stream_msg) => {
                            let events = handle_incoming_proposal_message(state, stream_msg);
                            for event in events {
                                tracing::trace!(?event, "Emitting proposal event");
                                let _ = event_sender.send(event);
                            }
                        }
                        Err(error) => {
                            error!(%message_id, %error, "Failed to parse proposal message");
                        }
                    }
                }
                hash if hash == topic_votes_hash => {
                    match Vote::from_protobuf_bytes(&message.data) {
                        Ok(vote) => {
                            tracing::trace!(?vote, "Emitting vote event");
                            let _ = event_sender.send(Event::Vote(vote));
                        }
                        Err(error) => {
                            error!(%message_id, %error, "Failed to parse vote message");
                        }
                    }
                }
                _ => {}
            },
            _ => {
                // TODO: Do we care about any other Gossipsub events?
            }
        }
    }

    fn domain() -> &'static str {
        "p2p_consensus"
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

        let proposals_topic = Sha256Topic::new(TOPIC_PROPOSALS);
        let votes_topic = Sha256Topic::new(TOPIC_VOTES);

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
