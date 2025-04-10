use libp2p::gossipsub::{self, Topic};
use libp2p::{identity, PeerId};
use libp2p::swarm::NetworkBehaviour;
use p2p_proto::ToProtobuf;
use tokio::sync::mpsc;

use crate::{consensus, ApplicationBehaviour};

const TOPIC_VOTES: &str = "consensus_votes";
const TOPIC_PROPOSALS: &str = "consensus_proposals";

/// The consensus P2P network behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    gossipsub: gossipsub::Behaviour,
}

impl ApplicationBehaviour for Behaviour {
    type Command = consensus::Command;
    type Event = consensus::Event;
    type State = consensus::State;

    async fn handle_command(&mut self, command: Self::Command, _state: &mut Self::State) {
        match command {
            Self::Command::BroadcastVote(vote) => {
                let topic = Topic::new(TOPIC_VOTES);
                let data = vote.to_protobuf();
                self.gossipsub.publish(topic, data);
            }
            Self::Command::BroadcastProposalPart { height, round, part } => {
                let topic = Topic::new(TOPIC_PROPOSALS);
            }
            Self::Command::StartHeight { height, validators } => {
                
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: <Self as NetworkBehaviour>::ToSwarm,
        _state: &mut Self::State,
        _event_sender: mpsc::Sender<Self::Event>,
    ) {
        match event {
            BehaviourEvent::Gossipsub(e) => {
                match e {
                    gossipsub::Event::Subscribed { peer_id, topic } => todo!(),
                    gossipsub::Event::Unsubscribed { peer_id, topic } => todo!(),
                    gossipsub::Event::GossipsubNotSupported { peer_id } => todo!(),
                    gossipsub::Event::SlowPeer { peer_id, failed_messages } => todo!(),
                    gossipsub::Event::Message { propagation_source, message_id, message } => todo!(),
                }
            }
        }
    }
}


impl Behaviour {
    pub fn new() -> Self {

        // This will probably come from the outside, but for now...
        let id_keys = identity::Keypair::generate_ed25519();
        // FYI, we can get our peer id from the public key
        let _peer_id = PeerId::from(id_keys.public());

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(id_keys),
            gossipsub::Config::default(),
        ).unwrap();

        Self { gossipsub }

    }
}
