use libp2p::gossipsub::PublishError;
use libp2p::PeerId;
use p2p_proto::consensus::{ProposalPart, Vote};
use tokio::sync::mpsc;

use crate::consensus::height_and_round::HeightAndRound;
use crate::consensus::Command;
use crate::core;

#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::UnboundedSender<core::Command<Command>>,
    local_peer_id: PeerId,
}

impl From<(PeerId, mpsc::UnboundedSender<core::Command<Command>>)> for Client {
    fn from((peer_id, sender): (PeerId, mpsc::UnboundedSender<core::Command<Command>>)) -> Self {
        Self {
            sender,
            local_peer_id: peer_id,
        }
    }
}

impl Client {
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub async fn gossip_vote(&self, vote: Vote) -> Result<(), PublishError> {
        let (done_tx, mut rx) = mpsc::channel(1);
        self.sender
            .send(core::Command::Application(Command::Vote { vote, done_tx }))
            .expect("Command receiver not to be dropped");

        rx.recv().await.expect("Sender not to be dropped")
    }

    pub async fn gossip_proposal(
        &self,
        height_and_round: HeightAndRound,
        proposal: Vec<ProposalPart>,
    ) -> Result<(), PublishError> {
        let (done_tx, mut rx) = mpsc::channel(1);
        self.sender
            .send(core::Command::Application(Command::Proposal {
                height_and_round,
                proposal,
                done_tx,
            }))
            .expect("Command receiver not to be dropped");

        rx.recv().await.expect("Sender not to be dropped")
    }

    /// Change the application-specific score for the given peer (if it is
    /// connected to us).
    ///
    /// The `delta` parameter should most likely be one of the constants defined
    /// in the [penalty](crate::consensus::penalty) module.
    pub fn change_peer_score(&self, peer_id: PeerId, delta: f64) {
        self.sender
            .send(core::Command::Application(Command::ChangePeerScore {
                peer_id,
                delta,
            }))
            .expect("Command receiver not to be dropped");
    }
}
