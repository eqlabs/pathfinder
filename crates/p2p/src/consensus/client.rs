use libp2p::PeerId;
use p2p_proto::consensus::{ProposalPart, Vote};
use tokio::sync::mpsc;

use crate::consensus::height_and_round::HeightAndRound;
use crate::consensus::Command;
use crate::core;

#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::Sender<core::Command<Command>>,
    local_peer_id: PeerId,
}

impl From<(PeerId, mpsc::Sender<core::Command<Command>>)> for Client {
    fn from((peer_id, sender): (PeerId, mpsc::Sender<core::Command<Command>>)) -> Self {
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

    pub async fn gossip_vote(&self, vote: Vote) -> anyhow::Result<()> {
        let (done_tx, mut rx) = mpsc::channel(1);
        self.sender
            .send(core::Command::Application(Command::Vote { vote, done_tx }))
            .await
            .expect("Command receiver not to be dropped");

        rx.recv().await.expect("Sender not to be dropped")
    }

    pub async fn gossip_proposal(
        &self,
        height_and_round: HeightAndRound,
        proposal: Vec<ProposalPart>,
    ) -> anyhow::Result<()> {
        let (done_tx, mut rx) = mpsc::channel(1);
        self.sender
            .send(core::Command::Application(Command::Proposal {
                height_and_round,
                proposal,
                done_tx,
            }))
            .await
            .expect("Command receiver not to be dropped");

        rx.recv().await.expect("Sender not to be dropped")
    }
}
