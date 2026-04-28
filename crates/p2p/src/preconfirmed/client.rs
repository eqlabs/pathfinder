#[cfg(test)]
use libp2p::gossipsub::PublishError;
use libp2p::PeerId;
use tokio::sync::mpsc;

use crate::core;
use crate::preconfirmed::Command;

#[derive(Clone, Debug)]
pub struct Client {
    _sender: mpsc::UnboundedSender<core::Command<Command>>,
    local_peer_id: PeerId,
}

impl From<(PeerId, mpsc::UnboundedSender<core::Command<Command>>)> for Client {
    fn from(
        (local_peer_id, _sender): (PeerId, mpsc::UnboundedSender<core::Command<Command>>),
    ) -> Self {
        Self {
            _sender,
            local_peer_id,
        }
    }
}

impl Client {
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    #[cfg(test)]
    pub async fn gossip_preconfirmed_transactions(&self) -> Result<(), PublishError> {
        let (done_tx, mut rx) = mpsc::channel(1);
        self._sender
            .send(core::Command::Application(
                Command::TestGossipPreconfirmedTransactions { done_tx },
            ))
            .expect("Command receiver not to be dropped");

        rx.recv().await.expect("Sender not to be dropped")
    }
}
