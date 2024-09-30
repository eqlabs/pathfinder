use std::collections::{BTreeSet, HashMap, HashSet};

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::peers::Peer;
use crate::test_utils::peer::ShortId;
use crate::{Command, TestCommand};

#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<Command>,
    peer_id: PeerId,
}

impl Client {
    pub fn new(sender: mpsc::Sender<Command>, peer_id: PeerId) -> Self {
        Self { sender, peer_id }
    }
}

impl Client {
    pub async fn get_peers_from_dht(&self) -> HashSet<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::GetPeersFromDHT(sender)))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn get_connected_peers(&self) -> HashMap<PeerId, Peer> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::GetConnectedPeers(sender)))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn force_dial(&self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::ForceDial {
                peer_id,
                addr,
                sender,
            }))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    /// Dump the DHT state to the log, use short peer IDs.
    pub async fn trace_dht(&self) {
        let me = ShortId::from(self.peer_id);
        let dht = self
            .get_peers_from_dht()
            .await
            .into_iter()
            .map(ShortId::from)
            .collect::<BTreeSet<ShortId>>();
        let len = dht.len();
        tracing::error!(%me, ?dht, %len);
    }

    /// Dump the connected peers to the log, use short peer IDs.
    pub async fn trace_connected(&self) {
        let me = ShortId::from(self.peer_id);
        let connected = self
            .get_connected_peers()
            .await
            .into_iter()
            .map(|(peer_id, _)| ShortId::from(peer_id))
            .collect::<BTreeSet<ShortId>>();
        let len = connected.len();
        tracing::error!(%me, ?connected, %len);
    }
}
