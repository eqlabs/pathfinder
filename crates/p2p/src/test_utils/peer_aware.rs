use std::collections::{HashMap, HashSet};

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::peers::Peer;
use crate::{Command, TestCommand};

#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    pub fn new(sender: mpsc::Sender<Command>) -> Self {
        Self { sender }
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
}
