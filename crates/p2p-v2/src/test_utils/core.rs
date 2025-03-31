use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot};

use crate::core::{Command, TestCommand};
use crate::peers::Peer;

#[derive(Clone)]
pub struct Client<A> {
    sender: mpsc::Sender<Command<A>>,
}

impl<A> Client<A> {
    pub fn new(sender: mpsc::Sender<Command<A>>) -> Self {
        Self { sender }
    }

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
}
