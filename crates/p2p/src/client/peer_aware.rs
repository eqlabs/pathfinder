//! _Low level_ client for p2p interaction. Caller has to manage peers manually.
//! For syncing use [`crate::client::peer_agnostic::Client`] instead, which manages peers "under the hood".
use std::collections::HashSet;

use anyhow::Context;
use libp2p::{gossipsub::IdentTopic, request_response::ResponseChannel, Multiaddr, PeerId};
use p2p_proto_v1::block::NewBlock;
use tokio::sync::{mpsc, oneshot};

#[cfg(test)]
use crate::test_utils;
use crate::Command;

#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::Sender<Command>,
    peer_id: PeerId,
}

impl Client {
    pub(crate) fn new(sender: mpsc::Sender<Command>, peer_id: PeerId) -> Self {
        Self { sender, peer_id }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub async fn start_listening(&self, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StarListening { addr, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Dial {
                peer_id,
                addr,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn provide_capability(&self, capability: &str) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::ProvideCapability {
                capability: capability.to_owned(),
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn get_capability_providers(
        &self,
        capability: &str,
    ) -> anyhow::Result<HashSet<PeerId>> {
        let (sender, mut receiver) = mpsc::channel(1);
        self.sender
            .send(Command::GetCapabilityProviders {
                capability: capability.to_owned(),
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");

        let mut providers = HashSet::new();

        while let Some(partial_result) = receiver.recv().await {
            let more_providers =
                partial_result.with_context(|| format!("Getting providers for {capability}"))?;
            providers.extend(more_providers.into_iter());
        }

        Ok(providers)
    }

    pub async fn subscribe_topic(&self, topic: &str) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::SubscribeTopic { topic, sender })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    // TODO
    pub async fn send_sync_request(&self, peer_id: PeerId, request: ()) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::SendSyncRequest {
                peer_id,
                request,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    // TODO
    pub async fn send_sync_response(&self, channel: ResponseChannel<()>, response: ()) {
        self.sender
            .send(Command::SendSyncResponse { channel, response })
            .await
            .expect("Command receiver not to be dropped");
    }

    pub async fn publish(&self, topic: &str, new_block: NewBlock) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::PublishPropagationMessage {
                topic,
                new_block,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    #[cfg(test)]
    pub(crate) fn for_test(&self) -> test_utils::Client {
        test_utils::Client::new(self.sender.clone())
    }
}
