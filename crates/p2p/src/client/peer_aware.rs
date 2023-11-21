//! _Low level_ client for p2p interaction. Caller has to manage peers manually.
//! For syncing use [`crate::client::peer_agnostic::Client`] instead, which manages peers "under the hood".
use std::collections::HashSet;

use anyhow::Context;
use futures::channel::mpsc::Receiver as ResponseReceiver;
use libp2p::{gossipsub::IdentTopic, Multiaddr, PeerId};
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockHeadersRequest, BlockHeadersResponse, NewBlock,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use tokio::sync::{mpsc, oneshot};

#[cfg(test)]
use crate::test_utils;
use crate::Command;

#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::Sender<Command>,
    peer_id: PeerId,
}

macro_rules! impl_send {
    ($fn_name_req: ident, $req_command: ident, $res_command: ident, $req_type: ty, $res_type: ty) => {
        pub async fn $fn_name_req(
            &self,
            peer_id: PeerId,
            request: $req_type,
        ) -> anyhow::Result<ResponseReceiver<$res_type>> {
            let (sender, receiver) = oneshot::channel();
            self.sender
                .send(Command::$req_command {
                    peer_id,
                    request,
                    sender,
                })
                .await
                .expect("Command receiver not to be dropped");
            receiver.await.expect("Sender not to be dropped")
        }
    };
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

    impl_send!(
        send_headers_sync_request,
        SendHeadersSyncRequest,
        SendHeadersSyncResponse,
        BlockHeadersRequest,
        BlockHeadersResponse
    );

    impl_send!(
        send_bodies_sync_request,
        SendBodiesSyncRequest,
        SendBodiesSyncResponse,
        BlockBodiesRequest,
        BlockBodiesResponse
    );

    impl_send!(
        send_transactions_sync_request,
        SendTransactionsSyncRequest,
        SendTransactionsSyncResponse,
        TransactionsRequest,
        TransactionsResponse
    );

    impl_send!(
        send_receipts_sync_request,
        SendReceiptsSyncRequest,
        SendReceiptsSyncResponse,
        ReceiptsRequest,
        ReceiptsResponse
    );

    impl_send!(
        send_events_sync_request,
        SendEventsSyncRequest,
        SendEventsSyncResponse,
        EventsRequest,
        EventsResponse
    );

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
