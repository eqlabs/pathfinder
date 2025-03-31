//! _Low level_ client for p2p interaction. Caller has to manage peers manually.
//! For syncing use [`crate::client::peer_agnostic::Client`] instead, which
//! manages peers "under the hood".
use std::collections::HashSet;

use anyhow::Context;
use futures::channel::mpsc::Receiver as ResponseReceiver;
use libp2p::{Multiaddr, PeerId};
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use tokio::sync::{mpsc, oneshot};

use crate::core;
use crate::sync::Command;
#[cfg(test)]
use crate::test_utils;

#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::Sender<core::Command<Command>>,
    peer_id: PeerId,
}

impl From<(PeerId, mpsc::Sender<core::Command<Command>>)> for Client {
    fn from((peer_id, sender): (PeerId, mpsc::Sender<core::Command<Command>>)) -> Self {
        Self { sender, peer_id }
    }
}

macro_rules! impl_send {
    ($fn_name_req: ident, $req_command: ident, $req_type: ty, $res_type: ty) => {
        pub async fn $fn_name_req(
            &self,
            peer_id: PeerId,
            request: $req_type,
        ) -> anyhow::Result<ResponseReceiver<std::io::Result<$res_type>>> {
            let (sender, receiver) = oneshot::channel();
            self.sender
                .send(core::Command::Application(Command::$req_command {
                    peer_id,
                    request,
                    sender,
                }))
                .await
                .expect("Command receiver not to be dropped");
            receiver.await.expect("Sender not to be dropped")
        }
    };
}

impl Client {
    pub(crate) fn new(sender: mpsc::Sender<core::Command<Command>>, peer_id: PeerId) -> Self {
        Self { sender, peer_id }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    impl_send!(
        send_headers_request,
        SendHeadersRequest,
        BlockHeadersRequest,
        BlockHeadersResponse
    );

    impl_send!(
        send_classes_request,
        SendClassesRequest,
        ClassesRequest,
        ClassesResponse
    );

    impl_send!(
        send_state_diffs_request,
        SendStateDiffsRequest,
        StateDiffsRequest,
        StateDiffsResponse
    );

    impl_send!(
        send_transactions_request,
        SendTransactionsRequest,
        TransactionsRequest,
        TransactionsResponse
    );

    impl_send!(
        send_events_request,
        SendEventsRequest,
        EventsRequest,
        EventsResponse
    );
}
