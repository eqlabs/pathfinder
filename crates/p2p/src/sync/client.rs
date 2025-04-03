use futures::channel::mpsc::Receiver as ResponseReceiver;
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use tokio::sync::{mpsc, oneshot};

use crate::core;
use crate::sync::Command;

pub mod conv;
pub mod peer_agnostic;
pub mod types;

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
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
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
