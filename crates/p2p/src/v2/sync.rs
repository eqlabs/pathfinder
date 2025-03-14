use futures::channel::mpsc::Receiver;
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use tokio::sync::oneshot;

mod behaviour;

#[derive(Debug)]
pub enum Command {
    SendHeadersSyncRequest {
        peer_id: PeerId,
        request: BlockHeadersRequest,
        sender: oneshot::Sender<anyhow::Result<Receiver<std::io::Result<BlockHeadersResponse>>>>,
    },
    SendClassesSyncRequest {
        peer_id: PeerId,
        request: ClassesRequest,
        sender: oneshot::Sender<anyhow::Result<Receiver<std::io::Result<ClassesResponse>>>>,
    },
    SendStateDiffsSyncRequest {
        peer_id: PeerId,
        request: StateDiffsRequest,
        sender: oneshot::Sender<anyhow::Result<Receiver<std::io::Result<StateDiffsResponse>>>>,
    },
    SendTransactionsSyncRequest {
        peer_id: PeerId,
        request: TransactionsRequest,
        sender: oneshot::Sender<anyhow::Result<Receiver<std::io::Result<TransactionsResponse>>>>,
    },
    SendEventsSyncRequest {
        peer_id: PeerId,
        request: EventsRequest,
        sender: oneshot::Sender<anyhow::Result<Receiver<std::io::Result<EventsResponse>>>>,
    },
}
