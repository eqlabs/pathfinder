use std::collections::HashMap;

use futures::channel::mpsc::{Receiver as ResponseReceiver, Sender as ResponseSender};
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use p2p_stream::OutboundRequestId;
use tokio::sync::oneshot;

mod behaviour;

/// Commands for the sync behaviour.
#[derive(Debug)]
pub enum Command {
    /// Request headers from a peer.
    Headers {
        peer_id: PeerId,
        request: BlockHeadersRequest,
        sender: oneshot::Sender<
            anyhow::Result<ResponseReceiver<std::io::Result<BlockHeadersResponse>>>,
        >,
    },
    /// Request classes from a peer.
    Classes {
        peer_id: PeerId,
        request: ClassesRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<ClassesResponse>>>>,
    },
    /// Request state diffs from a peer.
    StateDiffs {
        peer_id: PeerId,
        request: StateDiffsRequest,
        sender:
            oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<StateDiffsResponse>>>>,
    },
    /// Request transactions from a peer.
    Transactions {
        peer_id: PeerId,
        request: TransactionsRequest,
        sender: oneshot::Sender<
            anyhow::Result<ResponseReceiver<std::io::Result<TransactionsResponse>>>,
        >,
    },
    /// Request events from a peer.
    Events {
        peer_id: PeerId,
        request: EventsRequest,
        sender: oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<EventsResponse>>>>,
    },
}

/// Events emitted by the sync behaviour.
#[derive(Debug)]
pub enum Event {
    Headers {
        from: PeerId,
        request: BlockHeadersRequest,
        channel: ResponseSender<BlockHeadersResponse>,
    },
    Classes {
        from: PeerId,
        request: ClassesRequest,
        channel: ResponseSender<ClassesResponse>,
    },
    StateDiffs {
        from: PeerId,
        request: StateDiffsRequest,
        channel: ResponseSender<StateDiffsResponse>,
    },
    Transactions {
        from: PeerId,
        request: TransactionsRequest,
        channel: ResponseSender<TransactionsResponse>,
    },
    Events {
        from: PeerId,
        request: EventsRequest,
        channel: ResponseSender<EventsResponse>,
    },
}

/// State of the sync behaviour.
pub struct State {
    //pub pending_queries: PendingQueries,
    pub pending_requests: PendingRequests,
}

/// Used to keep track of the different types of pending sync requests and
/// allows us to send the response payloads back to the caller.
#[derive(Debug, Default)]
pub struct PendingRequests {
    pub headers: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<BlockHeadersResponse>>>>,
    >,
    pub classes: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<ClassesResponse>>>>,
    >,
    pub state_diffs: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<StateDiffsResponse>>>>,
    >,
    pub transactions: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<TransactionsResponse>>>>,
    >,
    pub events: HashMap<
        OutboundRequestId,
        oneshot::Sender<anyhow::Result<ResponseReceiver<std::io::Result<EventsResponse>>>>,
    >,
}
