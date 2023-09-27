//! This code is in an incomplete state and cannot be used as is.
//! 
//! This was an initial attempt at implementing websocket subscription
//! based support within pathfinder. It was deemed more important
//! to complete the normal framework without waiting for this, however
//! this code could inform a proper design. As such the code is left as 
//! is as a potential to form the skeleton in the future.
#![allow(dead_code, unused)]

use std::borrow::Cow;
use std::collections::HashMap;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_stream::wrappers::BroadcastStream;

use crate::context::RpcContext;
use crate::jsonrpc::request::RawParams;
use crate::jsonrpc::{RequestId, RpcError, RpcRequest, RpcResponse};
use crate::websocket::types::{BlockHeader, WebsocketSenders};

pub async fn websocket_handler(ws: WebSocketUpgrade, State(state): State<RpcContext>) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: RpcContext) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let (msg_sender, msg_receiver) = mpsc::channel(100);

    tokio::spawn(write(ws_sender, msg_receiver));
    tokio::spawn(read(ws_receiver, msg_sender, state.websocket));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    msg_sender: mpsc::Sender<ResponseEvent>,
    source: WebsocketSenders,
) {
    let mut subscription_manager = SubscriptionManager::default();

    loop {
        let request = match receiver.next().await {
            Some(Ok(x)) => x.into_data(),
            // Both of these are client disconnects according to the axum example
            // https://docs.rs/axum/0.6.20/axum/extract/ws/index.html#example
            Some(Err(e)) => {
                tracing::trace!(error=%e, "Client disconnected");
                break;
            }
            None => {
                tracing::trace!("Client disconnected");
                break;
            }
        };

        let Ok(request) = serde_json::from_slice::<RpcRequest<'_>>(&request) else {
            match msg_sender.try_send(ResponseEvent::InvalidRequest) {
                Ok(_) => continue,
                Err(e) => {
                    tracing::debug!(reason=%e, "Failed to send invalid request response");
                    break;
                }
            }
        };

        // Handle request.
        let response = match request.method.as_ref() {
            "pathfinder_subscribe" => subscription_manager.subscribe(
                request.id,
                request.params,
                msg_sender.clone(),
                source.clone(),
            ),
            "pathfinder_unsubscribe" => {
                subscription_manager
                    .unsubscribe(request.id, request.params)
                    .await
            }
            _ => ResponseEvent::InvalidMethod(request.id.into()),
        };

        if let Err(e) = msg_sender.try_send(response) {
            tracing::debug!(reason=%e, "Failed to send response");
            break;
        }
    }

    // Force some clean up by aborting all still running subscriptions.
    // These would naturally come to a halt as the message queues break,
    // but this will kill them more quickly.
    subscription_manager.abort_all();
}

#[derive(Default)]
struct SubscriptionManager {
    next_id: u32,
    subscriptions: HashMap<u32, tokio::task::JoinHandle<()>>,
}

impl SubscriptionManager {
    async fn unsubscribe(
        &mut self,
        request_id: RequestId<'_>,
        request_params: RawParams<'_>,
    ) -> ResponseEvent {
        #[derive(serde::Deserialize)]
        struct SubscriptionId {
            subscription: u32,
        }

        let Ok(subscription_id) = request_params.deserialize::<SubscriptionId>() else {
            return ResponseEvent::InvalidParams(request_id.into());
        };

        let success = match self.subscriptions.remove(&subscription_id.subscription) {
            Some(handle) => {
                handle.abort();
                handle.await;
                true
            }
            None => false,
        };

        ResponseEvent::Unsubscribed {
            success,
            request_id: request_id.into(),
        }
    }

    fn subscribe(
        &mut self,
        request_id: RequestId<'_>,
        request_params: RawParams<'_>,
        msg_sender: mpsc::Sender<ResponseEvent>,
        websocket_source: WebsocketSenders,
    ) -> ResponseEvent {
        #[derive(serde::Deserialize)]
        struct Kind<'a> {
            #[serde(borrow)]
            kind: Cow<'a, str>,
        }

        let Ok(kind) = request_params.deserialize::<Kind<'_>>() else {
            return ResponseEvent::InvalidParams(request_id.into());
        };

        let subscription_id = self.next_id;
        self.next_id += 1;
        let handle = match kind.kind.as_ref() {
            "newHeads" => tokio::spawn(header_subscription(
                msg_sender.clone(),
                websocket_source.new_head.0.subscribe(),
                subscription_id,
            )),
            _ => return ResponseEvent::InvalidParams(request_id.into()),
        };

        self.subscriptions.insert(subscription_id, handle);

        ResponseEvent::Subscribed {
            subscription_id,
            request_id: request_id.into(),
        }
    }

    fn abort_all(self) {
        for (_, handle) in self.subscriptions {
            handle.abort();
        }
    }
}

enum OwnedRequestId {
    Number(i64),
    String(String),
    Null,
    Notification,
}

impl From<RequestId<'_>> for OwnedRequestId {
    fn from(value: RequestId<'_>) -> Self {
        match value {
            RequestId::Number(x) => OwnedRequestId::Number(x),
            RequestId::String(x) => OwnedRequestId::String(x.into_owned()),
            RequestId::Null => OwnedRequestId::Null,
            RequestId::Notification => OwnedRequestId::Notification,
        }
    }
}

impl<'a> From<&'a OwnedRequestId> for RequestId<'a> {
    fn from(value: &'a OwnedRequestId) -> Self {
        match value {
            OwnedRequestId::Number(x) => RequestId::Number(*x),
            OwnedRequestId::String(x) => RequestId::String(x.into()),
            OwnedRequestId::Null => RequestId::Null,
            OwnedRequestId::Notification => RequestId::Notification,
        }
    }
}

enum ResponseEvent {
    Subscribed {
        subscription_id: u32,
        request_id: OwnedRequestId,
    },
    Unsubscribed {
        success: bool,
        request_id: OwnedRequestId,
    },
    SubscriptionClosed {
        subscription_id: u32,
        reason: String,
    },
    InvalidRequest,
    InvalidMethod(OwnedRequestId),
    InvalidParams(OwnedRequestId),
    Header(SubscriptionItem<BlockHeader>),
}

impl ResponseEvent {
    fn kind(&self) -> &'static str {
        match self {
            ResponseEvent::InvalidRequest => "InvalidRequest",
            ResponseEvent::InvalidMethod(_) => "InvalidMethod",
            ResponseEvent::Header(_) => "BlockHeader",
            ResponseEvent::Subscribed { .. } => "Subscribed",
            ResponseEvent::Unsubscribed { .. } => "Unsubscribed",
            ResponseEvent::SubscriptionClosed { .. } => "SubscriptionClosed",
            ResponseEvent::InvalidParams(_) => "InvalidParams",
        }
    }
}

async fn write(
    mut sender: SplitSink<WebSocket, Message>,
    mut msg_receiver: mpsc::Receiver<ResponseEvent>,
) {
    let mut sender = sender.buffer(100);
    while let Some(response) = msg_receiver.recv().await {
        let message = match serde_json::to_vec(&response) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, kind=response.kind(), "Encoding websocket message failed");
                break;
            }
        };

        // TODO: send() mentions that feed() should be preferred but it doesn't quite make sense to me.
        // TODO: should this have a timeout so we don't get stuck here? No, the underlying websocket has
        //       a configurable capacity i.e. an internal buffer where it will error if not handled..
        if let Err(e) = sender.send(Message::Binary(message)).await {
            // What could cause this failure? Probably the client closing the connection.. And a full buffer.
            tracing::debug!(error=%e, "Sending websocket message failed");
            break;
        }
    }
}

async fn header_subscription(
    msg_sender: mpsc::Sender<ResponseEvent>,
    mut headers: tokio::sync::broadcast::Receiver<BlockHeader>,
    subscription_id: u32,
) {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        let response = match headers.recv().await {
            Ok(header) => ResponseEvent::Header(SubscriptionItem {
                subscription_id,
                item: header,
            }),
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(amount)) => {
                tracing::debug!(
                    amount,
                    "Broken header stream, missed some events, closing subscription"
                );

                ResponseEvent::SubscriptionClosed {
                    subscription_id,
                    reason: "Broken stream, some headers were skipped. Closing subscription."
                        .to_owned(),
                }
            }
        };

        if msg_sender.send(response).await.is_err() {
            break;
        }
    }
}

struct SubscriptionItem<T> {
    subscription_id: u32,
    item: T,
}

impl<T: Serialize> Serialize for SubscriptionItem<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ResultHelper<'a, U: Serialize> {
            subscription: u32,
            result: &'a U,
        }

        use serde::ser::SerializeMap;
        let mut obj = serializer.serialize_map(Some(3))?;
        obj.serialize_entry("jsonrpc", "2.0")?;
        obj.serialize_entry("method", "pathfinder_subscription")?;
        obj.serialize_entry(
            "result",
            &ResultHelper {
                subscription: self.subscription_id,
                result: &self.item,
            },
        )?;
        obj.end()
    }
}

impl Serialize for ResponseEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ResponseEvent::InvalidRequest => RpcResponse::INVALID_REQUEST.serialize(serializer),
            ResponseEvent::InvalidMethod(id) => {
                RpcResponse::method_not_found(id.into()).serialize(serializer)
            }
            ResponseEvent::InvalidParams(id) => {
                RpcResponse::invalid_params(id.into()).serialize(serializer)
            }
            ResponseEvent::Header(header) => header.serialize(serializer),
            ResponseEvent::Subscribed {
                subscription_id,
                request_id,
            } => todo!(),
            ResponseEvent::Unsubscribed {
                success,
                request_id,
            } => todo!(),
            ResponseEvent::SubscriptionClosed {
                subscription_id,
                reason,
            } => todo!(),
        }
    }
}
