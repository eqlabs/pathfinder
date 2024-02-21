//! See [the parent module documentation](super)

use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::jsonrpc::request::RawParams;
use crate::jsonrpc::{RequestId, RpcRequest};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::sink::Buffer;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};
use tracing::error;

use crate::jsonrpc::websocket::data::{Kind, ResponseEvent, SubscriptionId, SubscriptionItem};
use crate::BlockHeader;

const SUBSCRIBE_METHOD: &str = "pathfinder_subscribe";
const UNSUBSCRIBE_METHOD: &str = "pathfinder_unsubscribe";
const NEW_HEADS_TOPIC: &str = "newHeads";

#[derive(Clone)]
pub struct WebsocketContext {
    socket_buffer_capacity: NonZeroUsize,
    pub broadcasters: TopicBroadcasters,
}

impl WebsocketContext {
    pub fn new(socket_buffer_capacity: NonZeroUsize, topic_sender_capacity: NonZeroUsize) -> Self {
        let senders = TopicBroadcasters::with_capacity(topic_sender_capacity);

        Self {
            socket_buffer_capacity,
            broadcasters: senders,
        }
    }
}

impl Default for WebsocketContext {
    fn default() -> Self {
        Self {
            socket_buffer_capacity: NonZeroUsize::new(100)
                .expect("Invalid socket buffer capacity default value"),
            broadcasters: TopicBroadcasters::default(),
        }
    }
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<WebsocketContext>,
) -> impl IntoResponse {
    let mut upgrade_response = ws.on_upgrade(|socket| handle_socket(socket, state));

    static APPLICATION_JSON: http::HeaderValue = http::HeaderValue::from_static("application/json");
    upgrade_response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, APPLICATION_JSON.clone());

    upgrade_response
}

async fn handle_socket(socket: WebSocket, context: WebsocketContext) {
    let (ws_sender, ws_receiver) = socket.split();

    let (response_sender, response_receiver) = mpsc::channel(10);

    tokio::spawn(write(
        ws_sender,
        response_receiver,
        context.socket_buffer_capacity,
    ));
    tokio::spawn(read(ws_receiver, response_sender, context.broadcasters));
}

async fn write(
    sender: SplitSink<WebSocket, Message>,
    mut response_receiver: mpsc::Receiver<ResponseEvent>,
    buffer_capacity: NonZeroUsize,
) {
    let mut sender = sender.buffer(buffer_capacity.get());
    while let Some(response) = response_receiver.recv().await {
        if let ControlFlow::Break(()) = send_response(&mut sender, &response).await {
            break;
        }
    }
}

async fn send_response(
    sender: &mut Buffer<SplitSink<WebSocket, Message>, Message>,
    response: &ResponseEvent,
) -> ControlFlow<()> {
    let message = match serde_json::to_string(&response) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error=%e, kind=response.kind(), "Encoding websocket message failed");
            return ControlFlow::Break(());
        }
    };

    // `send` implies a systematical flush.
    // We may want to poll the receiver less eagerly, flushing only once the `recv` is
    // `NotReady`, but because we won't get multiple heads coming in a row I fear this would
    // bring noticeable complexity for a negligible improvement
    if let Err(e) = sender.send(Message::Text(message)).await {
        // What could cause this failure? Probably the client closing the connection.. And a full buffer.
        tracing::debug!(error=%e, "Sending websocket message failed");
        return ControlFlow::Break(());
    }

    ControlFlow::Continue(())
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    response_sender: mpsc::Sender<ResponseEvent>,
    source: TopicBroadcasters,
) {
    let mut subscription_manager = SubscriptionManager::default();

    loop {
        let request = match receiver.next().await {
            Some(Ok(Message::Text(x))) => x.into_bytes(),
            Some(Ok(Message::Binary(x))) => x,
            Some(Ok(Message::Ping(_)))
            | Some(Ok(Message::Pong(_)))
            | Some(Ok(Message::Close(_))) => continue,
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

        let request = match serde_json::from_slice::<RpcRequest<'_>>(&request) {
            Ok(request) => request,
            Err(err) => {
                match response_sender.try_send(ResponseEvent::InvalidRequest(err.to_string())) {
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::debug!(reason=%e, "Failed to send invalid request response");
                        break;
                    }
                }
            }
        };

        // Handle request.
        let response = match request.method.as_ref() {
            SUBSCRIBE_METHOD => subscription_manager.subscribe(
                request.id,
                request.params,
                response_sender.clone(),
                source.clone(),
            ),
            UNSUBSCRIBE_METHOD => {
                subscription_manager
                    .unsubscribe(request.id, request.params)
                    .await
            }
            _ => ResponseEvent::InvalidMethod(request.id.into()),
        };

        if let Err(e) = response_sender.try_send(response) {
            tracing::debug!(reason=%e, "Failed to send response");
            break;
        }
    }

    // Force some clean up by aborting all still running subscriptions.
    // These would naturally come to a halt as the message queues break,
    // but this will kill them more quickly.
    subscription_manager.abort_all();
}

/// Manages the subscription for a single connection
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
        let subscription_id = match request_params.deserialize::<SubscriptionId>() {
            Ok(x) => x,
            Err(crate::jsonrpc::RpcError::InvalidParams(e)) => {
                return ResponseEvent::InvalidParams(request_id.into(), e)
            }
            Err(_) => {
                return ResponseEvent::InvalidParams(
                    request_id.into(),
                    "Unexpected parsing error".to_owned(),
                )
            }
        };

        let success = match self.subscriptions.remove(&subscription_id.id) {
            Some(handle) => {
                handle.abort();
                if let Some(err) = handle.await.err().filter(|e| !e.is_cancelled()) {
                    error!("Websocket subscription join error: {}", err);
                }
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
        response_sender: mpsc::Sender<ResponseEvent>,
        websocket_source: TopicBroadcasters,
    ) -> ResponseEvent {
        let kind = match request_params.deserialize::<Kind<'_>>() {
            Ok(x) => x,
            Err(crate::jsonrpc::RpcError::InvalidParams(e)) => {
                return ResponseEvent::InvalidParams(request_id.into(), e)
            }
            Err(_) => {
                return ResponseEvent::InvalidParams(
                    request_id.into(),
                    "Unexpected parsing error".to_owned(),
                )
            }
        };

        let subscription_id = self.next_id;
        self.next_id += 1;
        let receiver = websocket_source.new_head.subscribe();
        let handle = match kind.kind.as_ref() {
            NEW_HEADS_TOPIC => tokio::spawn(header_subscription(
                response_sender,
                receiver,
                subscription_id,
            )),
            _ => {
                return ResponseEvent::InvalidParams(
                    request_id.into(),
                    "Unknown subscription type".to_owned(),
                )
            }
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

async fn header_subscription(
    msg_sender: mpsc::Sender<ResponseEvent>,
    mut headers: broadcast::Receiver<Arc<Value>>,
    subscription_id: u32,
) {
    use broadcast::error::RecvError;
    loop {
        let response = match headers.recv().await {
            Ok(header) => ResponseEvent::Header(SubscriptionItem {
                subscription_id,
                item: header,
            }),
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(amount)) => {
                tracing::info!(
                    amount,
                    "Lagging header stream, missed some events, closing subscription"
                );

                // No explicit break here, the loop will be broken by the dropped receiver.
                ResponseEvent::SubscriptionClosed {
                    subscription_id,
                    reason: "Lagging stream, some headers were skipped. Closing subscription."
                        .to_owned(),
                }
            }
        };

        if msg_sender.send(response).await.is_err() {
            break;
        }
    }
}

/// A Tokio broadcast sender pre-serializing the value once for all subscribers.
/// Relies on `Arc`s to flatten the cloning costs inherent to Tokio broadcast channels.
#[derive(Debug, Clone)]
pub struct JsonBroadcaster<T> {
    sender: broadcast::Sender<Arc<Value>>,
    item_type: PhantomData<T>,
}

impl<T> JsonBroadcaster<T>
where
    T: Serialize,
{
    pub fn send_if_receiving(&self, item: T) -> Result<(), serde_json::Error> {
        if self.sender.receiver_count() > 0 {
            tracing::debug!("Broadcasting");

            // This won't cut all of serialization costs but it's a simple compromise.
            // At least things like string encoding will be performed once only.
            let value = serde_json::to_value(item)?;
            // Tokio broadcast channels clone the items for each subscriber.
            // Embed the value in an `Arc` to flatten this cost.
            let value = Arc::new(value);

            if let Err(err) = self.sender.send(value) {
                tracing::warn!("Broadcasting failed, the buffer might be full: {}", err);
            }
        } else {
            tracing::debug!("No receivers, skipping the broadcast");
        }

        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Value>> {
        self.sender.subscribe()
    }
}

#[derive(Debug, Clone)]
pub struct TopicBroadcasters {
    pub new_head: JsonBroadcaster<BlockHeader>,
}

impl TopicBroadcasters {
    fn with_capacity(capacity: NonZeroUsize) -> TopicBroadcasters {
        TopicBroadcasters {
            new_head: JsonBroadcaster {
                sender: broadcast::channel(capacity.get()).0,
                item_type: PhantomData {},
            },
        }
    }
}

impl Default for TopicBroadcasters {
    fn default() -> Self {
        TopicBroadcasters::with_capacity(
            NonZeroUsize::new(100).expect("Invalid default broadcaster capacity"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::websocket::data::successful_response;
    use crate::jsonrpc::{RpcError, RpcResponse};
    use axum::routing::get;
    use futures::{SinkExt, StreamExt};
    use serde::Serialize;
    use serde_json::value::RawValue;
    use serde_json::{json, Number, Value};
    use std::borrow::Cow;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

    #[tokio::test]
    async fn params_are_required() {
        let mut client = Client::new().await;

        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: Default::default(),
                id: RequestId::Null,
            })
            .await;

        client
            .expect_response(&RpcResponse {
                output: Err(RpcError::InvalidParams(
                    "EOF while parsing a value at line 1 column 0".to_owned(),
                )),
                id: RequestId::Null,
            })
            .await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn can_subscribe() {
        let mut client = Client::new().await;

        let req_id = RequestId::Number(37);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(&value(&Kind {
                    kind: NEW_HEADS_TOPIC.into(),
                }))),
                id: req_id.clone(),
            })
            .await;

        let expected_subscription_id = 0;
        client
            .expect_response(&successful_response(&expected_subscription_id, req_id).unwrap())
            .await;

        // Do this a bunch of times to ensure the test reception timeout is long enough.
        for _i in 0..10 {
            let header = header_sample();
            client
                .head_sender
                .send_if_receiving(header.clone())
                .unwrap();

            client
                .expect_response(&SubscriptionItem {
                    subscription_id: 0,
                    item: header,
                })
                .await;
        }

        let req_id = RequestId::String("req_id".into());
        client
            .send_request(&RpcRequest {
                method: Cow::from(UNSUBSCRIBE_METHOD),
                params: RawParams(Some(&value(&SubscriptionId {
                    id: expected_subscription_id,
                }))),
                id: req_id.clone(),
            })
            .await;
        client
            .expect_response(&successful_response(&true, req_id).unwrap())
            .await;

        // Now make sure we don't receive it. This is why testing the timeout was important.
        client
            .head_sender
            .send_if_receiving(header_sample())
            .unwrap();
        client.expect_no_response().await;

        client.destroy().await;
    }

    // TODO Prevent duplicate subscriptions?
    // This is actually tolerated by Alchemy, you can subscribe multiple times
    // to the same topic and receive duplicated messages as a result.
    // TODO Subscription limit?

    fn value<S>(payload: &S) -> Box<RawValue>
    where
        S: Serialize + ?Sized,
    {
        RawValue::from_string(serde_json::to_string(payload).unwrap()).unwrap()
    }

    fn header_sample() -> BlockHeader {
        BlockHeader(Default::default())
    }

    struct Client {
        sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        receiver: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        server_handle: JoinHandle<()>,
        head_sender: JsonBroadcaster<BlockHeader>,
    }

    impl Client {
        async fn new() -> Client {
            let context = WebsocketContext::default();
            let head_sender = context.broadcasters.new_head.clone();

            let router = axum::Router::new()
                .route("/ws", get(websocket_handler))
                .with_state(context)
                .layer(tower::ServiceBuilder::new());

            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("Websocket address already in use");
            let addr = listener.local_addr().unwrap();
            let server = axum::Server::from_tcp(listener).unwrap();
            let server_handle =
                tokio::spawn(
                    async move { server.serve(router.into_make_service()).await.unwrap() },
                );

            let ws_addr = "ws://".to_string() + &addr.to_string() + "/ws";
            let ws_stream = match connect_async(ws_addr).await {
                Ok((stream, _response)) => stream,
                Err(e) => {
                    panic!("WebSocket handshake failed with {e}!");
                }
            };

            let (sender, receiver) = ws_stream.split();

            Client {
                head_sender,
                sender,
                receiver,
                server_handle,
            }
        }

        async fn send_request(&mut self, request: &RpcRequest<'_>) {
            let id = match &request.id {
                RequestId::Number(n) => Value::Number(Number::from(*n)),
                RequestId::String(s) => Value::String(s.to_string()),
                RequestId::Null => Value::Null,
                RequestId::Notification => Value::String("notification".to_string()),
            };
            let json = serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": request.method,
                "id": id,
                "params": request.params,
            }))
            .unwrap();
            self.sender.send(Message::Text(json)).await.unwrap();
        }

        async fn expect_response<R>(&mut self, response: &R)
        where
            R: Serialize,
        {
            let message = timeout(Duration::from_millis(100), self.receiver.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Message::Text(raw_text) = message else {
                panic!("Unexpected type of message")
            };

            // Deserialize it to a generic value to avoid field ordering issues.
            let received: Value = serde_json::from_str(&raw_text).unwrap();
            let expected = serde_json::to_value(response).unwrap();
            assert_eq!(received, expected);
        }

        async fn expect_no_response(&mut self) {
            let timeout_result = timeout(Duration::from_millis(100), self.receiver.next()).await;

            match timeout_result {
                Ok(Some(_)) => {
                    panic!("Unexpected message received")
                }
                Ok(None) => {
                    panic!("Connection closed unexpectedly")
                }
                Err(_) => {
                    // Expected
                }
            }
        }

        async fn destroy(mut self) {
            self.sender.send(Message::Close(None)).await.unwrap();

            self.server_handle.abort();
            let _ignored = self.server_handle.await;
        }
    }
}
