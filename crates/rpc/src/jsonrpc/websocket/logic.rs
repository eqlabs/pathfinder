//! See [the parent module documentation](super)

use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::sink::Buffer;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use pathfinder_common::{BlockNumber, TransactionHash};
use serde::Serialize;
use serde_json::Value;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::transaction_status::{ExecutionStatus, FinalityStatus};
use starknet_gateway_types::reply::Block;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::error;

use super::{EmittedEvent, Params, TransactionStatusUpdate};
use crate::dto::serialize::{self, SerializeForVersion};
use crate::error::ApplicationError;
use crate::jsonrpc::request::RawParams;
use crate::jsonrpc::router::RpcRequestError;
use crate::jsonrpc::websocket::data::{
    EventFilterParams,
    ResponseEvent,
    SubscriptionId,
    SubscriptionItem,
};
use crate::jsonrpc::{RequestId, RpcError, RpcRequest, RpcRouter};
use crate::{BlockHeader, PendingData, RpcVersion};

const SUBSCRIBE_METHOD: &str = "pathfinder_subscribe";
const UNSUBSCRIBE_METHOD: &str = "pathfinder_unsubscribe";

#[derive(Clone)]
pub struct WebsocketContext {
    socket_buffer_capacity: NonZeroUsize,
    pub broadcasters: TopicBroadcasters,
}

impl WebsocketContext {
    pub fn new(
        socket_buffer_capacity: NonZeroUsize,
        topic_sender_capacity: NonZeroUsize,
        pending_data: watch::Receiver<PendingData>,
    ) -> Self {
        Self {
            socket_buffer_capacity,
            broadcasters: TopicBroadcasters::new(topic_sender_capacity, pending_data),
        }
    }
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(router): State<RpcRouter>,
) -> impl IntoResponse {
    let mut upgrade_response = ws
        .max_message_size(crate::REQUEST_MAX_SIZE)
        .on_failed_upgrade(|error| tracing::debug!(%error, "Websocket upgrade failed"))
        .on_upgrade(|socket| handle_socket(socket, router));

    static APPLICATION_JSON: http::HeaderValue = http::HeaderValue::from_static("application/json");
    upgrade_response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, APPLICATION_JSON.clone());

    upgrade_response
}

async fn handle_socket(socket: WebSocket, router: RpcRouter) {
    let websocket_context = router
        .context
        .websocket
        .as_ref()
        .expect("Websocket handler should not be called with Websocket disabled");
    let (ws_sender, ws_receiver) = socket.split();

    let (response_sender, response_receiver) = mpsc::channel(10);

    tokio::spawn(write(
        ws_sender,
        response_receiver,
        websocket_context.socket_buffer_capacity,
        router.version,
    ));
    tokio::spawn(read(ws_receiver, response_sender, router));
}

async fn write(
    sender: SplitSink<WebSocket, Message>,
    mut response_receiver: mpsc::Receiver<ResponseEvent>,
    buffer_capacity: NonZeroUsize,
    version: RpcVersion,
) {
    let mut sender = sender.buffer(buffer_capacity.get());
    while let Some(response) = response_receiver.recv().await {
        if let ControlFlow::Break(()) = send_response(&mut sender, &response, version).await {
            break;
        }
    }
}

async fn send_response(
    sender: &mut Buffer<SplitSink<WebSocket, Message>, Message>,
    response: &ResponseEvent,
    version: RpcVersion,
) -> ControlFlow<()> {
    let message = match serde_json::to_string(
        &response
            .serialize(serialize::Serializer::new(version))
            .unwrap(),
    ) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error=%e, kind=response.kind(), "Encoding websocket message failed");
            return ControlFlow::Break(());
        }
    };

    // `send` implies a systematical flush.
    // We may want to poll the receiver less eagerly, flushing only once the `recv`
    // is `NotReady`, but because we won't get multiple heads coming in a row I
    // fear this would bring noticeable complexity for a negligible improvement
    if let Err(e) = sender.send(Message::Text(message)).await {
        // What could cause this failure? Probably the client closing the connection..
        // And a full buffer.
        tracing::debug!(error=%e, "Sending websocket message failed");
        return ControlFlow::Break(());
    }

    ControlFlow::Continue(())
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    response_sender: mpsc::Sender<ResponseEvent>,
    router: RpcRouter,
) {
    let websocket_context = router
        .context
        .websocket
        .as_ref()
        .expect("Websocket handler should not be called with Websocket disabled");
    let source = &websocket_context.broadcasters;
    let mut subscription_manager = SubscriptionManager::default();

    loop {
        let request = match receiver.next().await {
            Some(Ok(Message::Text(x))) => x.into_bytes(),
            Some(Ok(Message::Binary(x))) => x,
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                // Ping and pong messages are handled automatically by axum.
                continue;
            }
            // All of the following indicate client disconnection.
            Some(Err(e)) => {
                tracing::trace!(error=%e, "Client disconnected");
                break;
            }
            Some(Ok(Message::Close(_))) | None => {
                tracing::trace!("Client disconnected");
                break;
            }
        };

        let parsed_request = match serde_json::from_slice::<RpcRequest<'_>>(&request) {
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
        let response = match parsed_request.method.as_ref() {
            SUBSCRIBE_METHOD => match subscription_manager.subscribe(
                parsed_request.id.clone(),
                parsed_request.params,
                response_sender.clone(),
                source.clone(),
                router.context.sequencer.clone(),
            ) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(error=%e, "Failed to subscribe");
                    ResponseEvent::InternalError(parsed_request.id, e)
                }
            },
            UNSUBSCRIBE_METHOD => {
                subscription_manager
                    .unsubscribe(parsed_request.id, parsed_request.params)
                    .await
            }
            _ => match super::super::router::handle_json_rpc_body(&router, &request).await {
                Ok(responses) => ResponseEvent::Responses(responses),
                Err(RpcRequestError::ParseError(e)) => ResponseEvent::InvalidRequest(e),
                Err(RpcRequestError::InvalidRequest(e)) => ResponseEvent::InvalidRequest(e),
            },
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
        request_id: RequestId,
        request_params: RawParams<'_>,
    ) -> ResponseEvent {
        let subscription_id = match request_params.deserialize::<SubscriptionId>() {
            Ok(x) => x,
            Err(crate::jsonrpc::RpcError::InvalidParams(e)) => {
                return ResponseEvent::InvalidParams(request_id, e)
            }
            Err(_) => {
                return ResponseEvent::InvalidParams(
                    request_id,
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
            request_id,
        }
    }

    fn subscribe(
        &mut self,
        request_id: RequestId,
        request_params: RawParams<'_>,
        response_sender: mpsc::Sender<ResponseEvent>,
        websocket_source: TopicBroadcasters,
        gateway: impl GatewayApi + Send + 'static,
    ) -> anyhow::Result<ResponseEvent> {
        let params = match request_params.deserialize::<Params>() {
            Ok(x) => x,
            Err(crate::jsonrpc::RpcError::InvalidParams(e)) => {
                return Ok(ResponseEvent::InvalidParams(request_id, e))
            }
            Err(_) => {
                return Ok(ResponseEvent::InvalidParams(
                    request_id,
                    "Unexpected parsing error".to_owned(),
                ))
            }
        };

        let subscription_id = self.next_id;
        self.next_id += 1;
        let handle = match params {
            Params::NewHeads => {
                let receiver = websocket_source.new_head.subscribe();
                tokio::spawn(header_subscription(
                    response_sender,
                    receiver,
                    subscription_id,
                ))
            }
            Params::Events(filter) => {
                let l2_blocks = websocket_source.l2_blocks.subscribe();
                let pending_data = websocket_source.pending_data.clone();
                tokio::spawn(event_subscription(
                    response_sender,
                    l2_blocks,
                    pending_data,
                    subscription_id,
                    filter,
                ))
            }
            Params::TransactionStatus(params) => tokio::spawn(transaction_status_subscription(
                response_sender,
                subscription_id,
                params.transaction_hash,
                gateway,
            )),
        };

        self.subscriptions.insert(subscription_id, handle);

        Ok(ResponseEvent::Subscribed {
            subscription_id,
            request_id,
        })
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
    loop {
        let response = match headers.recv().await {
            Ok(header) => ResponseEvent::Header(SubscriptionItem {
                subscription_id,
                item: header,
            }),
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(amount)) => {
                tracing::debug!(%subscription_id, %amount, kind="header", "Subscription consumer too slow, closing.");

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

async fn event_subscription(
    msg_sender: mpsc::Sender<ResponseEvent>,
    mut l2_blocks: broadcast::Receiver<Arc<Block>>,
    mut pending_data: watch::Receiver<PendingData>,
    subscription_id: u32,
    filter: EventFilterParams,
) {
    let key_filter_is_empty = filter.keys.iter().flatten().count() == 0;
    let keys: Vec<std::collections::HashSet<_>> = filter
        .keys
        .iter()
        .map(|keys| keys.iter().collect())
        .collect();
    let mut last_block: Option<BlockNumber> = None;
    let mut next_receipt_idx = 0;
    'outer: loop {
        let (receipts, block_number) = loop {
            tokio::select! {
                result = pending_data.changed() => {
                    match result {
                        Ok(()) => {
                            let data = pending_data.borrow();
                            if data.number.get() == 0 || last_block.map(|b| b.get()) != Some(data.number.get() - 1) {
                                // This pending update comes too early, ignore it for now. The
                                // same block will be received from the l2_blocks stream.
                                continue;
                            }
                            if data.block.transaction_receipts.len() <= next_receipt_idx {
                                // No new receipts in this update, ignore it.
                                continue;
                            }
                            let receipts = data.block.transaction_receipts[next_receipt_idx..].to_vec();
                            next_receipt_idx = data.block.transaction_receipts.len();
                            break (receipts, data.number);
                        }
                        Err(_) => {
                            tracing::debug!(%subscription_id, kind="event", "Unable to fetch pending data, closing.");
                            let response = ResponseEvent::SubscriptionClosed {
                                subscription_id,
                                reason: "Unable to fetch pending data. Closing subscription."
                                    .to_owned(),
                            };
                            msg_sender.send(response).await.ok();
                            break 'outer;
                        }
                    }
                }
                result = l2_blocks.recv() => {
                    match result {
                        Ok(block) => {
                            if let Some(last_block) = last_block {
                                if block.block_number.get() <= last_block.get() {
                                    // Should not be possible.
                                    tracing::warn!(
                                        %subscription_id,
                                        %block.block_number,
                                        %last_block,
                                        kind="event",
                                        "Received block out of order, closing.",
                                    );
                                    break 'outer;
                                }
                            }
                            if block.transaction_receipts.len() <= next_receipt_idx {
                                // No new receipts in this update, ignore it.
                                next_receipt_idx = 0;
                                last_block = Some(block.block_number);
                                continue;
                            }
                            let receipts = block.transaction_receipts[next_receipt_idx..].to_vec();
                            next_receipt_idx = 0;
                            last_block = Some(block.block_number);
                            break (receipts, block.block_number)
                        },
                        Err(RecvError::Closed) => break 'outer,
                        Err(RecvError::Lagged(amount)) => {
                            tracing::debug!(%subscription_id, %amount, kind="event", "Subscription consumer too slow, closing.");
                            let response = ResponseEvent::SubscriptionClosed {
                                subscription_id,
                                reason: "Lagging stream, some events were skipped. Closing subscription."
                                    .to_owned(),
                            };
                            msg_sender.send(response).await.ok();
                            break 'outer;
                        }
                    }
                },
            }
        };
        for (receipt, events) in receipts {
            for event in events {
                // Check if the event matches the filter.
                if let Some(address) = filter.address {
                    if event.from_address != address {
                        continue;
                    }
                }
                let matches_keys = if key_filter_is_empty {
                    true
                } else if event.keys.len() < keys.len() {
                    false
                } else {
                    event
                        .keys
                        .iter()
                        .zip(keys.iter())
                        .all(|(key, filter)| filter.is_empty() || filter.contains(key))
                };
                if !matches_keys {
                    continue;
                }

                let response = ResponseEvent::Event(SubscriptionItem {
                    subscription_id,
                    item: Arc::new(EmittedEvent {
                        data: event.data,
                        keys: event.keys,
                        from_address: event.from_address,
                        block_hash: None,
                        block_number: Some(block_number),
                        transaction_hash: receipt.transaction_hash,
                    }),
                });
                if msg_sender.send(response).await.is_err() {
                    break 'outer;
                }
            }
        }
    }
}

async fn transaction_status_subscription(
    msg_sender: mpsc::Sender<ResponseEvent>,
    subscription_id: u32,
    transaction_hash: TransactionHash,
    gateway: impl GatewayApi + Send + 'static,
) {
    let mut last_status = None;
    let start = Instant::now();
    let timeout = if cfg!(test) {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(10)
    };
    let mut poll_interval = tokio::time::interval(Duration::from_millis(500));
    let mut num_consecutive_errors = 0;
    loop {
        match gateway.transaction_status(transaction_hash).await {
            Ok(tx_status) => {
                num_consecutive_errors = 0;

                let execution_status = tx_status.execution_status.unwrap_or_default();

                let update = match (tx_status.finality_status, execution_status) {
                    (_, ExecutionStatus::Rejected) => Some(TransactionStatusUpdate::Rejected),
                    (FinalityStatus::NotReceived, _) => {
                        // "NOT_RECEIVED" status is never sent to the client.
                        if start.elapsed() > timeout {
                            // The transaction was not found on the gateway after some time.
                            // This means the transaction is probably not valid.
                            msg_sender
                                .send(ResponseEvent::RpcError(RpcError::ApplicationError(
                                    ApplicationError::SubscriptionTransactionHashNotFound {
                                        transaction_hash,
                                        subscription_id,
                                    },
                                )))
                                .await
                                .ok();
                            break;
                        }
                        None
                    }
                    (FinalityStatus::Received, _) => Some(TransactionStatusUpdate::Received),
                    (
                        FinalityStatus::AcceptedOnL1 | FinalityStatus::AcceptedOnL2,
                        ExecutionStatus::Succeeded,
                    ) => Some(TransactionStatusUpdate::Succeeded),
                    (
                        FinalityStatus::AcceptedOnL1 | FinalityStatus::AcceptedOnL2,
                        ExecutionStatus::Reverted,
                    ) => Some(TransactionStatusUpdate::Reverted),
                };
                let status_changed = match (last_status, update) {
                    (Some(last), Some(update)) => last < update,
                    (None, Some(_)) => true,
                    (Some(_), None) => false,
                    (None, None) => false,
                };
                if status_changed {
                    // Status changed, send an update to the client.
                    last_status = update;
                    if msg_sender
                        .send(ResponseEvent::TransactionStatus(SubscriptionItem {
                            subscription_id,
                            item: Arc::new(update.unwrap()),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                if execution_status == ExecutionStatus::Rejected
                    || tx_status.finality_status == FinalityStatus::AcceptedOnL1
                    || tx_status.finality_status == FinalityStatus::AcceptedOnL2
                {
                    // Final status reached, close the subscription.
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(%transaction_hash, %e, "Failed to poll transaction status");
                num_consecutive_errors += 1;
                if num_consecutive_errors == 5 {
                    msg_sender
                        .send(ResponseEvent::RpcError(RpcError::ApplicationError(
                            ApplicationError::SubscriptionGatewayDown { subscription_id },
                        )))
                        .await
                        .ok();
                    break;
                }
            }
        }
        poll_interval.tick().await;
    }
}

/// A Tokio broadcast sender pre-serializing the value once for all subscribers.
/// Relies on `Arc`s to flatten the cloning costs inherent to Tokio broadcast
/// channels.
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
    pub l2_blocks: broadcast::Sender<Arc<Block>>,
    pub pending_data: watch::Receiver<PendingData>,
}

impl TopicBroadcasters {
    fn new(
        capacity: NonZeroUsize,
        pending_data: watch::Receiver<PendingData>,
    ) -> TopicBroadcasters {
        TopicBroadcasters {
            new_head: JsonBroadcaster {
                sender: broadcast::channel(capacity.get()).0,
                item_type: PhantomData {},
            },
            l2_blocks: broadcast::channel(capacity.get()).0,
            pending_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use axum::routing::get;
    use futures::{SinkExt, StreamExt};
    use pathfinder_common::event::Event;
    use pathfinder_common::transaction::Transaction;
    use pathfinder_common::{
        block_hash,
        event_commitment,
        event_key,
        receipt_commitment,
        state_commitment,
        state_diff_commitment,
        transaction_commitment,
        transaction_hash,
        BlockNumber,
        BlockTimestamp,
        ContractAddress,
        EventData,
        EventKey,
        GasPrice,
        SequencerAddress,
        StarknetVersion,
    };
    use pathfinder_crypto::Felt;
    use pretty_assertions_sorted::assert_eq;
    use serde::Serialize;
    use serde_json::value::RawValue;
    use serde_json::{json, Number, Value};
    use starknet_gateway_types::error::SequencerError;
    use starknet_gateway_types::reply::{GasPrices, PendingBlock, Status, TransactionStatus};
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

    use super::*;
    use crate::context::RpcContext;
    use crate::jsonrpc::websocket::data::successful_response;
    use crate::jsonrpc::{RpcError, RpcResponse};

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
                version: RpcVersion::V07,
            })
            .await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn subscribe_new_heads() {
        let mut client = Client::new().await;

        let req_id = RequestId::Number(37);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(r#"["newHeads"]"#.to_owned()).unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        let expected_subscription_id = 0;
        client
            .expect_response(
                &successful_response(&expected_subscription_id, req_id, RpcVersion::V07).unwrap(),
            )
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
            .expect_response(&successful_response(&true, req_id, RpcVersion::V07).unwrap())
            .await;

        // Now make sure we don't receive it. This is why testing the timeout was
        // important.
        client
            .head_sender
            .send_if_receiving(header_sample())
            .unwrap();
        client.expect_no_response().await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn fall_back_to_rpc_method() {
        let mut client = Client::new().await;

        client
            .send_request(&RpcRequest {
                method: Cow::from("pathfinder_test"),
                params: Default::default(),
                id: RequestId::Number(1),
            })
            .await;

        client
            .expect_response(&RpcResponse {
                output: Ok(json!("0x534e5f5345504f4c4941")),
                id: RequestId::Number(1),
                version: RpcVersion::V07,
            })
            .await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn subscribe_events() {
        let mut client = Client::new().await;
        let block = block_sample();

        let req_id = RequestId::Number(37);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(r#"["events"]"#.to_owned()).unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        client
            .expect_response(&successful_response(&0, req_id, RpcVersion::V07).unwrap())
            .await;

        client.l2_blocks.send(block.clone().into()).unwrap();

        client
            .expect_response(&SubscriptionItem {
                subscription_id: 0,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("2").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("a").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("b").unwrap()),
                        event_key!("0xdeadbeef"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1000)),
                    transaction_hash: transaction_hash!("0x1"),
                },
            })
            .await;
        client
            .expect_response(&SubscriptionItem {
                subscription_id: 0,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("c").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("d").unwrap()),
                        event_key!("0xcafebabe"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1000)),
                    transaction_hash: transaction_hash!("0x2"),
                },
            })
            .await;
        client
            .expect_response(&SubscriptionItem {
                subscription_id: 0,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("4").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("e").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("f").unwrap()),
                        event_key!("0x1234"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1000)),
                    transaction_hash: transaction_hash!("0x2"),
                },
            })
            .await;

        client.expect_no_response().await;

        let req_id = RequestId::String("unsub_1".into());
        client
            .send_request(&RpcRequest {
                method: Cow::from(UNSUBSCRIBE_METHOD),
                params: RawParams(Some(&value(&SubscriptionId { id: 0 }))),
                id: req_id.clone(),
            })
            .await;
        client
            .expect_response(&successful_response(&true, req_id, RpcVersion::V07).unwrap())
            .await;

        let req_id = RequestId::Number(38);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(
                        r#"{"kind": "events", "keys": [[], ["0xdeadbeef"]]}"#.to_owned(),
                    )
                    .unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        client
            .expect_response(&successful_response(&1, req_id, RpcVersion::V07).unwrap())
            .await;

        client.l2_blocks.send(block.clone().into()).unwrap();

        client
            .expect_response(&SubscriptionItem {
                subscription_id: 1,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("2").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("a").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("b").unwrap()),
                        event_key!("0xdeadbeef"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1000)),
                    transaction_hash: transaction_hash!("0x1"),
                },
            })
            .await;

        client.expect_no_response().await;

        let req_id = RequestId::String("unsub_2".into());
        client
            .send_request(&RpcRequest {
                method: Cow::from(UNSUBSCRIBE_METHOD),
                params: RawParams(Some(&value(&SubscriptionId { id: 1 }))),
                id: req_id.clone(),
            })
            .await;
        client
            .expect_response(&successful_response(&true, req_id, RpcVersion::V07).unwrap())
            .await;

        let req_id = RequestId::Number(39);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(r#"{"kind": "events", "address": "0x3"}"#.to_owned())
                        .unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        client
            .expect_response(&successful_response(&2, req_id, RpcVersion::V07).unwrap())
            .await;

        client.l2_blocks.send(block.clone().into()).unwrap();

        client
            .expect_response(&SubscriptionItem {
                subscription_id: 2,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("c").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("d").unwrap()),
                        event_key!("0xcafebabe"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1000)),
                    transaction_hash: transaction_hash!("0x2"),
                },
            })
            .await;

        // Receive next pending block.
        client.pending_data_sender.send_replace(PendingData {
            block: PendingBlock {
                l1_gas_price: block.l1_gas_price,
                l1_data_gas_price: block.l1_data_gas_price,
                l2_gas_price: Default::default(), /* TODO: Fix when we get l2_gas_price in the
                                                   * gateway */
                parent_hash: block.block_hash,
                sequencer_address: SequencerAddress::ZERO,
                status: Status::Pending,
                timestamp: Default::default(),
                transaction_receipts: block.transaction_receipts.clone(),
                transactions: block.transactions.clone(),
                starknet_version: block.starknet_version,
                l1_da_mode: block.l1_da_mode,
            }
            .into(),
            number: BlockNumber::new_or_panic(block.block_number.get() + 1),
            state_update: Default::default(),
        });

        client
            .expect_response(&SubscriptionItem {
                subscription_id: 2,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("c").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("d").unwrap()),
                        event_key!("0xcafebabe"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1001)),
                    transaction_hash: transaction_hash!("0x2"),
                },
            })
            .await;

        // Receive additional events in pending block.
        let mut receipts = block.transaction_receipts.clone();
        receipts.push((
            pathfinder_common::receipt::Receipt {
                transaction_hash: transaction_hash!("0x12"),
                ..Default::default()
            },
            vec![Event {
                from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                data: vec![EventData(Felt::from_hex_str("cc").unwrap())],
                keys: vec![
                    EventKey(Felt::from_hex_str("ff").unwrap()),
                    event_key!("0xbeef"),
                ],
            }],
        ));
        client.pending_data_sender.send_replace(PendingData {
            block: PendingBlock {
                l1_gas_price: block.l1_gas_price,
                l1_data_gas_price: block.l1_data_gas_price,
                l2_gas_price: Default::default(), /* TODO: Fix when we get l2_gas_price in the
                                                   * gateway */
                parent_hash: block.block_hash,
                sequencer_address: SequencerAddress::ZERO,
                status: Status::Pending,
                timestamp: Default::default(),
                transaction_receipts: receipts,
                transactions: block.transactions.clone(),
                starknet_version: block.starknet_version,
                l1_da_mode: block.l1_da_mode,
            }
            .into(),
            number: BlockNumber::new_or_panic(block.block_number.get() + 1),
            state_update: Default::default(),
        });

        client
            .expect_response(&SubscriptionItem {
                subscription_id: 2,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("cc").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("ff").unwrap()),
                        event_key!("0xbeef"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1001)),
                    transaction_hash: transaction_hash!("0x12"),
                },
            })
            .await;

        client.expect_no_response().await;

        // Receive same block after confirmation. Nothing happens.
        client
            .l2_blocks
            .send(
                Block {
                    block_number: BlockNumber::new_or_panic(block.block_number.get() + 1),
                    ..block.clone()
                }
                .into(),
            )
            .unwrap();

        client.expect_no_response().await;

        // Pending data comes too early.
        client.pending_data_sender.send_replace(PendingData {
            block: PendingBlock {
                l1_gas_price: block.l1_gas_price,
                l1_data_gas_price: block.l1_data_gas_price,
                l2_gas_price: Default::default(), /* TODO: Fix when we get l2_gas_price in the
                                                   * gateway */
                parent_hash: block.block_hash,
                sequencer_address: SequencerAddress::ZERO,
                status: Status::Pending,
                timestamp: Default::default(),
                transaction_receipts: block.transaction_receipts.clone(),
                transactions: block.transactions.clone(),
                starknet_version: block.starknet_version,
                l1_da_mode: block.l1_da_mode,
            }
            .into(),
            number: BlockNumber::new_or_panic(block.block_number.get() + 3),
            state_update: Default::default(),
        });

        client.expect_no_response().await;

        // Pending data comes after the confirmed block. Nothing should happen when the
        // pending data is received.
        client
            .l2_blocks
            .send(
                Block {
                    block_number: BlockNumber::new_or_panic(block.block_number.get() + 2),
                    ..block.clone()
                }
                .into(),
            )
            .unwrap();
        client
            .expect_response(&SubscriptionItem {
                subscription_id: 2,
                item: EmittedEvent {
                    from_address: ContractAddress::new_or_panic(Felt::from_hex_str("3").unwrap()),
                    data: vec![EventData(Felt::from_hex_str("c").unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str("d").unwrap()),
                        event_key!("0xcafebabe"),
                    ],
                    block_hash: None,
                    block_number: Some(BlockNumber::new_or_panic(1002)),
                    transaction_hash: transaction_hash!("0x2"),
                },
            })
            .await;
        client.pending_data_sender.send_replace(PendingData {
            block: PendingBlock {
                l1_gas_price: block.l1_gas_price,
                l1_data_gas_price: block.l1_data_gas_price,
                l2_gas_price: Default::default(), /* TODO: Fix when we get l2_gas_price in the
                                                   * gateway */
                parent_hash: block.block_hash,
                sequencer_address: SequencerAddress::ZERO,
                status: Status::Pending,
                timestamp: Default::default(),
                transaction_receipts: block.transaction_receipts.clone(),
                transactions: block.transactions.clone(),
                starknet_version: block.starknet_version,
                l1_da_mode: block.l1_da_mode,
            }
            .into(),
            number: BlockNumber::new_or_panic(block.block_number.get() + 2),
            state_update: Default::default(),
        });
        client.expect_no_response().await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn subscribe_transaction_status() {
        let mut client = Client::new().await;

        let req_id = RequestId::Number(37);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(
                        r#"{"kind": "transactionStatus", "transaction_hash": "0x032bfcf2a36fafe6030c619d9245b37f0717449e7e5f4a0875e14a674c831ba0"}"#.to_owned(),
                    )
                    .unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        client
            .expect_response(&successful_response(&0, req_id, RpcVersion::V07).unwrap())
            .await;

        client
            .expect_response(&json!({
                "jsonrpc": "2.0",
                "method": "pathfinder_subscription",
                "result": {
                    "subscription": 0,
                    "result": "SUCCEEDED",
                }
            }))
            .await;

        client.expect_no_response().await;

        client.destroy().await;
    }

    #[tokio::test]
    async fn subscribe_transaction_status_mocked_succeeded() {
        struct Mock(Mutex<VecDeque<TransactionStatus>>);

        #[async_trait::async_trait]
        impl GatewayApi for Mock {
            async fn transaction_status(
                &self,
                transaction_hash: TransactionHash,
            ) -> Result<TransactionStatus, SequencerError> {
                assert_eq!(transaction_hash, transaction_hash!("0x1"));
                Ok(self.0.lock().unwrap().pop_front().unwrap())
            }
        }

        let (msg_sender, mut msg_receiver) = mpsc::channel(10);
        tokio::spawn(transaction_status_subscription(
            msg_sender,
            0,
            transaction_hash!("0x1"),
            Mock(Mutex::new(
                [
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::AcceptedOnL1,
                        finality_status: FinalityStatus::AcceptedOnL1,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                ]
                .into_iter()
                .collect(),
            )),
        ));

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Received => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Succeeded => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap();
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn subscribe_transaction_status_mocked_reverted() {
        struct Mock(Mutex<VecDeque<TransactionStatus>>);

        #[async_trait::async_trait]
        impl GatewayApi for Mock {
            async fn transaction_status(
                &self,
                transaction_hash: TransactionHash,
            ) -> Result<TransactionStatus, SequencerError> {
                assert_eq!(transaction_hash, transaction_hash!("0x1"));
                Ok(self.0.lock().unwrap().pop_front().unwrap())
            }
        }

        let (msg_sender, mut msg_receiver) = mpsc::channel(10);
        tokio::spawn(transaction_status_subscription(
            msg_sender,
            0,
            transaction_hash!("0x1"),
            Mock(Mutex::new(
                [
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::AcceptedOnL1,
                        finality_status: FinalityStatus::AcceptedOnL1,
                        execution_status: Some(ExecutionStatus::Reverted),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                ]
                .into_iter()
                .collect(),
            )),
        ));

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Received => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Reverted => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap();
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn subscribe_transaction_status_mocked_rejected() {
        struct Mock(Mutex<VecDeque<TransactionStatus>>);

        #[async_trait::async_trait]
        impl GatewayApi for Mock {
            async fn transaction_status(
                &self,
                transaction_hash: TransactionHash,
            ) -> Result<TransactionStatus, SequencerError> {
                assert_eq!(transaction_hash, transaction_hash!("0x1"));
                Ok(self.0.lock().unwrap().pop_front().unwrap())
            }
        }

        let (msg_sender, mut msg_receiver) = mpsc::channel(10);
        tokio::spawn(transaction_status_subscription(
            msg_sender,
            0,
            transaction_hash!("0x1"),
            Mock(Mutex::new(
                [
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::NotReceived,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Received,
                        finality_status: FinalityStatus::Received,
                        execution_status: Some(ExecutionStatus::Succeeded),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                    TransactionStatus {
                        tx_status: Status::Rejected,
                        finality_status: FinalityStatus::NotReceived,
                        execution_status: Some(ExecutionStatus::Rejected),
                        tx_failure_reason: None,
                        tx_revert_reason: None,
                    },
                ]
                .into_iter()
                .collect(),
            )),
        ));

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Received => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match msg {
            ResponseEvent::TransactionStatus(SubscriptionItem {
                subscription_id: 0,
                item,
            }) if item.as_ref() == &TransactionStatusUpdate::Rejected => {}
            _ => panic!("Unexpected message: {:?}", msg),
        }

        let msg = timeout(Duration::from_secs(2), msg_receiver.recv())
            .await
            .unwrap();
        assert!(msg.is_none());
    }

    #[tokio::test]
    async fn subscribe_transaction_status_does_not_exist() {
        let mut client = Client::new().await;

        let req_id = RequestId::Number(37);
        client
            .send_request(&RpcRequest {
                method: Cow::from(SUBSCRIBE_METHOD),
                params: RawParams(Some(
                    &RawValue::from_string(
                        r#"{"kind": "transactionStatus", "transaction_hash": "0x032bfcf2a36fbfe6030c619d9245b37f0717449e7e5f4a0875e14a674c831ba0"}"#.to_owned(),
                    )
                    .unwrap(),
                )),
                id: req_id.clone(),
            })
            .await;

        client
            .expect_response(&successful_response(&0, req_id, RpcVersion::V07).unwrap())
            .await;

        tokio::time::sleep(Duration::from_secs(15)).await;

        client
            .expect_response(&serde_json::json!({
                "code": 10029,
                "data": {
                    "subscription_id": 0,
                    "transaction_hash": "0x32bfcf2a36fbfe6030c619d9245b37f0717449e7e5f4a0875e14a674c831ba0",
                },
                "message": "Transaction hash not found in websocket subscription"
            }))
            .await;

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

    fn block_sample() -> Block {
        Block {
            block_hash: block_hash!("0x1"),
            block_number: BlockNumber::new_or_panic(1000),
            l1_gas_price: GasPrices {
                price_in_wei: GasPrice(0),
                price_in_fri: GasPrice(0),
            },
            l1_data_gas_price: GasPrices {
                price_in_wei: GasPrice(0),
                price_in_fri: GasPrice(0),
            },
            parent_block_hash: block_hash!("0x2"),
            sequencer_address: None,
            state_commitment: state_commitment!("0x3"),
            status: starknet_gateway_types::reply::Status::AcceptedOnL2,
            timestamp: BlockTimestamp::new_or_panic(1),
            transaction_receipts: vec![
                (
                    pathfinder_common::receipt::Receipt {
                        transaction_hash: transaction_hash!("0x1"),
                        ..Default::default()
                    },
                    vec![Event {
                        from_address: ContractAddress::new_or_panic(
                            Felt::from_hex_str("2").unwrap(),
                        ),
                        data: vec![EventData(Felt::from_hex_str("a").unwrap())],
                        keys: vec![
                            EventKey(Felt::from_hex_str("b").unwrap()),
                            event_key!("0xdeadbeef"),
                        ],
                    }],
                ),
                (
                    pathfinder_common::receipt::Receipt {
                        transaction_hash: transaction_hash!("0x2"),
                        ..Default::default()
                    },
                    vec![
                        Event {
                            from_address: ContractAddress::new_or_panic(
                                Felt::from_hex_str("3").unwrap(),
                            ),
                            data: vec![EventData(Felt::from_hex_str("c").unwrap())],
                            keys: vec![
                                EventKey(Felt::from_hex_str("d").unwrap()),
                                event_key!("0xcafebabe"),
                            ],
                        },
                        Event {
                            from_address: ContractAddress::new_or_panic(
                                Felt::from_hex_str("4").unwrap(),
                            ),
                            data: vec![EventData(Felt::from_hex_str("e").unwrap())],
                            keys: vec![
                                EventKey(Felt::from_hex_str("f").unwrap()),
                                event_key!("0x1234"),
                            ],
                        },
                    ],
                ),
            ],
            transactions: vec![
                Transaction {
                    hash: transaction_hash!("0x1"),
                    variant: Default::default(),
                },
                Transaction {
                    hash: transaction_hash!("0x2"),
                    variant: Default::default(),
                },
            ],
            starknet_version: StarknetVersion::new(1, 1, 1, 1),
            transaction_commitment: transaction_commitment!("0x4"),
            event_commitment: event_commitment!("0x5"),
            l1_da_mode: starknet_gateway_types::reply::L1DataAvailabilityMode::Blob,
            receipt_commitment: Some(receipt_commitment!("0x6")),
            state_diff_commitment: Some(state_diff_commitment!("0x7")),
            state_diff_length: Some(8),
        }
    }

    struct Client {
        sender: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        receiver: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        server_handle: JoinHandle<()>,
        head_sender: JsonBroadcaster<BlockHeader>,
        l2_blocks: broadcast::Sender<Arc<Block>>,
        pending_data_sender: watch::Sender<PendingData>,
    }

    impl Client {
        async fn new() -> Client {
            let (pending_data_tx, pending_data_rx) = watch::channel(PendingData {
                block: Default::default(),
                number: BlockNumber::new_or_panic(0),
                state_update: Default::default(),
            });
            let context = RpcContext::for_tests().with_websockets(WebsocketContext::new(
                100.try_into().unwrap(),
                100.try_into().unwrap(),
                pending_data_rx.clone(),
            ));
            let router = RpcRouter::builder(crate::RpcVersion::V07)
                .register("pathfinder_test", rpc_test_method)
                .build(context.clone());
            let websocket_context = context.websocket.clone().unwrap();
            let head_sender = websocket_context.broadcasters.new_head.clone();
            let l2_blocks = websocket_context.broadcasters.l2_blocks.clone();

            let router = axum::Router::new()
                .route("/ws", get(websocket_handler))
                .with_state(router)
                .layer(tower::ServiceBuilder::new());

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("Websocket address already in use");
            let addr = listener.local_addr().unwrap();
            let server_handle = tokio::spawn(async move {
                axum::serve(listener, router.into_make_service())
                    .await
                    .unwrap()
            });

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
                l2_blocks,
                pending_data_sender: pending_data_tx,
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
            R: SerializeForVersion,
        {
            let message = timeout(Duration::from_secs(2), self.receiver.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Message::Text(raw_text) = message else {
                panic!("Unexpected type of message")
            };

            // Deserialize it to a generic value to avoid field ordering issues.
            let received: Value = serde_json::from_str(&raw_text).unwrap();
            let expected = response
                .serialize(serialize::Serializer::new(RpcVersion::V07))
                .unwrap();
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

    pub async fn rpc_test_method(
        context: RpcContext,
    ) -> Result<pathfinder_common::ChainId, RpcError> {
        Ok(context.chain_id)
    }
}
