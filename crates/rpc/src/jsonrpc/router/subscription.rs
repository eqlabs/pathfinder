use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pathfinder_common::{BlockId, BlockNumber};
use tokio::sync::mpsc;

use super::RpcRouter;
use crate::context::RpcContext;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::DeserializeForVersion;
use crate::error::ApplicationError;
use crate::jsonrpc::{RequestId, RpcError, RpcRequest, RpcResponse};
use crate::{RpcVersion, SubscriptionId};

/// See [`RpcSubscriptionFlow`].
#[axum::async_trait]
pub(super) trait RpcSubscriptionEndpoint: Send + Sync {
    // Start the subscription.
    async fn invoke(
        &self,
        router: RpcRouter,
        input: serde_json::Value,
        subscription_id: SubscriptionId,
        subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
        req_id: RequestId,
        tx: mpsc::Sender<Result<Message, RpcResponse>>,
    ) -> Result<(), RpcError>;
}

/// This trait is the main entry point for subscription endpoint
/// implementations.
///
/// Many subscription endpoints allow for historical data to be streamed before
/// starting to stream active updates. This is done by having the subscription
/// request pass a `block` parameter indicating the block to start from. This
/// trait is designed to make it easy to implement this behavior, and difficult
/// to make mistakes (e.g. race conditions or accidentally dropping messages).
///
/// The `catch_up` method is used to stream historical data, while the
/// `subscribe` method is used to subscribe to active updates. The
/// `starting_block` method extracts the first block to start streaming from.
/// This will probably always just be the `block` field of the request.
///
/// If a subscription endpoint does not need to stream historical data, it
/// should always return an empty vec from `catch_up`.
///
/// The flow is implemented as follows:
/// - Catch up from the starting block to the latest block known to pathfinder,
///   in batches. Call that block K.
/// - Subscribe to active updates. Fetch the first update, along with the block
///   number that it applies to.
/// - Catch up from block K to the block just before the first active update.
///   This is done to ensure that no blocks are missed between the previous
///   catch-up and the subscription.
/// - Stream the first active update, and then keep streaming the rest.
#[axum::async_trait]
pub trait RpcSubscriptionFlow: Send + Sync {
    type Request: crate::dto::DeserializeForVersion + Clone + Send + Sync + 'static;
    type Notification: crate::dto::serialize::SerializeForVersion + Send + Sync + 'static;

    /// The block to start streaming from. If the subscription endpoint does not
    /// support catching up, this method should always return
    /// [`BlockId::Latest`].
    fn starting_block(req: &Self::Request) -> BlockId;

    /// Fetch historical data from the `from` block to the `to` block. The
    /// range is inclusive on both ends. If there is no historical data in the
    /// range, return an empty vec.
    async fn catch_up(
        state: &RpcContext,
        req: &Self::Request,
        from: BlockNumber,
        to: BlockNumber,
    ) -> Result<Vec<SubscriptionMessage<Self::Notification>>, RpcError>;

    /// Subscribe to active updates.
    async fn subscribe(
        state: RpcContext,
        req: Self::Request,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    );
}

#[derive(Debug)]
pub struct SubscriptionMessage<T> {
    /// [`RpcSubscriptionFlow::Notification`] to be sent to the client.
    pub notification: T,
    /// The block number of the notification. If the notification does not have
    /// a block number, this value does not matter.
    pub block_number: BlockNumber,
    /// The value for the `method` field of the subscription notification sent
    /// to the client.
    pub subscription_name: &'static str,
}

#[axum::async_trait]
impl<T> RpcSubscriptionEndpoint for T
where
    T: RpcSubscriptionFlow + 'static,
{
    async fn invoke(
        &self,
        router: RpcRouter,
        input: serde_json::Value,
        subscription_id: SubscriptionId,
        subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
        req_id: RequestId,
        ws_tx: mpsc::Sender<Result<Message, RpcResponse>>,
    ) -> Result<(), RpcError> {
        let req = T::Request::deserialize(crate::dto::Value::new(input, router.version))
            .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
        let tx = SubscriptionSender {
            subscription_id,
            subscriptions,
            tx: ws_tx.clone(),
            version: router.version,
            _phantom: Default::default(),
        };

        let first_block = T::starting_block(&req);

        let current_block = match &first_block {
            BlockId::Pending => {
                return Err(RpcError::InvalidParams(
                    "Pending block is not supported for new heads subscription".to_string(),
                ));
            }
            BlockId::Latest => {
                // No need to catch up. The code below will subscribe to new blocks.
                // Only needs to send the subscription ID to the client.
                if ws_tx
                    .send(Ok(Message::Text(
                        serde_json::to_string(&RpcResponse {
                            output: Ok(serde_json::to_value(&SubscriptionIdResult {
                                subscription_id,
                            })
                            .unwrap()),
                            id: req_id.clone(),
                        })
                        .unwrap(),
                    )))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                BlockNumber::MAX
            }
            BlockId::Number(_) | BlockId::Hash(_) => {
                // Catch up to the latest block in batches of BATCH_SIZE.

                // Load the first block number, return an error if it's invalid.
                let first_block = pathfinder_storage::BlockId::try_from(T::starting_block(&req))
                    .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
                let storage = router.context.storage.clone();
                let mut current_block =
                    tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
                        let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                        let db = conn.transaction().map_err(RpcError::InternalError)?;
                        db.block_number(first_block)
                            .map_err(RpcError::InternalError)?
                            .ok_or_else(|| ApplicationError::BlockNotFound.into())
                    })
                    .await
                    .map_err(|e| RpcError::InternalError(e.into()))??;

                // Send the subscription ID to the client.
                if ws_tx
                    .send(Ok(Message::Text(
                        serde_json::to_string(&RpcResponse {
                            output: Ok(serde_json::to_value(&SubscriptionIdResult {
                                subscription_id,
                            })
                            .unwrap()),
                            id: req_id.clone(),
                        })
                        .unwrap(),
                    )))
                    .await
                    .is_err()
                {
                    return Ok(());
                }

                const BATCH_SIZE: u64 = 64;
                loop {
                    let messages = T::catch_up(
                        &router.context,
                        &req,
                        current_block,
                        current_block + BATCH_SIZE,
                    )
                    .await?;
                    if messages.is_empty() {
                        // Caught up.
                        break;
                    }
                    for msg in messages {
                        if tx
                            .send(msg.notification, msg.subscription_name)
                            .await
                            .is_err()
                        {
                            // Subscription closing.
                            return Ok(());
                        }
                        current_block = msg.block_number;
                    }
                    // Increment the current block by 1 because the catch_up range is inclusive.
                    current_block += 1;
                }
                current_block
            }
        };

        // Subscribe to new blocks. Receive the first subscription message.
        let (tx1, mut rx1) = mpsc::channel::<SubscriptionMessage<T::Notification>>(1024);
        {
            let req = req.clone();
            tokio::spawn(T::subscribe(router.context.clone(), req, tx1));
        }
        let first_msg = match rx1.recv().await {
            Some(msg) => msg,
            None => {
                // Subscription closing.
                return Ok(());
            }
        };

        // Catch up from the latest block that we already caught up to, to the first
        // block that will be streamed from the subscription. This way we don't miss any
        // blocks. Because the catch_up range is inclusive, we need to subtract 1 from
        // the block number.
        if let Some(block_number) = first_msg.block_number.parent() {
            let messages = T::catch_up(&router.context, &req, current_block, block_number).await?;
            for msg in messages {
                if tx
                    .send(msg.notification, msg.subscription_name)
                    .await
                    .is_err()
                {
                    // Subscription closing.
                    return Ok(());
                }
            }
        }

        // Send the first subscription message and then forward the rest.
        if tx
            .send(first_msg.notification, first_msg.subscription_name)
            .await
            .is_err()
        {
            // Subscription closing.
            return Ok(());
        }
        let mut last_block = first_msg.block_number;
        tokio::spawn(async move {
            while let Some(msg) = rx1.recv().await {
                if msg.block_number.get() > last_block.get() + 1 {
                    // One or more blocks have been skipped. This is likely due to a race condition
                    // resulting from a reorg. This message should be ignored.
                    continue;
                }
                if tx
                    .send(msg.notification, msg.subscription_name)
                    .await
                    .is_err()
                {
                    // Subscription closing.
                    break;
                }
                last_block = msg.block_number;
            }
        });
        Ok(())
    }
}

type WsSender = mpsc::Sender<Result<Message, RpcResponse>>;
type WsReceiver = mpsc::Receiver<Result<Message, axum::Error>>;

/// Split a websocket into an MPSC sender and receiver.
/// These two are later passed to [`handle_json_rpc_socket`]. This separation
/// serves to allow easier testing. The sender sends `Result<_, RpcResponse>`
/// purely for convenience, and the [`RpcResponse`] will be encoded into a
/// [`Message::Text`].
pub fn split_ws(ws: WebSocket) -> (WsSender, WsReceiver) {
    let (mut ws_sender, mut ws_receiver) = ws.split();
    // Send messages to the websocket using an MPSC channel.
    let (sender_tx, mut sender_rx) = mpsc::channel::<Result<Message, RpcResponse>>(1024);
    tokio::spawn(async move {
        while let Some(msg) = sender_rx.recv().await {
            match msg {
                Ok(msg) => {
                    if ws_sender.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if ws_sender
                        .send(Message::Text(serde_json::to_string(&e).unwrap()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    // Receive messages from the websocket using an MPSC channel.
    let (receiver_tx, receiver_rx) = mpsc::channel::<Result<Message, axum::Error>>(1024);
    tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if receiver_tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    (sender_tx, receiver_rx)
}

pub fn handle_json_rpc_socket(
    state: RpcRouter,
    ws_tx: mpsc::Sender<Result<Message, RpcResponse>>,
    mut ws_rx: mpsc::Receiver<Result<Message, axum::Error>>,
) {
    let subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>> =
        Default::default();
    // Read and handle messages from the websocket.
    tokio::spawn(async move {
        loop {
            let request = match ws_rx.recv().await {
                Some(Ok(Message::Text(msg))) => msg.into_bytes(),
                Some(Ok(Message::Binary(bytes))) => bytes,
                Some(Ok(Message::Pong(_) | Message::Ping(_))) => {
                    // Ping and pong messages are handled automatically by axum.
                    continue;
                }
                Some(Ok(Message::Close(_))) | None => {
                    // Websocket closed.
                    return;
                }
                Some(Err(e)) => {
                    tracing::trace!(error = ?e, "Error receiving websocket message");
                    return;
                }
            };

            let rpc_request = match serde_json::from_slice::<RpcRequest<'_>>(&request) {
                Ok(request) => request,
                Err(err) => {
                    if ws_tx
                        .send(Err(RpcResponse::parse_error(err.to_string())))
                        .await
                        .is_err()
                    {
                        // Connection is closing.
                        break;
                    }
                    continue;
                }
            };
            let req_id = rpc_request.id;

            if rpc_request.method == "starknet_unsubscribe" {
                // End the subscription.
                let Some(params) = rpc_request.params.0 else {
                    if ws_tx
                        .send(Err(RpcResponse::invalid_params(
                            req_id,
                            "Missing params for starknet_unsubscribe".to_string(),
                        )))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                };
                let params = match serde_json::from_str::<StarknetUnsubscribeParams>(params.get()) {
                    Ok(params) => params,
                    Err(err) => {
                        if ws_tx
                            .send(Err(RpcResponse::invalid_params(req_id, err.to_string())))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let Some((_, handle)) = subscriptions.remove(&params.subscription_id) else {
                    if ws_tx
                        .send(Err(RpcResponse::invalid_params(
                            req_id,
                            "Subscription not found".to_string(),
                        )))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                };
                handle.abort();
                if ws_tx
                    .send(Ok(Message::Text(
                        serde_json::to_string(&RpcResponse {
                            output: Ok(true.into()),
                            id: req_id.clone(),
                        })
                        .unwrap(),
                    )))
                    .await
                    .is_err()
                {
                    break;
                }
                metrics::increment_counter!("rpc_method_calls_total", "method" => "starknet_unsubscribe", "version" => state.version.to_str());
                continue;
            }

            // Also grab the method_name as it is a static str, which is required by the
            // metrics.
            let Some((&method_name, endpoint)) = state
                .subscription_endpoints
                .get_key_value(rpc_request.method.as_ref())
            else {
                ws_tx
                    .send(Ok(Message::Text(
                        serde_json::to_string(&RpcResponse::method_not_found(req_id)).unwrap(),
                    )))
                    .await
                    .ok();
                continue;
            };
            metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => state.version.to_str());

            let params = match serde_json::to_value(rpc_request.params) {
                Ok(params) => params,
                Err(_e) => {
                    if ws_tx
                        .send(Ok(Message::Text(
                            serde_json::to_string(&RpcError::InvalidParams(
                                "Invalid params".to_string(),
                            ))
                            .unwrap(),
                        )))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
            };

            // Start the subscription.
            let state = state.clone();
            let subscription_id = SubscriptionId::next();
            let ws_tx = ws_tx.clone();
            let handle = tokio::spawn({
                let subscriptions = subscriptions.clone();
                async move {
                    if let Err(e) = endpoint
                        .invoke(
                            state,
                            params,
                            subscription_id,
                            subscriptions.clone(),
                            req_id.clone(),
                            ws_tx.clone(),
                        )
                        .await
                    {
                        ws_tx
                            .send(Err(RpcResponse {
                                output: Err(e),
                                id: req_id,
                            }))
                            .await
                            .ok();
                        while subscriptions.remove(&subscription_id).is_none() {
                            // Race condition, the insert has not yet happened.
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
            if subscriptions.insert(subscription_id, handle).is_some() {
                panic!("subscription id overflow");
            }
        }
    });
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StarknetUnsubscribeParams {
    subscription_id: SubscriptionId,
}

#[derive(Debug, serde::Serialize)]
struct SubscriptionIdResult {
    subscription_id: SubscriptionId,
}

#[derive(Debug)]
struct SubscriptionSender<T> {
    subscription_id: SubscriptionId,
    subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
    tx: mpsc::Sender<Result<Message, RpcResponse>>,
    version: RpcVersion,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Clone for SubscriptionSender<T> {
    fn clone(&self) -> Self {
        Self {
            subscription_id: self.subscription_id,
            subscriptions: self.subscriptions.clone(),
            tx: self.tx.clone(),
            version: self.version,
            _phantom: Default::default(),
        }
    }
}

impl<T: crate::dto::serialize::SerializeForVersion> SubscriptionSender<T> {
    pub async fn send(
        &self,
        value: T,
        subscription_name: &'static str,
    ) -> Result<(), mpsc::error::SendError<()>> {
        if !self.subscriptions.contains_key(&self.subscription_id) {
            // Race condition due to the subscription ending.
            return Ok(());
        }
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method: subscription_name,
            params: SubscriptionResult {
                subscription_id: self.subscription_id,
                result: value,
            },
        }
        .serialize(crate::dto::serialize::Serializer::new(self.version))
        .unwrap();
        let data = serde_json::to_string(&notification).unwrap();
        self.tx
            .send(Ok(Message::Text(data)))
            .await
            .map_err(|_| mpsc::error::SendError(()))
    }
}

#[derive(Debug)]
struct RpcNotification<T> {
    jsonrpc: &'static str,
    method: &'static str,
    params: SubscriptionResult<T>,
}

#[derive(Debug)]
pub struct SubscriptionResult<T> {
    subscription_id: SubscriptionId,
    result: T,
}

impl<T> crate::dto::serialize::SerializeForVersion for RpcNotification<T>
where
    T: crate::dto::serialize::SerializeForVersion,
{
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("jsonrpc", &self.jsonrpc)?;
        serializer.serialize_field("method", &self.method)?;
        serializer.serialize_field("params", &self.params)?;
        serializer.end()
    }
}

impl<T> crate::dto::serialize::SerializeForVersion for SubscriptionResult<T>
where
    T: crate::dto::serialize::SerializeForVersion,
{
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("subscription_id", &self.subscription_id)?;
        serializer.serialize_field("result", &self.result)?;
        serializer.end()
    }
}
