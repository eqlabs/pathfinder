use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pathfinder_common::{BlockId, BlockNumber};
use tokio::sync::mpsc;

use super::RpcRouter;
use crate::context::RpcContext;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::DeserializeForVersion;
use crate::jsonrpc::{RpcError, RpcRequest, RpcResponse};
use crate::{RpcVersion, SubscriptionId};

#[axum::async_trait]
pub(super) trait RpcSubscriptionEndpoint: Send + Sync {
    // Start the subscription.
    async fn invoke(
        &self,
        state: RpcContext,
        input: serde_json::Value,
        subscription_id: SubscriptionId,
        subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
        version: RpcVersion,
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
    type Request: crate::dto::DeserializeForVersion + Send + Sync + 'static;
    type Notification: crate::dto::serialize::SerializeForVersion + Send + Sync + 'static;

    /// The value for the `method` field of the subscription notification.
    fn subscription_name() -> &'static str;

    /// The block to start streaming from.
    fn starting_block(req: &Self::Request) -> BlockId;

    /// Fetch historical data from the `from` block to the `to` block. The
    /// range is inclusive on both ends. If there is no historical data in the
    /// range, return an empty vec.
    async fn catch_up(
        state: &RpcContext,
        req: &Self::Request,
        from: BlockNumber,
        to: BlockNumber,
    ) -> Result<Vec<(Self::Notification, BlockNumber)>, RpcError>;

    /// Subscribe to active updates.
    async fn subscribe(state: RpcContext, tx: mpsc::Sender<(Self::Notification, BlockNumber)>);
}

#[axum::async_trait]
impl<T> RpcSubscriptionEndpoint for T
where
    T: RpcSubscriptionFlow + 'static,
{
    async fn invoke(
        &self,
        state: RpcContext,
        input: serde_json::Value,
        subscription_id: SubscriptionId,
        subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
        version: RpcVersion,
        tx: mpsc::Sender<Result<Message, RpcResponse>>,
    ) -> Result<(), RpcError> {
        let req = T::Request::deserialize(crate::dto::Value::new(input, version))
            .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
        let tx = SubscriptionSender {
            subscription_id,
            subscriptions,
            tx,
            subscription_name: T::subscription_name(),
            version,
            _phantom: Default::default(),
        };

        // Catch up to the latest block in batches of BATCH_SIZE.
        let first_block = pathfinder_storage::BlockId::try_from(T::starting_block(&req))
            .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
        let storage = state.storage.clone();
        let mut current_block = tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
            let mut conn = storage.connection().map_err(RpcError::InternalError)?;
            let db = conn.transaction().map_err(RpcError::InternalError)?;
            db.block_number(first_block)
                .map_err(RpcError::InternalError)?
                .ok_or_else(|| RpcError::InvalidParams("Block not found".to_string()))
        })
        .await
        .map_err(|e| RpcError::InternalError(e.into()))??;
        const BATCH_SIZE: u64 = 64;
        loop {
            let messages =
                T::catch_up(&state, &req, current_block, current_block + BATCH_SIZE).await?;
            if messages.is_empty() {
                // Caught up.
                break;
            }
            for (message, block_number) in messages {
                if tx.send(message).await.is_err() {
                    // Subscription closing.
                    return Ok(());
                }
                current_block = block_number;
            }
            // Increment the current block by 1 because the catch_up range is inclusive.
            current_block += 1;
        }

        // Subscribe to new blocks. Receive the first subscription message.
        let (tx1, mut rx1) = mpsc::channel::<(T::Notification, BlockNumber)>(1024);
        tokio::spawn(T::subscribe(state.clone(), tx1));
        let (first_message, block_number) = match rx1.recv().await {
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
        if let Some(block_number) = block_number.parent() {
            let messages = T::catch_up(&state, &req, current_block, block_number).await?;
            for (message, _) in messages {
                if tx.send(message).await.is_err() {
                    // Subscription closing.
                    return Ok(());
                }
            }
        }

        // Send the first subscription message and then forward the rest.
        if tx.send(first_message).await.is_err() {
            // Subscription closing.
            return Ok(());
        }
        let mut last_block = block_number;
        tokio::spawn(async move {
            while let Some((message, block_number)) = rx1.recv().await {
                if block_number.get() > last_block.get() + 1 {
                    // One or more blocks have been skipped. This is likely due to a race condition
                    // resulting from a reorg. This message should be ignored.
                    continue;
                }
                if tx.send(message).await.is_err() {
                    // Subscription closing.
                    break;
                }
                last_block = block_number;
            }
        });
        Ok(())
    }
}

pub async fn handle_json_rpc_socket(state: RpcRouter, ws: WebSocket) {
    let subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>> =
        Default::default();
    // Send messages to the websocket using an mpsc channel.
    let (tx, mut rx) = mpsc::channel::<Result<Message, RpcResponse>>(1024);
    let (mut ws_tx, mut ws_rx) = ws.split();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                Ok(msg) => {
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if ws_tx
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
    // Read and handle messages from the websocket.
    tokio::spawn(async move {
        loop {
            let request = match ws_rx.next().await {
                Some(Ok(Message::Text(msg))) => msg.into_bytes(),
                Some(Ok(Message::Binary(bytes))) => bytes,
                Some(Ok(Message::Pong(_) | Message::Ping(_))) => continue,
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
                    if tx
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

            if rpc_request.method == "starknet_unsubscribe" {
                // End the subscription.
                let Some(params) = rpc_request.params.0 else {
                    if tx
                        .send(Err(RpcResponse::invalid_params(
                            rpc_request.id,
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
                        if tx
                            .send(Err(RpcResponse::invalid_params(
                                rpc_request.id,
                                err.to_string(),
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                };
                let Some((_, handle)) = subscriptions.remove(&params.subscription_id) else {
                    if tx
                        .send(Err(RpcResponse::invalid_params(
                            rpc_request.id,
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
                metrics::increment_counter!("rpc_method_calls_total", "method" => "starknet_unsubscribe", "version" => state.version.to_str());
            }

            // Also grab the method_name as it is a static str, which is required by the
            // metrics.
            let Some((&method_name, endpoint)) = state
                .subscription_endpoints
                .get_key_value(rpc_request.method.as_ref())
            else {
                tx.send(Ok(Message::Text(
                    serde_json::to_string(&RpcResponse::method_not_found(rpc_request.id)).unwrap(),
                )))
                .await
                .ok();
                continue;
            };
            metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => state.version.to_str());

            let params = match serde_json::to_value(rpc_request.params) {
                Ok(params) => params,
                Err(_e) => {
                    if tx
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
            let subscription_id = SubscriptionId::next();
            let context = state.context.clone();
            let version = state.version;
            let tx = tx.clone();
            let req_id = rpc_request.id;
            if tx
                .send(Ok(Message::Text(
                    serde_json::to_string(&RpcResponse {
                        output: Ok(
                            serde_json::to_value(&SubscriptionIdResult { subscription_id })
                                .unwrap(),
                        ),
                        id: req_id.clone(),
                    })
                    .unwrap(),
                )))
                .await
                .is_err()
            {
                break;
            }
            let handle = tokio::spawn({
                let subscriptions = subscriptions.clone();
                async move {
                    if let Err(e) = endpoint
                        .invoke(
                            context,
                            params,
                            subscription_id,
                            subscriptions,
                            version,
                            tx.clone(),
                        )
                        .await
                    {
                        tx.send(Err(RpcResponse {
                            output: Err(e),
                            id: req_id,
                        }))
                        .await
                        .ok();
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
    subscription_name: &'static str,
    version: RpcVersion,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Clone for SubscriptionSender<T> {
    fn clone(&self) -> Self {
        Self {
            subscription_id: self.subscription_id,
            subscriptions: self.subscriptions.clone(),
            tx: self.tx.clone(),
            subscription_name: self.subscription_name,
            version: self.version,
            _phantom: Default::default(),
        }
    }
}

impl<T: crate::dto::serialize::SerializeForVersion> SubscriptionSender<T> {
    pub async fn send(&self, value: T) -> Result<(), mpsc::error::SendError<()>> {
        if !self.subscriptions.contains_key(&self.subscription_id) {
            // Race condition due to the subscription ending.
            return Ok(());
        }
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method: self.subscription_name,
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
