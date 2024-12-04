use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pathfinder_common::{BlockId, BlockNumber};
use serde_json::value::RawValue;
use tokio::sync::{mpsc, RwLock};
use tracing::Instrument;

use super::{run_concurrently, RpcRouter};
use crate::context::RpcContext;
use crate::dto::serialize::{self, SerializeForVersion};
use crate::dto::DeserializeForVersion;
use crate::error::ApplicationError;
use crate::jsonrpc::{RpcError, RpcRequest, RpcResponse};
use crate::{RpcVersion, SubscriptionId};

pub const CATCH_UP_BATCH_SIZE: u64 = 64;

/// See [`RpcSubscriptionFlow`].
#[axum::async_trait]
pub(super) trait RpcSubscriptionEndpoint: Send + Sync {
    // Start the subscription.
    async fn invoke(&self, params: InvokeParams) -> Result<tokio::task::JoinHandle<()>, RpcError>;
}

pub(super) struct InvokeParams {
    router: RpcRouter,
    input: serde_json::Value,
    subscription_id: SubscriptionId,
    subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
    ws_tx: mpsc::Sender<Result<Message, RpcResponse>>,
    lock: Arc<RwLock<()>>,
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
    /// `params` field of the subscription request.
    type Params: crate::dto::DeserializeForVersion + Clone + Send + Sync + 'static;
    /// The notification type to be sent to the client.
    type Notification: crate::dto::serialize::SerializeForVersion + Send + Sync + 'static;

    /// Validate the subscription parameters. If the parameters are invalid,
    /// return an error.
    fn validate_params(_params: &Self::Params) -> Result<(), RpcError> {
        Ok(())
    }

    /// The block to start streaming from. If the subscription endpoint does not
    /// support catching up, leave this method unimplemented.
    fn starting_block(_params: &Self::Params) -> BlockId {
        BlockId::Latest
    }

    /// Fetch historical data from the `from` block to the `to` block. The
    /// range is inclusive on both ends. If there is no historical data in the
    /// range, return an empty vec. If the subscription endpoint does not
    /// support catching up, leave this method unimplemented.
    async fn catch_up(
        _state: &RpcContext,
        _params: &Self::Params,
        _from: BlockNumber,
        _to: BlockNumber,
    ) -> Result<CatchUp<Self::Notification>, RpcError> {
        Ok(Default::default())
    }

    /// Subscribe to active updates.
    async fn subscribe(
        state: RpcContext,
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError>;
}

pub struct CatchUp<T> {
    pub messages: Vec<SubscriptionMessage<T>>,
    /// [`SubscriptionMessage`] already contains a `block_number` field, but
    /// `messages` can be empty (e.g. due to some filtering logic), so the last
    /// block caught up to must be sent separately.
    ///
    /// If there are no blocks in the block range given to
    /// [`RpcSubscriptionFlow::catch_up`], this field should be [`None`].
    pub last_block: Option<BlockNumber>,
}

impl<T> Default for CatchUp<T> {
    fn default() -> Self {
        Self {
            messages: Default::default(),
            last_block: Default::default(),
        }
    }
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
        InvokeParams {
            router,
            input,
            subscription_id,
            subscriptions,
            ws_tx,
            lock,
        }: InvokeParams,
    ) -> Result<tokio::task::JoinHandle<()>, RpcError> {
        let params = T::Params::deserialize(crate::dto::Value::new(input, router.version))
            .map_err(|e| RpcError::InvalidParams(e.to_string()))?;

        T::validate_params(&params)?;

        let tx = SubscriptionSender {
            subscription_id,
            subscriptions: subscriptions.clone(),
            tx: ws_tx,
            version: router.version,
            _phantom: Default::default(),
        };

        let first_block = T::starting_block(&params);

        let mut current_block = match first_block {
            BlockId::Pending => {
                return Err(RpcError::ApplicationError(ApplicationError::CallOnPending));
            }
            BlockId::Latest => {
                // No need to catch up. The code below will subscribe to new blocks.
                None
            }
            first_block @ (BlockId::Number(_) | BlockId::Hash(_)) => {
                // Load the first block number, return an error if it's invalid.
                let first_block = pathfinder_storage::BlockId::try_from(first_block)
                    .map_err(|e| RpcError::InvalidParams(e.to_string()))?;
                let storage = router.context.storage.clone();
                let current_block = tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
                    let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                    let db = conn.transaction().map_err(RpcError::InternalError)?;
                    db.block_number(first_block)
                        .map_err(RpcError::InternalError)?
                        .ok_or_else(|| ApplicationError::BlockNotFound.into())
                })
                .await
                .map_err(|e| RpcError::InternalError(e.into()))??;
                Some(current_block)
            }
        };

        Ok(tokio::spawn(async move {
            let _subscription_guard = SubscriptionsGuard {
                subscription_id,
                subscriptions,
            };
            // This lock ensures that the streaming of subscriptions doesn't start before
            // the caller sends the success response for the subscription request.
            let _lock_guard = lock.read().await;

            // Catch up to the latest block in batches of BATCH_SIZE.
            if let Some(current_block) = current_block.as_mut() {
                loop {
                    // -1 because the end is inclusive, otherwise we get batches of
                    // `CATCH_UP_BATCH_SIZE + 1` which probably doesn't really
                    // matter, but it's misleading.
                    let end = *current_block + CATCH_UP_BATCH_SIZE - 1;
                    let catch_up =
                        match T::catch_up(&router.context, &params, *current_block, end).await {
                            Ok(messages) => messages,
                            Err(e) => {
                                tx.send_err(e)
                                    .await
                                    // Could error if the subscription is closing.
                                    .ok();
                                return;
                            }
                        };
                    let last_block = match catch_up.last_block {
                        Some(last_block) => last_block,
                        None => {
                            // `None` means that there were no messages for the given block range.
                            break;
                        }
                    };
                    for msg in catch_up.messages {
                        if tx
                            .send(msg.notification, msg.subscription_name)
                            .await
                            .is_err()
                        {
                            // Subscription closing.
                            return;
                        }
                    }
                    // Increment by 1 because the catch_up range is inclusive.
                    *current_block = last_block + 1;
                    if last_block < end {
                        // This was the last batch.
                        break;
                    }
                }
            }

            // Subscribe to new blocks. Receive the first subscription message.
            let (tx1, mut rx1) = mpsc::channel::<SubscriptionMessage<T::Notification>>(1024);
            tokio::spawn({
                let params = params.clone();
                let context = router.context.clone();
                let tx = tx.clone();
                async move {
                    if let Err(e) = T::subscribe(context, params, tx1).await {
                        tx.send_err(e).await.ok();
                    }
                }
            });
            let first_msg = match rx1.recv().await {
                Some(msg) => msg,
                None => {
                    // Subscription closing.
                    return;
                }
            };

            // Catch up from the latest block that we already caught up to, to the first
            // block that will be streamed from the subscription. This way we don't miss any
            // blocks. Because the catch_up range is inclusive, we need to subtract 1 from
            // the block number (i.e. take its parent).
            let end = first_msg.block_number.parent();
            match (current_block, end) {
                (Some(current_block), Some(end)) if current_block <= end => {
                    let catch_up =
                        match T::catch_up(&router.context, &params, current_block, end).await {
                            Ok(messages) => messages,
                            Err(e) => {
                                tx.send_err(e)
                                    .await
                                    // Could error if the subscription is closing.
                                    .ok();
                                return;
                            }
                        };
                    for msg in catch_up.messages {
                        if tx
                            .send(msg.notification, msg.subscription_name)
                            .await
                            .is_err()
                        {
                            // Subscription closing.
                            return;
                        }
                    }
                }
                _ => {
                    // Either the range is empty or catch-up is not supported by
                    // the endpoint (`current_block` is `None`).
                }
            }

            // Send the first subscription message and then forward the rest.
            if tx
                .send(first_msg.notification, first_msg.subscription_name)
                .await
                .is_err()
            {
                // Subscription closing.
                return;
            }
            let mut last_block = first_msg.block_number;
            while let Some(msg) = rx1.recv().await {
                if msg.block_number.get() > last_block.get() + 1 {
                    // One or more blocks have been skipped. This is likely due to a race
                    // condition resulting from a reorg. This message should be ignored.
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
        }))
    }
}

/// A guard to ensure that the subscription handle is removed when the
/// subscription task corresponding to that handle returns.
struct SubscriptionsGuard {
    subscription_id: SubscriptionId,
    subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
}

impl Drop for SubscriptionsGuard {
    fn drop(&mut self) {
        self.subscriptions.remove(&self.subscription_id);
    }
}

type WsSender = mpsc::Sender<Result<Message, RpcResponse>>;
type WsReceiver = mpsc::Receiver<Result<Message, axum::Error>>;

/// Split a websocket into an MPSC sender and receiver.
/// These two are later passed to [`handle_json_rpc_socket`]. This separation
/// serves to allow easier testing. The sender sends `Result<_, RpcResponse>`
/// purely for convenience, and the [`RpcResponse`] will be encoded into a
/// [`Message::Text`].
pub fn split_ws(ws: WebSocket, version: RpcVersion) -> (WsSender, WsReceiver) {
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
                        .send(Message::Text(
                            serde_json::to_string(
                                &e.serialize(serialize::Serializer::new(version)).unwrap(),
                            )
                            .unwrap(),
                        ))
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
                Some(Ok(Message::Text(msg))) => msg,
                Some(Ok(Message::Binary(bytes))) => match String::from_utf8(bytes) {
                    Ok(msg) => msg,
                    Err(e) => {
                        if ws_tx
                            .send(Err(RpcResponse::parse_error(e.to_string(), state.version)))
                            .await
                            .is_err()
                        {
                            // Connection is closing.
                            break;
                        }
                        continue;
                    }
                },
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

            // This lock ensures that the streaming of subscriptions doesn't start before we
            // send the success response for the subscription request. Once this write guard
            // is dropped, all of the read guards can proceed.
            let lock = Arc::new(RwLock::new(()));
            let _guard = lock.write().await;

            // Unfortunately due to this https://github.com/serde-rs/json/issues/497
            // we cannot use an enum with borrowed raw values inside to do a single
            // deserialization for us. Instead we have to distinguish manually
            // between a single request and a batch request which we do by checking
            // the first byte.
            let request = request.trim_start();
            if !request.starts_with('[') {
                let raw_value: &RawValue = match serde_json::from_str(request) {
                    Ok(raw_value) => raw_value,
                    Err(e) => {
                        if ws_tx
                            .send(Err(RpcResponse::parse_error(e.to_string(), state.version)))
                            .await
                            .is_err()
                        {
                            // Connection is closing.
                            break;
                        }
                        continue;
                    }
                };
                match handle_request(
                    &state,
                    raw_value,
                    subscriptions.clone(),
                    ws_tx.clone(),
                    lock.clone(),
                )
                .await
                {
                    Ok(Some(response)) | Err(response) => {
                        if ws_tx
                            .send(Ok(Message::Text(
                                serde_json::to_string(
                                    &response
                                        .serialize(serialize::Serializer::new(state.version))
                                        .unwrap(),
                                )
                                .unwrap(),
                            )))
                            .await
                            .is_err()
                        {
                            // Connection is closing.
                            break;
                        }
                    }
                    Ok(None) => {
                        // No response.
                        continue;
                    }
                }
            } else {
                // Batch request.
                let requests = match serde_json::from_str::<Vec<&RawValue>>(request) {
                    Ok(requests) => requests,
                    Err(e) => {
                        if ws_tx
                            .send(Err(RpcResponse::parse_error(e.to_string(), state.version)))
                            .await
                            .is_err()
                        {
                            // Connection is closing.
                            break;
                        }
                        continue;
                    }
                };

                if requests.is_empty() {
                    // According to the JSON-RPC spec, a batch request cannot be empty.
                    if ws_tx
                        .send(Err(RpcResponse::invalid_request(
                            "A batch request must contain at least one request".to_owned(),
                            state.version,
                        )))
                        .await
                        .is_err()
                    {
                        // Connection is closing.
                        break;
                    }
                }

                let responses = run_concurrently(
                    state.context.config.batch_concurrency_limit,
                    requests.into_iter().enumerate(),
                    {
                        |(idx, request)| {
                            let state = &state;
                            let ws_tx = ws_tx.clone();
                            let subscriptions = subscriptions.clone();
                            let lock = lock.clone();
                            async move {
                                match handle_request(state, request, subscriptions, ws_tx, lock)
                                    .instrument(tracing::debug_span!("ws batch", idx))
                                    .await
                                {
                                    Ok(Some(response)) | Err(response) => Some(response),
                                    Ok(None) => None,
                                }
                            }
                        }
                    },
                )
                .await
                .flatten()
                .collect::<Vec<RpcResponse>>();

                // All requests were notifications, no response needed.
                if responses.is_empty() {
                    continue;
                }

                let values = responses
                    .into_iter()
                    .map(|response| {
                        response
                            .serialize(serialize::Serializer::new(state.version))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                if ws_tx
                    .send(Ok(Message::Text(serde_json::to_string(&values).unwrap())))
                    .await
                    .is_err()
                {
                    // Connection is closing.
                    break;
                }
            }
        }
    });
}

/// Handle a single request. Returns `Result` for convenience, so that the `?`
/// operator could be used in the body of the function. Returns `Ok(None)` if
/// the request was a notification (i.e. no response is needed).
async fn handle_request(
    state: &RpcRouter,
    raw_request: &RawValue,
    subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
    ws_tx: mpsc::Sender<Result<Message, RpcResponse>>,
    lock: Arc<RwLock<()>>,
) -> Result<Option<RpcResponse>, RpcResponse> {
    let rpc_request = serde_json::from_str::<RpcRequest<'_>>(raw_request.get())
        .map_err(|e| RpcResponse::invalid_request(e.to_string(), state.version))?;
    let req_id = rpc_request.id;

    // Ignore notification requests.
    if req_id.is_notification() {
        return Ok(None);
    }

    // Handle JSON-RPC non-subscription methods.
    if state
        .method_endpoints
        .contains_key(rpc_request.method.as_ref())
    {
        return Ok(state.run_request(raw_request.get()).await);
    }

    // Handle starknet_unsubscribe.
    if rpc_request.method == "starknet_unsubscribe" {
        // End the subscription.
        let params = rpc_request.params.0.ok_or_else(|| {
            RpcResponse::invalid_params(
                req_id.clone(),
                "Missing params for starknet_unsubscribe".to_string(),
                state.version,
            )
        })?;
        let params =
            serde_json::from_str::<StarknetUnsubscribeParams>(params.get()).map_err(|e| {
                RpcResponse::invalid_params(req_id.clone(), e.to_string(), state.version)
            })?;
        let (_, handle) = subscriptions
            .remove(&params.subscription_id)
            .ok_or_else(|| RpcResponse {
                output: Err(RpcError::ApplicationError(
                    ApplicationError::InvalidSubscriptionID,
                )),
                id: req_id.clone(),
                version: state.version,
            })?;
        handle.abort();
        metrics::increment_counter!("rpc_method_calls_total", "method" => "starknet_unsubscribe", "version" => state.version.to_str());
        return Ok(Some(RpcResponse {
            output: Ok(true.into()),
            id: req_id,
            version: state.version,
        }));
    }

    let (&method_name, endpoint) = state
        .subscription_endpoints
        .get_key_value(rpc_request.method.as_ref())
        .ok_or_else(|| RpcResponse::method_not_found(req_id.clone(), state.version))?;
    metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => state.version.to_str());

    let params = serde_json::to_value(rpc_request.params)
        .map_err(|e| RpcResponse::invalid_params(req_id.clone(), e.to_string(), state.version))?;

    // Start the subscription.
    let router = state.clone();
    let subscription_id = SubscriptionId::next();
    let ws_tx = ws_tx.clone();
    match endpoint
        .invoke(InvokeParams {
            router,
            input: params,
            subscription_id,
            subscriptions: subscriptions.clone(),
            ws_tx: ws_tx.clone(),
            lock,
        })
        .await
    {
        Ok(handle) => {
            if subscriptions.insert(subscription_id, handle).is_some() {
                panic!("subscription id overflow");
            }
            Ok(Some(RpcResponse {
                output: Ok(serde_json::to_value(subscription_id).unwrap()),
                id: req_id,
                version: state.version,
            }))
        }
        Err(e) => Err(RpcResponse {
            output: Err(e),
            id: req_id,
            version: state.version,
        }),
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StarknetUnsubscribeParams {
    subscription_id: SubscriptionId,
}

#[derive(Debug)]
pub struct SubscriptionSender<T> {
    pub subscription_id: SubscriptionId,
    pub subscriptions: Arc<DashMap<SubscriptionId, tokio::task::JoinHandle<()>>>,
    pub tx: mpsc::Sender<Result<Message, RpcResponse>>,
    pub version: RpcVersion,
    pub _phantom: std::marker::PhantomData<T>,
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

    pub async fn send_err(&self, err: RpcError) -> Result<(), mpsc::error::SendError<()>> {
        if !self.subscriptions.contains_key(&self.subscription_id) {
            // Race condition due to the subscription ending.
            return Ok(());
        }
        let notification = RpcNotification {
            jsonrpc: "2.0",
            method: "pathfinder_subscriptionError",
            params: SubscriptionResult {
                subscription_id: self.subscription_id,
                result: err,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::async_trait;
    use axum::extract::ws::Message;
    use pathfinder_common::{BlockHash, BlockHeader, BlockId, BlockNumber, ChainId};
    use pathfinder_crypto::Felt;
    use pathfinder_ethereum::EthereumClient;
    use pathfinder_storage::StorageBuilder;
    use primitive_types::H160;
    use starknet_gateway_client::Client;
    use tokio::sync::mpsc;

    use super::RpcSubscriptionEndpoint;
    use crate::context::{RpcConfig, RpcContext};
    use crate::dto::DeserializeForVersion;
    use crate::jsonrpc::{
        handle_json_rpc_socket,
        CatchUp,
        RpcRouter,
        RpcSubscriptionFlow,
        SubscriptionMessage,
    };
    use crate::pending::PendingWatcher;
    use crate::types::syncing::Syncing;
    use crate::{Notifications, SyncState};

    #[tokio::test]
    async fn test_error_returned_from_catch_up() {
        struct ErrorFromCatchUp;

        #[async_trait]
        impl RpcSubscriptionFlow for ErrorFromCatchUp {
            type Params = Params;
            type Notification = serde_json::Value;

            fn starting_block(_params: &Self::Params) -> BlockId {
                BlockId::Number(BlockNumber::GENESIS)
            }

            async fn catch_up(
                _state: &RpcContext,
                _params: &Self::Params,
                _from: BlockNumber,
                _to: BlockNumber,
            ) -> Result<CatchUp<Self::Notification>, crate::jsonrpc::RpcError> {
                Err(crate::jsonrpc::RpcError::InternalError(anyhow::anyhow!(
                    "error from catch_up"
                )))
            }

            async fn subscribe(
                _state: RpcContext,
                _params: Self::Params,
                _tx: tokio::sync::mpsc::Sender<SubscriptionMessage<Self::Notification>>,
            ) -> Result<(), crate::jsonrpc::RpcError> {
                Ok(())
            }
        }

        let router = setup(5, ErrorFromCatchUp).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "test",
                    "params": {}
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let subscription_id = match res {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let msg = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match msg {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "pathfinder_subscriptionError",
                "params": {
                    "result": { "code": -32603, "message": "Internal error" },
                    "subscription_id": subscription_id
                }
            })
        )
    }

    #[tokio::test]
    async fn test_error_returned_from_subscribe() {
        struct ErrorFromSubscribe;

        #[async_trait]
        impl RpcSubscriptionFlow for ErrorFromSubscribe {
            type Params = Params;
            type Notification = serde_json::Value;

            fn starting_block(_params: &Self::Params) -> BlockId {
                BlockId::Number(BlockNumber::GENESIS)
            }

            async fn catch_up(
                _state: &RpcContext,
                _params: &Self::Params,
                _from: BlockNumber,
                _to: BlockNumber,
            ) -> Result<CatchUp<Self::Notification>, crate::jsonrpc::RpcError> {
                Ok(Default::default())
            }

            async fn subscribe(
                _state: RpcContext,
                _params: Self::Params,
                _tx: tokio::sync::mpsc::Sender<SubscriptionMessage<Self::Notification>>,
            ) -> Result<(), crate::jsonrpc::RpcError> {
                Err(crate::jsonrpc::RpcError::InternalError(anyhow::anyhow!(
                    "error from catch_up"
                )))
            }
        }

        let router = setup(5, ErrorFromSubscribe).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "test",
                    "params": {}
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let subscription_id = match res {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let msg = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match msg {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "pathfinder_subscriptionError",
                "params": {
                    "result": { "code": -32603, "message": "Internal error" },
                    "subscription_id": subscription_id
                }
            })
        )
    }

    #[derive(Debug, Clone)]
    struct Params;

    impl DeserializeForVersion for Params {
        fn deserialize(_: crate::dto::Value) -> Result<Self, serde_json::Error> {
            Ok(Self)
        }
    }

    async fn setup(num_blocks: u64, endpoint: impl RpcSubscriptionEndpoint + 'static) -> RpcRouter {
        let storage = StorageBuilder::in_memory().unwrap();
        tokio::task::spawn_blocking({
            let storage = storage.clone();
            move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                for i in 0..num_blocks {
                    let header = BlockHeader {
                        hash: BlockHash(Felt::from_u64(i)),
                        number: BlockNumber::new_or_panic(i),
                        parent_hash: BlockHash::ZERO,
                        ..Default::default()
                    };
                    db.insert_block_header(&header).unwrap();
                }
                db.commit().unwrap();
            }
        })
        .await
        .unwrap();
        let (_, pending_data) = tokio::sync::watch::channel(Default::default());
        let notifications = Notifications::default();
        let ctx = RpcContext {
            cache: Default::default(),
            storage,
            execution_storage: StorageBuilder::in_memory().unwrap(),
            pending_data: PendingWatcher::new(pending_data),
            sync_status: SyncState {
                status: Syncing::False(false).into(),
            }
            .into(),
            chain_id: ChainId::MAINNET,
            core_contract_address: H160::from(pathfinder_ethereum::core_addr::MAINNET),
            sequencer: Client::mainnet(Duration::from_secs(10)),
            websocket: None,
            notifications,
            ethereum: EthereumClient::new("wss://eth-sepolia.g.alchemy.com/v2/just-for-tests")
                .unwrap(),
            config: RpcConfig {
                batch_concurrency_limit: 1.try_into().unwrap(),
                get_events_max_blocks_to_scan: 1.try_into().unwrap(),
                get_events_max_uncached_bloom_filters_to_load: 1.try_into().unwrap(),
                #[cfg(feature = "aggregate_bloom")]
                get_events_max_bloom_filters_to_load: 1.try_into().unwrap(),
                custom_versioned_constants: None,
            },
        };
        RpcRouter::builder(crate::RpcVersion::V08)
            .register("test", endpoint)
            .build(ctx)
    }
}
