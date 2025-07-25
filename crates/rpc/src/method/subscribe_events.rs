use std::collections::HashSet;
use std::sync::Arc;

use pathfinder_common::{BlockNumber, ContractAddress, EventKey};
use pathfinder_storage::{AGGREGATE_BLOOM_BLOCK_RANGE_LEN, EVENT_KEY_FILTER_LIMIT};
use tokio::sync::mpsc;

use super::REORG_SUBSCRIPTION_NAME;
use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::jsonrpc::{CatchUp, RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::method::get_events::EmittedEvent;
use crate::types::request::SubscriptionBlockId;
use crate::{Reorg, RpcVersion};

pub struct SubscribeEvents;

#[derive(Debug, Clone, Default)]
pub struct Params {
    from_address: Option<ContractAddress>,
    keys: Option<Vec<Vec<EventKey>>>,
    block_id: Option<SubscriptionBlockId>,
}

impl Params {
    fn matches(&self, event: &pathfinder_common::event::Event) -> bool {
        if let Some(from_address) = self.from_address {
            if event.from_address != from_address {
                return false;
            }
        }
        if let Some(keys) = &self.keys {
            let no_key_constraints = keys.iter().flatten().count() == 0;
            if no_key_constraints {
                return true;
            }
            if event.keys.len() < keys.len() {
                return false;
            }
            event
                .keys
                .iter()
                .zip(keys.iter())
                .all(|(key, filter)| filter.is_empty() || filter.contains(key))
        } else {
            true
        }
    }
}

impl crate::dto::DeserializeForVersion for Option<Params> {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        if value.is_null() {
            // Params are optional.
            return Ok(None);
        }
        value.deserialize_map(|value| {
            Ok(Some(Params {
                from_address: value
                    .deserialize_optional("from_address")?
                    .map(ContractAddress),
                keys: value.deserialize_optional_array("keys", |value| {
                    value.deserialize_array(|value| Ok(EventKey(value.deserialize()?)))
                })?,
                block_id: value.deserialize_optional("block_id")?,
            }))
        })
    }
}

#[derive(Debug)]
pub enum Notification {
    EmittedEvent(crate::method::get_events::EmittedEvent),
    Reorg(Arc<Reorg>),
}

impl crate::dto::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            Notification::EmittedEvent(event) => event.serialize(serializer),
            Notification::Reorg(reorg) => reorg.serialize(serializer),
        }
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionEvents";

impl RpcSubscriptionFlow for SubscribeEvents {
    type Params = Option<Params>;
    type Notification = Notification;
    const CATCH_UP_BATCH_SIZE: u64 = AGGREGATE_BLOOM_BLOCK_RANGE_LEN;

    fn validate_params(params: &Self::Params) -> Result<(), RpcError> {
        if let Some(params) = params {
            if let Some(keys) = &params.keys {
                if keys.len() > EVENT_KEY_FILTER_LIMIT {
                    return Err(RpcError::ApplicationError(
                        ApplicationError::TooManyKeysInFilter {
                            limit: EVENT_KEY_FILTER_LIMIT,
                            requested: keys.len(),
                        },
                    ));
                }
            }
        }
        Ok(())
    }

    fn starting_block(params: &Self::Params) -> SubscriptionBlockId {
        params
            .as_ref()
            .and_then(|req| req.block_id)
            .unwrap_or(SubscriptionBlockId::Latest)
    }

    async fn catch_up(
        state: &RpcContext,
        params: &Self::Params,
        from: BlockNumber,
        to: BlockNumber,
    ) -> Result<CatchUp<Self::Notification>, RpcError> {
        let params = params.clone().unwrap_or_default();
        let storage = state.storage.clone();
        let (events, last_block) = util::task::spawn_blocking(move |_| -> Result<_, RpcError> {
            let mut conn = storage.connection().map_err(RpcError::InternalError)?;
            let db = conn.transaction().map_err(RpcError::InternalError)?;

            if db.blockchain_pruning_enabled() {
                let blockchain_history_tip = db
                    .earliest_block_number()
                    .map_err(RpcError::InternalError)?
                    .unwrap_or(BlockNumber::GENESIS);
                if from < blockchain_history_tip {
                    tracing::debug!(
                        from_block = %from,
                        %blockchain_history_tip,
                        "Event catch-up batch is below the blockchain history tip, sending an error and closing the subscription"
                    );
                    // Some of the blocks that were supposed to be part of this catch-up batch have
                    // been pruned in the meantime. Send the user an error because we cannot
                    // maintain data integrity at this point.
                    return Err(RpcError::InternalError(anyhow::anyhow!(
                        "Next block to be streamed ({from}) could not be found. It has likely \
                         been pruned during an ongoing subscription"
                    )));
                }
            }

            let events = db
                .events_in_range(
                    from,
                    to,
                    params.from_address,
                    params.keys.unwrap_or_default(),
                )
                .map_err(RpcError::InternalError)?;

            Ok(events)
        })
        .await
        .map_err(|e| RpcError::InternalError(e.into()))??;
        let messages = events
            .into_iter()
            .map(|event| {
                let block_number = event.block_number;
                SubscriptionMessage {
                    notification: Notification::EmittedEvent(event.into()),
                    block_number,
                    subscription_name: SUBSCRIPTION_NAME,
                }
            })
            .collect();
        Ok(CatchUp {
            messages,
            last_block,
        })
    }

    async fn subscribe(
        state: RpcContext,
        _version: RpcVersion,
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError> {
        let mut blocks = state.notifications.l2_blocks.subscribe();
        let mut reorgs = state.notifications.reorgs.subscribe();
        let mut pending_data = state.pending_data.0.clone();
        let mut params = params.unwrap_or_default();

        if let Some(ref mut keys) = params.keys {
            // Truncate empty key lists from the end of the key filter.
            if let Some(last_non_empty) = keys.iter().rposition(|keys| !keys.is_empty()) {
                keys.truncate(last_non_empty + 1);
            }
        }

        let mut sent_txs = HashSet::new();
        let mut current_block = BlockNumber::GENESIS;
        loop {
            tokio::select! {
                reorg = reorgs.recv() => {
                    match reorg {
                        Ok(reorg) => {
                            let block_number = reorg.first_block_number;
                            if tx.send(SubscriptionMessage {
                                notification: Notification::Reorg(reorg),
                                block_number,
                                subscription_name: REORG_SUBSCRIPTION_NAME,
                            }).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Error receiving reorg from notifications channel, node might be \
                                 lagging: {:?}",
                                e
                            );
                            return Ok(());
                        }
                    }
                }
                block = blocks.recv() => {
                    match block {
                        Ok(block) => {
                            let block_number = block.block_number;
                            let block_hash = block.block_hash;

                            tracing::trace!(%block_number, %block_hash, "Received new block");

                            if block_number != current_block {
                                tracing::trace!(
                                    %block_number,
                                    %current_block,
                                    "Clearing sent transactions"
                                );
                                sent_txs.clear();
                                current_block = block_number;
                            }
                            for (receipt, events) in block.transaction_receipts.iter() {
                                if sent_txs.contains(&receipt.transaction_hash) {
                                    tracing::trace!(
                                        transaction_hash=%receipt.transaction_hash,
                                        "Transaction already sent, skipping"
                                    );
                                    continue;
                                }
                                for event in events {
                                    // Check if the event matches the filter.
                                    if !params.matches(event) {
                                        continue;
                                    }
                                    sent_txs.insert(receipt.transaction_hash);
                                    if tx.send(SubscriptionMessage {
                                        notification: Notification::EmittedEvent(EmittedEvent {
                                            data: event.data.clone(),
                                            keys: event.keys.clone(),
                                            from_address: event.from_address,
                                            block_hash: Some(block_hash),
                                            block_number: Some(block_number),
                                            transaction_hash: receipt.transaction_hash,
                                        }),
                                        block_number,
                                        subscription_name: SUBSCRIPTION_NAME,
                                    }).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Error receiving block header from notifications channel, node might be \
                                 lagging: {:?}",
                                e
                            );
                            return Ok(());
                        }
                    }
                }
                pending_changed = pending_data.changed() => {
                    if let Err(e) = pending_changed {
                        tracing::debug!(error=%e, "Pending data channel closed, stopping subscription");
                        return Ok(());
                    }

                    let pending = pending_data.borrow_and_update().clone();
                    if pending.is_pre_confirmed() {
                        // Ignore pre-confirmed data as it might never actually finalize.
                        continue;
                    }

                    tracing::trace!(block_number=%pending.block_number(), "Received pending block update");

                    let block_number = pending.block_number();
                    if block_number != current_block {
                        tracing::trace!(
                            %block_number,
                            %current_block,
                            "Clearing sent transactions"
                        );
                        sent_txs.clear();
                        current_block = block_number;
                    }
                    for (receipt, events) in pending.transaction_receipts_and_events().iter() {
                        if sent_txs.contains(&receipt.transaction_hash) {
                            tracing::trace!(
                                transaction_hash=%receipt.transaction_hash,
                                "Transaction already sent, skipping"
                            );
                            continue;
                        }
                        for event in events {
                            // Check if the event matches the filter.
                            if !params.matches(event) {
                                continue;
                            }
                            sent_txs.insert(receipt.transaction_hash);
                            tracing::trace!(
                                transaction_hash=%receipt.transaction_hash,
                                "Sending event"
                            );
                            if tx.send(SubscriptionMessage {
                                notification: Notification::EmittedEvent(EmittedEvent {
                                    data: event.data.clone(),
                                    keys: event.keys.clone(),
                                    from_address: event.from_address,
                                    block_hash: None,
                                    block_number: Some(block_number),
                                    transaction_hash: receipt.transaction_hash,
                                }),
                                block_number,
                                subscription_name: SUBSCRIPTION_NAME,
                            }).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;
    use pathfinder_common::event::Event;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::transaction::{Transaction, TransactionVariant};
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_types::reply::{Block, PendingBlock, PreConfirmedBlock};
    use tokio::sync::mpsc;

    use crate::context::{RpcContext, WebsocketContext};
    use crate::jsonrpc::websocket::WebsocketHistory;
    use crate::jsonrpc::{handle_json_rpc_socket, RpcRouter, RpcSubscriptionFlow};
    use crate::method::subscribe_events::SubscribeEvents;
    use crate::{v06, v07, v08, v09, Notifications, Reorg, RpcVersion};

    #[tokio::test]
    async fn no_filtering() {
        let num_blocks = SubscribeEvents::CATCH_UP_BATCH_SIZE + 10;
        let (router, _pending_data_tx) = setup(num_blocks, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {"block_id": {"block_number": 0}}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        for i in 0..num_blocks {
            let expected = sample_event_message(i, subscription_id);
            let event = sender_rx.recv().await.unwrap().unwrap();
            let json: serde_json::Value = match event {
                Message::Text(json) => serde_json::from_str(&json).unwrap(),
                _ => panic!("Expected text message"),
            };
            assert_eq!(json, expected);
        }
        for i in 0..10 {
            retry(|| {
                router
                    .context
                    .notifications
                    .l2_blocks
                    .send(sample_block(i).into())
            })
            .await
            .unwrap();
            let expected = sample_event_message(i, subscription_id);
            let event = sender_rx.recv().await.unwrap().unwrap();
            let json: serde_json::Value = match event {
                Message::Text(json) => serde_json::from_str(&json).unwrap(),
                _ => panic!("Expected text message"),
            };
            assert_eq!(json, expected);
        }
        assert!(sender_rx.is_empty());
    }

    #[tokio::test]
    async fn filter_from_address() {
        let (router, _pending_data_tx) =
            setup(SubscribeEvents::CATCH_UP_BATCH_SIZE + 10, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x16",
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        retry(|| {
            router
                .context
                .notifications
                .l2_blocks
                .send(sample_block(0x8f).into())
        })
        .await
        .unwrap();
        router
            .context
            .notifications
            .l2_blocks
            .send(sample_block(0x16).into())
            .unwrap();
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        assert!(sender_rx.is_empty());
    }

    #[tokio::test]
    async fn filter_keys() {
        let (router, _pending_data_tx) =
            setup(SubscribeEvents::CATCH_UP_BATCH_SIZE + 10, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "keys": [["0x16"], [], ["0x17", "0x18"]],
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        retry(|| {
            router
                .context
                .notifications
                .l2_blocks
                .send(sample_block(0x8f).into())
        })
        .await
        .unwrap();
        router
            .context
            .notifications
            .l2_blocks
            .send(sample_block(0x16).into())
            .unwrap();
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        assert!(sender_rx.is_empty());
    }

    #[tokio::test]
    async fn filter_from_address_and_keys() {
        let (router, _pending_data_tx) =
            setup(SubscribeEvents::CATCH_UP_BATCH_SIZE + 10, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x16",
                "keys": [["0x16"], [], ["0x17", "0x18"]],
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        retry(|| {
            router
                .context
                .notifications
                .l2_blocks
                .send(sample_block(0x8f).into())
        })
        .await
        .unwrap();
        router
            .context
            .notifications
            .l2_blocks
            .send(sample_block(0x16).into())
            .unwrap();
        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        assert!(sender_rx.is_empty());
    }

    #[test_log::test(tokio::test)]
    async fn filter_keys_pending() {
        let num_blocks = SubscribeEvents::CATCH_UP_BATCH_SIZE + 10;
        let (router, pending_data_tx) = setup(num_blocks, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "keys": [["0x16", format!("{:x}", num_blocks), format!("{:x}", num_blocks + 1)]],
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };

        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);

        let next_block_number = SubscribeEvents::CATCH_UP_BATCH_SIZE + 10;
        pending_data_tx
            .send(crate::PendingData::from_pending_block(
                sample_pending_block(next_block_number),
                StateUpdate::default(),
                BlockNumber::new_or_panic(next_block_number),
            ))
            .unwrap();
        let expected = sample_event_message_without_block_hash(next_block_number, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);

        router
            .context
            .notifications
            .l2_blocks
            .send(sample_block(next_block_number).into())
            .unwrap();

        let next_block_number = next_block_number + 1;
        assert_eq!(
            router
                .context
                .notifications
                .l2_blocks
                .send(sample_block(next_block_number).into())
                .unwrap(),
            1
        );

        let expected = sample_event_message(next_block_number, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        assert!(sender_rx.is_empty());
    }

    #[test_log::test(tokio::test)]
    async fn ignore_pre_confirmed_data() {
        let num_blocks = SubscribeEvents::CATCH_UP_BATCH_SIZE + 10;
        let (router, pending_data_tx) = setup(num_blocks, RpcVersion::V09).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "keys": [["0x16", format!("{:x}", num_blocks), format!("{:x}", num_blocks + 1)]],
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
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
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };

        let expected = sample_event_message(0x16, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);

        // Send pre-confirmed data, expecting it to be ignored.
        pending_data_tx
            .send(crate::PendingData::from_pre_confirmed_block(
                sample_pre_confirmed_block(num_blocks),
                BlockNumber::new_or_panic(num_blocks),
            ))
            .unwrap();
        assert!(sender_rx.is_empty());

        // Process a new block to make sure that we are still receiving new blocks, just
        // not pre-confirmed data.
        let next_block_number = num_blocks + 1;
        let num_receivers = retry(|| {
            router
                .context
                .notifications
                .l2_blocks
                .send(sample_block(next_block_number).into())
        })
        .await
        .unwrap();
        assert_eq!(num_receivers, 1);

        // Expect `num_blocks + 1` (new block) and not `num_blocks` (pending data).
        let expected = sample_event_message(next_block_number, subscription_id);
        let event = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match event {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected);
        assert!(sender_rx.is_empty());
    }

    #[tokio::test]
    async fn too_many_keys_filter() {
        let (router, _pending_data_tx) =
            setup(SubscribeEvents::CATCH_UP_BATCH_SIZE + 10, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x10",
                "keys": [
                    ["0x10"],
                    ["0x10"],
                    ["0x11"],
                    ["0x13"],
                    ["0x14"],
                    ["0x15"],
                    ["0x16"],
                    ["0x17"],
                    ["0x18"],
                    ["0x19"],
                    ["0x1a"],
                    ["0x1b"],
                    ["0x1c"],
                    ["0x1d"],
                    ["0x1e"],
                    ["0x1f"],
                    ["0x20"],
                ],
            }
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": params
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        match res {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(
                    json,
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": 34,
                            "data": { "limit": 16, "requested": 17 },
                            "message": "Too many keys provided in a filter"
                        }
                    }),
                );
            }
            _ => panic!("Expected text message"),
        }
    }

    #[test_log::test(tokio::test)]
    async fn reorg() {
        let (router, _pending_data_tx) = setup(1, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);

        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let subscription_id: u64 = match res {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_str().unwrap().parse().unwrap()
            }
            _ => panic!("Expected text message"),
        };

        // event from "latest" block
        let res = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match res {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "starknet_subscriptionEvents",
                "params": {
                    "result": {
                        "block_hash": "0x0",
                        "block_number": 0,
                        "data": ["0x0", "0x1", "0x2"],
                        "from_address": "0x0",
                        "keys": ["0x0", "0x1", "0x2"],
                        "transaction_hash": "0x0"
                    },
                    "subscription_id": subscription_id.to_string()
                }
            })
        );

        retry(|| {
            router.context.notifications.reorgs.send(
                Reorg {
                    first_block_number: BlockNumber::new_or_panic(1),
                    first_block_hash: BlockHash(felt!("0x1")),
                    last_block_number: BlockNumber::new_or_panic(2),
                    last_block_hash: BlockHash(felt!("0x2")),
                }
                .into(),
            )
        })
        .await
        .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match res {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "starknet_subscriptionReorg",
                "params": {
                    "result": {
                        "first_block_hash": "0x1",
                        "first_block_number": 1,
                        "last_block_hash": "0x2",
                        "last_block_number": 2
                    },
                    "subscription_id": subscription_id.to_string()
                }
            })
        );
    }

    #[tokio::test]
    async fn subscribe_with_pending_block() {
        let (router, _pending_data_tx) = setup(1, RpcVersion::V08).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);

        // Send subscription request with pending block
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeEvents",
                    "params": {"block_id": "pending"}
                })
                .to_string(),
            )))
            .await
            .unwrap();

        // Expect error response
        let res = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match res {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };

        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32602,
                    "message": "Invalid params",
                    "data": {
                        "reason": "Invalid block id"
                    }
                }
            })
        );
    }

    async fn setup(
        num_blocks: u64,
        version: RpcVersion,
    ) -> (RpcRouter, tokio::sync::watch::Sender<crate::PendingData>) {
        assert!(num_blocks > 0);

        let storage = StorageBuilder::in_memory().unwrap();
        tokio::task::spawn_blocking({
            let storage = storage.clone();
            move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                for i in 0..num_blocks {
                    let header = sample_header(i);
                    db.insert_block_header(&header).unwrap();
                    let tx = sample_transaction(i);
                    let receipt = sample_receipt(i);
                    let event = sample_event(i);
                    db.insert_transaction_data(
                        BlockNumber::new_or_panic(i),
                        &[(tx, receipt)],
                        Some(&[vec![event]]),
                    )
                    .unwrap();
                }
                db.commit().unwrap();
                tracing::debug!("Inserted {} blocks", num_blocks);
            }
        })
        .await
        .unwrap();
        let (pending_data_tx, pending_data) = tokio::sync::watch::channel(Default::default());
        let notifications = Notifications::default();
        let ctx = RpcContext::for_tests()
            .with_storage(storage)
            .with_notifications(notifications)
            .with_pending_data(pending_data.clone())
            .with_websockets(WebsocketContext::new(WebsocketHistory::Unlimited));
        match version {
            RpcVersion::V06 => (v06::register_routes().build(ctx), pending_data_tx),
            RpcVersion::V07 => (v07::register_routes().build(ctx), pending_data_tx),
            RpcVersion::V08 => (v08::register_routes().build(ctx), pending_data_tx),
            RpcVersion::V09 => (v09::register_routes().build(ctx), pending_data_tx),
            RpcVersion::PathfinderV01 => {
                unreachable!("Did not expect RPC version for tests to be Pathfinder v0.1")
            }
        }
    }

    fn sample_header(block_number: u64) -> BlockHeader {
        BlockHeader {
            hash: BlockHash(Felt::from_u64(block_number)),
            number: BlockNumber::new_or_panic(block_number),
            ..Default::default()
        }
    }

    fn sample_event(block_number: u64) -> Event {
        Event {
            data: vec![
                EventData(Felt::from_u64(block_number)),
                EventData(Felt::from_u64(block_number + 1)),
                EventData(Felt::from_u64(block_number + 2)),
            ],
            from_address: ContractAddress(Felt::from_u64(block_number)),
            keys: vec![
                EventKey(Felt::from_u64(block_number)),
                EventKey(Felt::from_u64(block_number + 1)),
                EventKey(Felt::from_u64(block_number + 2)),
            ],
        }
    }

    fn sample_transaction(block_number: u64) -> Transaction {
        Transaction {
            hash: TransactionHash(Felt::from_u64(block_number)),
            variant: TransactionVariant::DeclareV0(Default::default()),
        }
    }

    fn sample_receipt(block_number: u64) -> Receipt {
        Receipt {
            transaction_hash: TransactionHash(Felt::from_u64(block_number)),
            transaction_index: TransactionIndex::new_or_panic(0),
            ..Default::default()
        }
    }

    fn sample_block(block_number: u64) -> Block {
        Block {
            block_hash: BlockHash(Felt::from_u64(block_number)),
            block_number: BlockNumber::new_or_panic(block_number),
            transaction_receipts: vec![(
                sample_receipt(block_number),
                vec![sample_event(block_number)],
            )],
            transactions: vec![sample_transaction(block_number)],
            ..Default::default()
        }
    }

    fn sample_pending_block(block_number: u64) -> PendingBlock {
        PendingBlock {
            transaction_receipts: vec![(
                sample_receipt(block_number),
                vec![sample_event(block_number)],
            )],
            transactions: vec![sample_transaction(block_number)],
            ..Default::default()
        }
    }

    fn sample_pre_confirmed_block(block_number: u64) -> PreConfirmedBlock {
        PreConfirmedBlock {
            transaction_receipts: vec![Some((
                sample_receipt(block_number),
                vec![sample_event(block_number)],
            ))],
            transactions: vec![sample_transaction(block_number)],
            ..Default::default()
        }
    }

    fn sample_event_message(block_number: u64, subscription_id: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionEvents",
            "params": {
                "result": {
                    "keys": [
                        Felt::from_u64(block_number),
                        Felt::from_u64(block_number + 1),
                        Felt::from_u64(block_number + 2),
                    ],
                    "data": [
                        Felt::from_u64(block_number),
                        Felt::from_u64(block_number + 1),
                        Felt::from_u64(block_number + 2),
                    ],
                    "from_address": Felt::from_u64(block_number),
                    "block_number": block_number,
                    "block_hash": Felt::from_u64(block_number),
                    "transaction_hash": Felt::from_u64(block_number),
                },
                "subscription_id": subscription_id.to_string()
            }
        })
    }

    fn sample_event_message_without_block_hash(
        block_number: u64,
        subscription_id: u64,
    ) -> serde_json::Value {
        let mut message = sample_event_message(block_number, subscription_id);
        message["params"]["result"]
            .as_object_mut()
            .unwrap()
            .remove("block_hash");
        message
    }

    // Retry to let other tasks make progress.
    async fn retry<T, E>(cb: impl Fn() -> Result<T, E>) -> Result<T, E>
    where
        E: std::fmt::Debug,
    {
        const RETRIES: u64 = 25;
        for i in 0..RETRIES {
            match cb() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if i == RETRIES - 1 {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_secs(i)).await;
                }
            }
        }
        unreachable!()
    }
}
