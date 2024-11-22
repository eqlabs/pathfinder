use std::sync::Arc;

use axum::async_trait;
use pathfinder_common::{BlockId, BlockNumber, ContractAddress, EventKey};
use pathfinder_storage::EVENT_KEY_FILTER_LIMIT;
use tokio::sync::mpsc;

use super::REORG_SUBSCRIPTION_NAME;
use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::jsonrpc::{CatchUp, RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::method::get_events::EmittedEvent;
use crate::Reorg;

pub struct SubscribeEvents;

#[derive(Debug, Clone, Default)]
pub struct Params {
    from_address: Option<ContractAddress>,
    keys: Option<Vec<Vec<EventKey>>>,
    block_id: Option<BlockId>,
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
                block_id: value.deserialize_optional_serde("block_id")?,
            }))
        })
    }
}

#[derive(Debug)]
pub enum Notification {
    EmittedEvent(crate::method::get_events::EmittedEvent),
    Reorg(Arc<Reorg>),
}

impl crate::dto::serialize::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        match self {
            Notification::EmittedEvent(event) => event.serialize(serializer),
            Notification::Reorg(reorg) => reorg.serialize(serializer),
        }
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionEvents";

#[async_trait]
impl RpcSubscriptionFlow for SubscribeEvents {
    type Params = Option<Params>;
    type Notification = Notification;

    fn validate_params(params: &Self::Params) -> Result<(), RpcError> {
        if let Some(params) = params {
            if let Some(BlockId::Pending) = params.block_id {
                return Err(RpcError::ApplicationError(ApplicationError::CallOnPending));
            }
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

    fn starting_block(params: &Self::Params) -> BlockId {
        params
            .as_ref()
            .and_then(|req| req.block_id)
            .unwrap_or(BlockId::Latest)
    }

    async fn catch_up(
        state: &RpcContext,
        params: &Self::Params,
        from: BlockNumber,
        to: BlockNumber,
    ) -> Result<CatchUp<Self::Notification>, RpcError> {
        let params = params.clone().unwrap_or_default();
        let storage = state.storage.clone();
        let (events, last_block) = tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
            let mut conn = storage.connection().map_err(RpcError::InternalError)?;
            let db = conn.transaction().map_err(RpcError::InternalError)?;
            db.events_in_range(
                from,
                to,
                params.from_address,
                params.keys.unwrap_or_default(),
            )
            .map_err(RpcError::InternalError)
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
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError> {
        let mut blocks = state.notifications.l2_blocks.subscribe();
        let mut reorgs = state.notifications.reorgs.subscribe();
        let params = params.unwrap_or_default();
        let keys = params.keys.unwrap_or_default();
        let key_filter_is_empty = keys.iter().flatten().count() == 0;
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
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Error receiving reorg from notifications channel, node might be \
                                 lagging: {:?}",
                                e
                            );
                            break;
                        }
                    }
                }
                block = blocks.recv() => {
                    match block {
                        Ok(block) => {
                            let block_number = block.block_number;
                            let block_hash = block.block_hash;
                            for (receipt, events) in block.transaction_receipts.iter() {
                                for event in events {
                                    // Check if the event matches the filter.
                                    if let Some(from_address) = params.from_address {
                                        if event.from_address != from_address {
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
                                        break;
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
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;
    use pathfinder_common::event::Event;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::transaction::{Transaction, TransactionVariant};
    use pathfinder_common::{
        felt,
        BlockHash,
        BlockHeader,
        BlockNumber,
        ChainId,
        ContractAddress,
        EventData,
        EventKey,
        TransactionHash,
        TransactionIndex,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_ethereum::EthereumClient;
    use pathfinder_storage::StorageBuilder;
    use primitive_types::H160;
    use starknet_gateway_client::Client;
    use starknet_gateway_types::reply::Block;
    use tokio::sync::mpsc;

    use crate::context::{RpcConfig, RpcContext};
    use crate::jsonrpc::{handle_json_rpc_socket, RpcRouter, CATCH_UP_BATCH_SIZE};
    use crate::pending::PendingWatcher;
    use crate::types::syncing::Syncing;
    use crate::{v08, Notifications, Reorg, SyncState};

    #[tokio::test]
    async fn no_filtering() {
        let num_blocks = 2000;
        let router = setup(num_blocks).await;
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
                json["result"].as_u64().unwrap()
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
        let router = setup(2000).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x46",
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
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x46, subscription_id);
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
            .send(sample_block(0x46).into())
            .unwrap();
        let expected = sample_event_message(0x46, subscription_id);
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
        let router = setup(2000).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "keys": [["0x46"], [], ["0x47", "0x48"]],
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
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x46, subscription_id);
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
            .send(sample_block(0x46).into())
            .unwrap();
        let expected = sample_event_message(0x46, subscription_id);
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
        let router = setup(2000).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x46",
                "keys": [["0x46"], [], ["0x47", "0x48"]],
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
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
        let expected = sample_event_message(0x46, subscription_id);
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
            .send(sample_block(0x46).into())
            .unwrap();
        let expected = sample_event_message(0x46, subscription_id);
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
        let router = setup(2000).await;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {
                "block_id": {"block_number": 0},
                "from_address": "0x46",
                "keys": [
                    ["0x46"],
                    ["0x47"],
                    ["0x48"],
                    ["0x49"],
                    ["0x4a"],
                    ["0x4b"],
                    ["0x4c"],
                    ["0x4d"],
                    ["0x4e"],
                    ["0x4f"],
                    ["0x50"],
                    ["0x51"],
                    ["0x52"],
                    ["0x53"],
                    ["0x54"],
                    ["0x55"],
                    ["0x56"],
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

    #[tokio::test]
    async fn reorg() {
        let router = setup(0).await;
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
        let subscription_id = match res {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_u64().unwrap()
            }
            _ => panic!("Expected text message"),
        };
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
                    "subscription_id": subscription_id
                }
            })
        );
    }

    #[tokio::test]
    async fn subscribe_with_pending_block() {
        let router = setup(0).await;
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
                    "code": 69,
                    "message": "This method does not support being called on the pending block"
                }
            })
        );
    }

    async fn setup(num_blocks: u64) -> RpcRouter {
        assert!(num_blocks == 0 || num_blocks > CATCH_UP_BATCH_SIZE);

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
                batch_concurrency_limit: 64.try_into().unwrap(),
                get_events_max_blocks_to_scan: 1024.try_into().unwrap(),
                get_events_max_uncached_bloom_filters_to_load: 1024.try_into().unwrap(),
                #[cfg(feature = "aggregate_bloom")]
                get_events_max_bloom_filters_to_load: 1.try_into().unwrap(),
                custom_versioned_constants: None,
            },
        };
        v08::register_routes().build(ctx)
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
                "subscription_id": subscription_id
            }
        })
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
