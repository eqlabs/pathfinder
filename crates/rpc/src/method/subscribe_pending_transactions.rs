use std::collections::HashSet;

use axum::async_trait;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockId, BlockNumber, ContractAddress, TransactionHash};
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};

pub struct SubscribePendingTransactions;

#[derive(Debug, Clone)]
pub struct Request {
    transaction_details: Option<bool>,
    sender_address: Option<HashSet<ContractAddress>>,
}

impl crate::dto::DeserializeForVersion for Request {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_details: value.deserialize_optional_serde("transaction_details")?,
                sender_address: value
                    .deserialize_optional_array("sender_address", |addr| {
                        Ok(ContractAddress(addr.deserialize()?))
                    })?
                    .map(|addrs| addrs.into_iter().collect()),
            })
        })
    }
}

#[derive(Debug)]
pub enum Notification {
    Transaction(Box<Transaction>),
    TransactionHash(TransactionHash),
}

impl crate::dto::serialize::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        match self {
            Notification::Transaction(transaction) => {
                crate::dto::Transaction(transaction).serialize(serializer)
            }
            Notification::TransactionHash(transaction_hash) => {
                transaction_hash.0.serialize(serializer)
            }
        }
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionPendingTransactions";

#[async_trait]
impl RpcSubscriptionFlow for SubscribePendingTransactions {
    type Request = Request;
    type Notification = Notification;

    fn starting_block(_req: &Self::Request) -> BlockId {
        // Rollback is not supported.
        BlockId::Latest
    }

    async fn catch_up(
        _state: &RpcContext,
        _req: &Self::Request,
        _from: BlockNumber,
        _to: BlockNumber,
    ) -> Result<Vec<SubscriptionMessage<Self::Notification>>, RpcError> {
        Ok(vec![])
    }

    async fn subscribe(
        state: RpcContext,
        req: Self::Request,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) {
        let mut pending_data = state.pending_data.0.clone();
        // Last block sent to the subscriber. Initial value doesn't really matter
        let mut last_block = BlockNumber::GENESIS;
        // Hashes of transactions that have already been sent to the subscriber, as part
        // of `last_block` block. It is necessary to keep track of this because the
        // pending data updates might include new transactions for the same
        // block number.
        let mut sent_txs = HashSet::new();
        loop {
            let pending = pending_data.borrow_and_update().clone();
            if pending.number != last_block {
                last_block = pending.number;
                sent_txs.clear();
            }
            for transaction in pending.block.transactions.iter() {
                if sent_txs.contains(&transaction.hash) {
                    continue;
                }
                // Filter the transactions by sender address.
                if let Some(sender_address) = &req.sender_address {
                    use pathfinder_common::transaction::TransactionVariant::*;
                    let address = match &transaction.variant {
                        DeclareV0(tx) => tx.sender_address,
                        DeclareV1(tx) => tx.sender_address,
                        DeclareV2(tx) => tx.sender_address,
                        DeclareV3(tx) => tx.sender_address,
                        DeployV0(tx) => tx.contract_address,
                        DeployV1(tx) => tx.contract_address,
                        DeployAccountV1(tx) => tx.contract_address,
                        DeployAccountV3(tx) => tx.contract_address,
                        InvokeV0(tx) => tx.sender_address,
                        InvokeV1(tx) => tx.sender_address,
                        InvokeV3(tx) => tx.sender_address,
                        L1Handler(tx) => tx.contract_address,
                    };
                    if !sender_address.contains(&address) {
                        continue;
                    }
                }
                let notification = match req.transaction_details {
                    Some(true) => Notification::Transaction(transaction.clone().into()),
                    Some(false) | None => Notification::TransactionHash(transaction.hash),
                };
                sent_txs.insert(transaction.hash);
                if tx
                    .send(SubscriptionMessage {
                        notification,
                        block_number: pending.number,
                        subscription_name: SUBSCRIPTION_NAME,
                    })
                    .await
                    .is_err()
                {
                    // Subscription has been closed.
                    return;
                }
            }
            if pending_data.changed().await.is_err() {
                tracing::debug!("Pending data channel closed, stopping subscription");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;
    use pathfinder_common::transaction::{DeclareTransactionV0V1, Transaction, TransactionVariant};
    use pathfinder_common::{
        contract_address,
        transaction_hash,
        BlockNumber,
        ChainId,
        ContractAddress,
        TransactionHash,
    };
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_client::Client;
    use starknet_gateway_types::reply::PendingBlock;
    use tokio::sync::{mpsc, watch};

    use crate::context::{RpcConfig, RpcContext};
    use crate::jsonrpc::{handle_json_rpc_socket, RpcResponse};
    use crate::pending::PendingWatcher;
    use crate::v02::types::syncing::Syncing;
    use crate::{v08, Notifications, PendingData, SyncState};

    #[tokio::test]
    async fn no_filtering_no_details() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribePendingTransactions",
                "params": {}
            })
            .to_string(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"]["subscription_id"].as_u64().unwrap()
            }
            _ => {
                panic!("Expected text message");
            }
        };
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS,
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x1")),
                    (contract_address!("0x2"), transaction_hash!("0x2")),
                ],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x1", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x2", subscription_id)
        );
        assert!(rx.is_empty());
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS,
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x1")),
                    (contract_address!("0x2"), transaction_hash!("0x2")),
                    (contract_address!("0x3"), transaction_hash!("0x3")),
                    (contract_address!("0x4"), transaction_hash!("0x4")),
                    (contract_address!("0x5"), transaction_hash!("0x5")),
                ],
            ))
            .unwrap();
        // Assert that same transactions are not sent twice.
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x4", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x5", subscription_id)
        );
        // Assert that transactions from new blocks are sent correctly.
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS + 1,
                vec![(contract_address!("0x1"), transaction_hash!("0x1"))],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x1", subscription_id)
        );
        assert!(rx.is_empty());
    }

    #[tokio::test]
    async fn no_filtering_with_details() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribePendingTransactions",
                "params": {
                    "transaction_details": true
                }
            })
            .to_string(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"]["subscription_id"].as_u64().unwrap()
            }
            _ => {
                panic!("Expected text message");
            }
        };
        assert!(rx.is_empty());
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS,
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                ],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_message_with_details("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_message_with_details("0x2", "0x4", subscription_id)
        );
        assert!(rx.is_empty());
    }

    #[tokio::test]
    async fn filtering_one_address() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribePendingTransactions",
                "params": {
                    "sender_address": ["0x1"]
                }
            })
            .to_string(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"]["subscription_id"].as_u64().unwrap()
            }
            _ => {
                panic!("Expected text message");
            }
        };
        assert!(rx.is_empty());
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS,
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x1")),
                    (contract_address!("0x2"), transaction_hash!("0x2")),
                ],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x1", subscription_id)
        );
        assert!(rx.is_empty());
    }

    #[tokio::test]
    async fn filtering_two_addresses() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribePendingTransactions",
                "params": {
                    "sender_address": ["0x1", "0x2"]
                }
            })
            .to_string(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"]["subscription_id"].as_u64().unwrap()
            }
            _ => {
                panic!("Expected text message");
            }
        };
        assert!(rx.is_empty());
        pending_data_tx
            .send(sample_block(
                BlockNumber::GENESIS,
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                    (contract_address!("0x3"), transaction_hash!("0x5")),
                ],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_message_no_details("0x4", subscription_id)
        );
        assert!(rx.is_empty());
    }

    async fn recv(rx: &mut mpsc::Receiver<Result<Message, RpcResponse>>) -> serde_json::Value {
        let res = rx.recv().await.unwrap().unwrap();
        match res {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        }
    }

    fn sample_block(
        block_number: BlockNumber,
        txs: Vec<(ContractAddress, TransactionHash)>,
    ) -> PendingData {
        PendingData {
            block: PendingBlock {
                transactions: txs
                    .into_iter()
                    .map(|(sender_address, hash)| Transaction {
                        variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                            sender_address,
                            ..Default::default()
                        }),
                        hash,
                    })
                    .collect(),
                ..Default::default()
            }
            .into(),
            number: block_number,
            ..Default::default()
        }
    }

    fn sample_message_no_details(hash: &str, subscription_id: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionPendingTransactions",
            "params": {
                "result": hash,
                "subscription_id": subscription_id
            }
        })
    }

    fn sample_message_with_details(
        sender_address: &str,
        hash: &str,
        subscription_id: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionPendingTransactions",
            "params": {
                "result": {
                    "class_hash": "0x0",
                    "max_fee": "0x0",
                    "sender_address": sender_address,
                    "signature": [],
                    "transaction_hash": hash,
                    "type": "DECLARE",
                    "version": "0x0"
                },
                "subscription_id": subscription_id
            }
        })
    }

    fn setup() -> Setup {
        let storage = StorageBuilder::in_memory().unwrap();
        let (pending_data_tx, pending_data) = tokio::sync::watch::channel(Default::default());
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
            sequencer: Client::mainnet(Duration::from_secs(10)),
            websocket: None,
            notifications,
            config: RpcConfig {
                batch_concurrency_limit: 1.try_into().unwrap(),
                get_events_max_blocks_to_scan: 1.try_into().unwrap(),
                get_events_max_uncached_bloom_filters_to_load: 1.try_into().unwrap(),
                custom_versioned_constants: None,
            },
        };
        let router = v08::register_routes().build(ctx);
        let (sender_tx, sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        Setup {
            tx: receiver_tx,
            rx: sender_rx,
            pending_data_tx,
        }
    }

    struct Setup {
        tx: mpsc::Sender<Result<Message, axum::Error>>,
        rx: mpsc::Receiver<Result<Message, RpcResponse>>,
        pending_data_tx: watch::Sender<PendingData>,
    }
}
