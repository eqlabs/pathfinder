use std::collections::HashSet;

use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockNumber, ContractAddress, TransactionHash};
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::RpcVersion;

pub struct SubscribePendingTransactions;

#[derive(Debug, Clone, Default)]
pub struct Params {
    transaction_details: Option<bool>,
    sender_address: Option<HashSet<ContractAddress>>,
}

impl crate::dto::DeserializeForVersion for Option<Params> {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        if value.is_null() {
            return Ok(None);
        }
        value.deserialize_map(|value| {
            Ok(Some(Params {
                transaction_details: value.deserialize_optional_serde("transaction_details")?,
                sender_address: value
                    .deserialize_optional_array("sender_address", |addr| {
                        Ok(ContractAddress(addr.deserialize()?))
                    })?
                    .map(|addrs| addrs.into_iter().collect()),
            }))
        })
    }
}

#[derive(Debug)]
pub enum Notification {
    Transaction(Box<Transaction>),
    TransactionHash(TransactionHash),
}

impl crate::dto::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            Notification::Transaction(transaction) => crate::dto::TransactionWithHash {
                transaction,
                include_proof_facts: false,
            }
            .serialize(serializer),
            Notification::TransactionHash(transaction_hash) => {
                transaction_hash.0.serialize(serializer)
            }
        }
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionPendingTransactions";

impl RpcSubscriptionFlow for SubscribePendingTransactions {
    type Params = Option<Params>;
    type Notification = Notification;

    async fn subscribe(
        state: RpcContext,
        _version: RpcVersion,
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError> {
        let params = params.unwrap_or_default();
        let mut pending_data = state.pending_data.0.clone();
        // Last block sent to the subscriber. Initial value doesn't really matter.
        let mut last_block = BlockNumber::GENESIS;
        // Hashes of transactions that have already been sent to the subscriber, as part
        // of `last_block` block. It is necessary to keep track of this because the
        // pending data updates might include new transactions for the same
        // block number.
        let mut sent_txs = HashSet::new();
        loop {
            let pending = pending_data.borrow_and_update().clone();
            // JSON-RPC 0.9.0 has removed `starknet_subscribePendingTransactions`, and
            // pre-0.9.0 APIs should not have access to pre-confirmed data. That
            // is, if the update is from a pre-confirmed block, we should just
            // ignore it. Note that this renders this method mostly useless,
            // since after the Starknet 0.14.0 update no transactions will be
            // sent over this subscription.
            if pending.is_pre_confirmed() {
                if pending_data.changed().await.is_err() {
                    tracing::debug!("Pending data channel closed, stopping subscription");
                    return Ok(());
                }
                continue;
            }

            if pending.pending_block_number() != last_block {
                last_block = pending.pending_block_number();
                sent_txs.clear();
            }
            for transaction in pending.pending_transactions().iter() {
                if sent_txs.contains(&transaction.hash) {
                    continue;
                }
                // Filter the transactions by sender address.
                if let Some(sender_address) = &params.sender_address {
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
                let notification = match params.transaction_details {
                    Some(true) => Notification::Transaction(transaction.clone().into()),
                    Some(false) | None => Notification::TransactionHash(transaction.hash),
                };
                sent_txs.insert(transaction.hash);
                if tx
                    .send(SubscriptionMessage {
                        notification,
                        block_number: pending.pending_block_number(),
                        subscription_name: SUBSCRIPTION_NAME,
                    })
                    .await
                    .is_err()
                {
                    // Subscription has been closed.
                    return Ok(());
                }
            }
            if pending_data.changed().await.is_err() {
                tracing::debug!("Pending data channel closed, stopping subscription");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::ws::Message;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::transaction::{DeclareTransactionV0V1, Transaction, TransactionVariant};
    use pathfinder_crypto::Felt;
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_types::reply::PendingBlock;
    use tokio::sync::{mpsc, watch};

    use crate::context::{RpcContext, WebsocketContext};
    use crate::jsonrpc::websocket::WebsocketHistory;
    use crate::jsonrpc::{handle_json_rpc_socket, RpcResponse};
    use crate::{v08, Notifications, PendingData};

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
            })
            .to_string()
            .into(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_str().unwrap().parse().unwrap()
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
            .to_string()
            .into(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_str().unwrap().parse().unwrap()
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
            .to_string()
            .into(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_str().unwrap().parse().unwrap()
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
            .to_string()
            .into(),
        )))
        .await
        .unwrap();
        let response = rx.recv().await.unwrap().unwrap();
        let subscription_id = match response {
            Message::Text(json) => {
                let json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].as_str().unwrap().parse().unwrap()
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
        PendingData::from_pending_block(
            PendingBlock {
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
            },
            StateUpdate::default(),
            block_number,
        )
    }

    fn sample_message_no_details(hash: &str, subscription_id: u64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionPendingTransactions",
            "params": {
                "result": hash,
                "subscription_id": subscription_id.to_string()
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
                "subscription_id": subscription_id.to_string()
            }
        })
    }

    fn sample_header(block_number: u64) -> BlockHeader {
        BlockHeader {
            hash: BlockHash(Felt::from_u64(block_number)),
            number: BlockNumber::new_or_panic(block_number),
            parent_hash: BlockHash::ZERO,
            ..Default::default()
        }
    }

    fn setup() -> Setup {
        let storage = StorageBuilder::in_memory().unwrap();
        {
            let mut conn = storage.connection().unwrap();
            let db = conn.transaction().unwrap();
            db.insert_block_header(&sample_header(0)).unwrap();
            db.commit().unwrap();
        }
        let (pending_data_tx, pending_data) = tokio::sync::watch::channel(Default::default());
        let notifications = Notifications::default();
        let ctx = RpcContext::for_tests()
            .with_storage(storage)
            .with_notifications(notifications)
            .with_pending_data(pending_data.clone())
            .with_websockets(WebsocketContext::new(WebsocketHistory::Unlimited));
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
