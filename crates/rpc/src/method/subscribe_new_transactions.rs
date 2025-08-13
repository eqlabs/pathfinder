use std::collections::HashSet;

use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockNumber, ContractAddress};
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::dto::{TransactionWithHash, TxnFinalityStatus};
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::RpcVersion;

pub struct SubscribeNewTransactions;

#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    finality_status: Vec<TxnFinalityStatus>,
    sender_address: Option<HashSet<ContractAddress>>,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            finality_status: vec![TxnFinalityStatus::AcceptedOnL2],
            sender_address: None,
        }
    }
}

impl Params {
    fn matches(&self, sender_address: &ContractAddress, finality: TxnFinalityStatus) -> bool {
        if let Some(addresses) = &self.sender_address {
            if !addresses.contains(sender_address) {
                return false;
            }
        }
        if !self.finality_status.contains(&finality) {
            return false;
        }
        true
    }
}

impl crate::dto::DeserializeForVersion for Option<Params> {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        if value.is_null() {
            return Ok(None);
        }
        value.deserialize_map(|value| {
            Ok(Some(Params {
                finality_status: value
                    .deserialize_optional_array("finality_status", |v| {
                        v.deserialize::<TxnFinalityStatusWithoutL1Accepted>()
                            .map(Into::into)
                    })?
                    .unwrap_or_else(|| vec![TxnFinalityStatus::AcceptedOnL2]),
                sender_address: value
                    .deserialize_optional_array("sender_address", |addr| {
                        Ok(ContractAddress(addr.deserialize()?))
                    })?
                    .map(|addrs| addrs.into_iter().collect()),
            }))
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TxnFinalityStatusWithoutL1Accepted {
    Candidate,
    PreConfirmed,
    AcceptedOnL2,
}

impl crate::dto::DeserializeForVersion for TxnFinalityStatusWithoutL1Accepted {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let s: String = value.deserialize()?;
        match s.as_str() {
            "CANDIDATE" => Ok(Self::Candidate),
            "ACCEPTED_ON_L2" => Ok(Self::AcceptedOnL2),
            "PRE_CONFIRMED" => Ok(Self::PreConfirmed),
            _ => Err(serde::de::Error::unknown_variant(
                &s,
                &["ACCEPTED_ON_L2", "PRE_CONFIRMED", "CANDIDATE"],
            )),
        }
    }
}

impl From<TxnFinalityStatusWithoutL1Accepted> for TxnFinalityStatus {
    fn from(status: TxnFinalityStatusWithoutL1Accepted) -> Self {
        match status {
            TxnFinalityStatusWithoutL1Accepted::Candidate => TxnFinalityStatus::Candidate,
            TxnFinalityStatusWithoutL1Accepted::PreConfirmed => TxnFinalityStatus::PreConfirmed,
            TxnFinalityStatusWithoutL1Accepted::AcceptedOnL2 => TxnFinalityStatus::AcceptedOnL2,
        }
    }
}

#[derive(Debug)]
pub struct Notification {
    transaction: Transaction,
    finality: TxnFinalityStatus,
}

impl crate::dto::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.flatten(&TransactionWithHash(&self.transaction))?;
        serializer.serialize_field("finality_status", &self.finality)?;
        serializer.end()
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionNewTransaction";

impl RpcSubscriptionFlow for SubscribeNewTransactions {
    type Params = Option<Params>;
    type Notification = Notification;

    async fn subscribe(
        state: RpcContext,
        _version: RpcVersion,
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError> {
        let params = params.unwrap_or_default();
        let mut blocks = state.notifications.l2_blocks.subscribe();
        let mut pending_data = state.pending_data.0.clone();

        // Last block sent to the subscriber. Initial value doesn't really matter.
        let mut last_pre_confirmed_block = BlockNumber::GENESIS;

        // Set to keep track of sent transactions to avoid duplicates.
        let mut pre_confirmed_sent_txs = HashSet::new();

        loop {
            tokio::select! {
                block = blocks.recv() => {
                    match block {
                        Err(e) => {
                            tracing::debug!(error=%e, "Block channel closed, stopping subscription");
                            return Ok(());
                        }
                        Ok(block) => {
                            tracing::trace!(block_number=%block.block_number, "New block header");

                            if block.block_number == last_pre_confirmed_block {
                                // Send all transactions that might have been missed in the pre-confirmed block.
                                for transaction in block.transactions.iter() {
                                    if !params.matches(&transaction.variant.sender_address(), TxnFinalityStatus::AcceptedOnL2) {
                                        continue;
                                    }

                                    let notification = Notification {
                                        transaction: transaction.clone(),
                                        finality: TxnFinalityStatus::AcceptedOnL2,
                                    };
                                    if tx
                                        .send(SubscriptionMessage {
                                            notification,
                                            block_number: block.block_number,
                                            subscription_name: SUBSCRIPTION_NAME,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        // Close subscription.
                                        return Ok(());
                                    }
                                }

                                // Clear the sent transactions set.
                                pre_confirmed_sent_txs.clear();
                            }
                        }
                    }
                }
                pending_changed = pending_data.changed() => {
                    if let Err(e) = pending_changed {
                        tracing::debug!(error=%e, "Pending data channel closed, stopping subscription");
                        return Ok(());
                    }

                    let pending = pending_data.borrow_and_update().clone();
                    let finality_status = pending.block().finality_status();

                    tracing::trace!(block_number=%pending.block_number(), ?finality_status, "Pre-confirmed block update");

                    if pending.block_number() != last_pre_confirmed_block {
                        last_pre_confirmed_block = pending.block_number();
                        pre_confirmed_sent_txs.clear();
                    }

                    for (transaction, finality_status) in pending.transactions().iter().zip(std::iter::repeat(finality_status)).chain(
                        pending.candidate_transactions().into_iter().flatten().zip(std::iter::repeat(TxnFinalityStatus::Candidate))
                    ) {
                        if pre_confirmed_sent_txs.contains(&(transaction.hash, finality_status)) {
                            continue;
                        }

                        if !params.matches(&transaction.variant.sender_address(), finality_status) {
                            continue;
                        }

                        let notification = Notification {
                            transaction: transaction.clone(),
                            finality: finality_status,
                        };
                        pre_confirmed_sent_txs.insert((transaction.hash, finality_status));
                        if tx
                            .send(SubscriptionMessage {
                                notification,
                                block_number: pending.block_number(),
                                subscription_name: SUBSCRIPTION_NAME,
                            })
                            .await
                            .is_err()
                        {
                            // Close subscription.
                            return Ok(());
                        }
                    }
                }
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
    use starknet_gateway_types::reply::PreConfirmedBlock;
    use tokio::sync::{mpsc, watch};

    use super::Params;
    use crate::context::{RpcContext, WebsocketContext};
    use crate::dto::TxnFinalityStatus;
    use crate::jsonrpc::websocket::WebsocketHistory;
    use crate::jsonrpc::{handle_json_rpc_socket, RpcResponse};
    use crate::{v09, Notifications, PendingData, RpcVersion};

    #[test]
    fn parse_params() {
        let params = crate::dto::Value::new(
            serde_json::json!({
                "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED", "CANDIDATE"],
                "sender_address": ["0x1", "0x2"]
            }),
            RpcVersion::V09,
        );
        let params: Option<Params> = params.deserialize().unwrap();
        assert_eq!(
            params.unwrap(),
            Params {
                finality_status: vec![
                    TxnFinalityStatus::AcceptedOnL2,
                    TxnFinalityStatus::PreConfirmed,
                    TxnFinalityStatus::Candidate
                ],
                sender_address: Some(
                    [contract_address!("0x1"), contract_address!("0x2")]
                        .iter()
                        .cloned()
                        .collect()
                ),
            }
        );
    }

    #[test]
    fn parse_params_fails_for_invalid_finality_status() {
        let params = crate::dto::Value::new(
            serde_json::json!({
                "finality_status": ["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"],
                "sender_address": ["0x1", "0x2"]
            }),
            RpcVersion::V09,
        );
        let error = params.deserialize::<Option<Params>>().unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown variant `ACCEPTED_ON_L1`, expected one of `ACCEPTED_ON_L2`, `PRE_CONFIRMED`, \
             `CANDIDATE`"
                .to_string()
        );
    }

    #[test_log::test(tokio::test)]
    async fn pre_confirmed_no_filtering() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            ..
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED"]
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
        assert_recv_nothing(&mut rx).await;

        // First pre-confirmed block update.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // We expect that the second pre-confirmed block update will ignore
        // transactions that were already sent.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                    (contract_address!("0x1"), transaction_hash!("0x5")),
                    (contract_address!("0x2"), transaction_hash!("0x6")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x5", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x6", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;
    }

    #[test_log::test(tokio::test)]
    async fn pre_confirmed_with_candidate() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            ..
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED", "CANDIDATE"]
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
        assert_recv_nothing(&mut rx).await;

        // First pre-confirmed block update.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // We expect that the second pre-confirmed block update will ignore
        // transactions that were already sent. This includes a candidate transaction
        // that was not sent before.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                    (contract_address!("0x1"), transaction_hash!("0x5")),
                ],
                vec![(contract_address!("0x2"), transaction_hash!("0x6"))],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x5", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_candidate_transaction_message("0x2", "0x6", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // The next pre-confirmed block does have a receipt for the previously sent
        // candidate transaction. We expect the transaction to be re-sent with
        // PRE_CONFIRMED status.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                    (contract_address!("0x1"), transaction_hash!("0x5")),
                    (contract_address!("0x2"), transaction_hash!("0x6")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x6", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;
    }

    #[tokio::test]
    async fn pre_confirmed_filtering_one_address() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            ..
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "sender_address": ["0x1"],
                    "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED"]
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
        assert_recv_nothing(&mut rx).await;
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x1")),
                    (contract_address!("0x2"), transaction_hash!("0x2")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x1", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;
    }

    #[tokio::test]
    async fn pre_confirmed_filtering_two_addresses() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            ..
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "sender_address": ["0x1", "0x2"],
                    "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED"]
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
        assert_recv_nothing(&mut rx).await;
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                    (contract_address!("0x3"), transaction_hash!("0x5")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;
    }

    #[test_log::test(tokio::test)]
    async fn pre_confirmed_followed_by_block_with_extra_transactions() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            notifications,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "finality_status": ["ACCEPTED_ON_L2", "PRE_CONFIRMED"]
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
        assert_recv_nothing(&mut rx).await;

        // Send a pre-confirmed block with two transactions.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // The finalized block is sent after the pre-confirmed block, but contains more
        // transactions
        notifications
            .l2_blocks
            .send(
                sample_block(
                    BlockNumber::new_or_panic(1),
                    vec![
                        (contract_address!("0x1"), transaction_hash!("0x3")),
                        (contract_address!("0x2"), transaction_hash!("0x4")),
                        (contract_address!("0x1"), transaction_hash!("0x5")),
                        (contract_address!("0x2"), transaction_hash!("0x6")),
                    ],
                )
                .into(),
            )
            .unwrap();
        // We expect transactions 0x3 and 0x4 to be re-sent, since the finality status
        // has changed to ACCEPTED_ON_L2.
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x1", "0x5", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x2", "0x6", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // The next pre-confirmed block is sent.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(2),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x7")),
                    (contract_address!("0x2"), transaction_hash!("0x8")),
                ],
                vec![],
            ))
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x1", "0x7", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_pre_confirmed_transaction_message("0x2", "0x8", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;
    }

    #[test_log::test(tokio::test)]
    async fn pre_confirmed_followed_by_block_with_filter_on_finality_status() {
        let Setup {
            tx,
            mut rx,
            pending_data_tx,
            notifications,
        } = setup();
        tx.send(Ok(Message::Text(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "starknet_subscribeNewTransactions",
                "params": {
                    "finality_status": ["ACCEPTED_ON_L2"]
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
        assert_recv_nothing(&mut rx).await;

        notifications
            .l2_blocks
            .send(
                sample_block(
                    BlockNumber::new_or_panic(0),
                    vec![(contract_address!("0x1"), transaction_hash!("0x1"))],
                )
                .into(),
            )
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x1", "0x1", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // Send a pre-confirmed block with two transactions: since we're filtering on
        // finality status ACCEPTED_ON_L2, we expect that the pre-confirmed
        // block will not send any receipts.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(1),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x3")),
                    (contract_address!("0x2"), transaction_hash!("0x4")),
                ],
                vec![],
            ))
            .unwrap();
        assert_recv_nothing(&mut rx).await;

        // The finalized block is sent after the pre-confirmed block, but contains more
        // transactions.
        notifications
            .l2_blocks
            .send(
                sample_block(
                    BlockNumber::new_or_panic(1),
                    vec![
                        (contract_address!("0x1"), transaction_hash!("0x3")),
                        (contract_address!("0x2"), transaction_hash!("0x4")),
                        (contract_address!("0x1"), transaction_hash!("0x5")),
                        (contract_address!("0x2"), transaction_hash!("0x6")),
                    ],
                )
                .into(),
            )
            .unwrap();
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x1", "0x3", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x2", "0x4", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x1", "0x5", subscription_id)
        );
        assert_eq!(
            recv(&mut rx).await,
            sample_transaction_message("0x2", "0x6", subscription_id)
        );
        assert_recv_nothing(&mut rx).await;

        // The next pre-confirmed block is sent, we expect no receipts.
        pending_data_tx
            .send(sample_pre_confirmed_block(
                BlockNumber::new_or_panic(2),
                vec![
                    (contract_address!("0x1"), transaction_hash!("0x7")),
                    (contract_address!("0x2"), transaction_hash!("0x8")),
                ],
                vec![],
            ))
            .unwrap();
        assert_recv_nothing(&mut rx).await;
    }

    async fn recv(rx: &mut mpsc::Receiver<Result<Message, RpcResponse>>) -> serde_json::Value {
        let res = rx.recv().await.unwrap().unwrap();
        match res {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        }
    }

    /// Waits for the receiver to receive nothing within a short timeout.
    /// If it receives a message, it panics.
    async fn assert_recv_nothing(rx: &mut mpsc::Receiver<Result<Message, RpcResponse>>) {
        let timeout = std::time::Duration::from_millis(100);
        tokio::time::timeout(timeout, rx.recv())
            .await
            .expect_err("Message received when none was expected");
    }

    fn sample_pre_confirmed_block(
        block_number: BlockNumber,
        txs: Vec<(ContractAddress, TransactionHash)>,
        candidate_txs: Vec<(ContractAddress, TransactionHash)>,
    ) -> PendingData {
        let pre_confirmed_block = PreConfirmedBlock {
            status: starknet_gateway_types::reply::Status::PreConfirmed,
            transactions: txs
                .iter()
                .map(|(sender_address, hash)| Transaction {
                    variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                        sender_address: *sender_address,
                        ..Default::default()
                    }),
                    hash: *hash,
                })
                .chain(
                    candidate_txs
                        .iter()
                        .map(|(sender_address, hash)| Transaction {
                            variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                                sender_address: *sender_address,
                                ..Default::default()
                            }),
                            hash: *hash,
                        }),
                )
                .collect(),
            transaction_receipts: txs
                .iter()
                .map(|(_sender_address, hash)| {
                    Some((
                        pathfinder_common::receipt::Receipt {
                            transaction_hash: *hash,
                            ..Default::default()
                        },
                        vec![],
                    ))
                })
                .chain(candidate_txs.iter().map(|_| None))
                .collect(),
            transaction_state_diffs: vec![],
            ..Default::default()
        };
        PendingData::from_pre_confirmed_block(pre_confirmed_block, block_number)
    }

    fn sample_pre_confirmed_transaction_message(
        sender_address: &str,
        hash: &str,
        subscription_id: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionNewTransaction",
            "params": {
                "result": {
                    "class_hash": "0x0",
                    "max_fee": "0x0",
                    "sender_address": sender_address,
                    "signature": [],
                    "transaction_hash": hash,
                    "type": "DECLARE",
                    "version": "0x0",
                    "finality_status": "PRE_CONFIRMED",
                },
                "subscription_id": subscription_id.to_string()
            }
        })
    }

    fn sample_candidate_transaction_message(
        sender_address: &str,
        hash: &str,
        subscription_id: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionNewTransaction",
            "params": {
                "result": {
                    "class_hash": "0x0",
                    "max_fee": "0x0",
                    "sender_address": sender_address,
                    "signature": [],
                    "transaction_hash": hash,
                    "type": "DECLARE",
                    "version": "0x0",
                    "finality_status": "CANDIDATE",
                },
                "subscription_id": subscription_id.to_string()
            }
        })
    }

    fn sample_transaction_message(
        sender_address: &str,
        hash: &str,
        subscription_id: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "method":"starknet_subscriptionNewTransaction",
            "params": {
                "result": {
                    "class_hash": "0x0",
                    "max_fee": "0x0",
                    "sender_address": sender_address,
                    "signature": [],
                    "transaction_hash": hash,
                    "type": "DECLARE",
                    "version": "0x0",
                    "finality_status": "ACCEPTED_ON_L2",
                },
                "subscription_id": subscription_id.to_string()
            }
        })
    }

    fn sample_block(
        block_number: BlockNumber,
        txs: Vec<(ContractAddress, TransactionHash)>,
    ) -> starknet_gateway_types::reply::Block {
        starknet_gateway_types::reply::Block {
            block_hash: BlockHash(Felt::from_u64(block_number.get())),
            block_number,
            parent_block_hash: BlockHash::ZERO,
            transactions: txs
                .iter()
                .map(|(sender_address, hash)| Transaction {
                    variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                        sender_address: *sender_address,
                        ..Default::default()
                    }),
                    hash: *hash,
                })
                .collect(),
            transaction_receipts: txs
                .iter()
                .map(|(_sender_address, hash)| {
                    (
                        pathfinder_common::receipt::Receipt {
                            transaction_hash: *hash,
                            ..Default::default()
                        },
                        vec![],
                    )
                })
                .collect(),
            ..Default::default()
        }
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
            .with_notifications(notifications.clone())
            .with_pending_data(pending_data.clone())
            .with_websockets(WebsocketContext::new(WebsocketHistory::Unlimited));
        let router = v09::register_routes().build(ctx);
        let (sender_tx, sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        Setup {
            tx: receiver_tx,
            rx: sender_rx,
            pending_data_tx,
            notifications,
        }
    }

    struct Setup {
        tx: mpsc::Sender<Result<Message, axum::Error>>,
        rx: mpsc::Receiver<Result<Message, RpcResponse>>,
        pending_data_tx: watch::Sender<PendingData>,
        notifications: Notifications,
    }
}
