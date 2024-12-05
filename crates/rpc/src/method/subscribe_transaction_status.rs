use std::sync::Arc;
use std::time::Duration;

use axum::async_trait;
use pathfinder_common::receipt::ExecutionStatus;
use pathfinder_common::{BlockId, BlockNumber, TransactionHash};
use reply::transaction_status as status;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply;
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;

use super::REORG_SUBSCRIPTION_NAME;
use crate::context::RpcContext;
use crate::error::ApplicationError;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::Reorg;

pub struct SubscribeTransactionStatus;

#[derive(Debug, Clone, Default)]
pub struct Params {
    transaction_hash: TransactionHash,
    block_id: Option<BlockId>,
}

impl crate::dto::DeserializeForVersion for Params {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value.deserialize("transaction_hash").map(TransactionHash)?,
                block_id: value.deserialize_optional_serde("block_id")?,
            })
        })
    }
}

#[derive(Debug)]
pub enum Notification {
    TransactionStatus(TransactionHash, FinalityStatus, Option<ExecutionStatus>),
    Reorg(Arc<Reorg>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityStatus {
    Received,
    AcceptedOnL2,
    AcceptedOnL1,
    Rejected { reason: Option<String> },
}

impl crate::dto::serialize::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        return match self {
            Notification::TransactionStatus(tx_hash, finality_status, execution_status) => {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("transaction_hash", &tx_hash)?;
                serializer.serialize_field(
                    "status",
                    &TransactionStatus {
                        finality_status,
                        execution_status,
                    },
                )?;
                serializer.end()
            }
            Notification::Reorg(reorg) => reorg.serialize(serializer),
        };

        struct TransactionStatus<'a> {
            finality_status: &'a FinalityStatus,
            execution_status: &'a Option<ExecutionStatus>,
        }

        impl crate::dto::serialize::SerializeForVersion for TransactionStatus<'_> {
            fn serialize(
                &self,
                serializer: crate::dto::serialize::Serializer,
            ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field(
                    "finality_status",
                    &match self.finality_status {
                        FinalityStatus::Received => "RECEIVED",
                        FinalityStatus::AcceptedOnL2 => "ACCEPTED_ON_L2",
                        FinalityStatus::AcceptedOnL1 => "ACCEPTED_ON_L1",
                        FinalityStatus::Rejected { .. } => "REJECTED",
                    },
                )?;
                if let Some(execution_status) = self.execution_status {
                    serializer.serialize_field(
                        "execution_status",
                        &match execution_status {
                            ExecutionStatus::Succeeded => "SUCCEEDED",
                            ExecutionStatus::Reverted { .. } => "REVERTED",
                        },
                    )?;
                }
                match (self.finality_status, self.execution_status) {
                    (
                        FinalityStatus::Rejected {
                            reason: Some(reason),
                        },
                        _,
                    )
                    | (_, Some(ExecutionStatus::Reverted { reason })) => {
                        serializer.serialize_field("failure_reason", reason)?;
                    }
                    _ => {}
                }
                serializer.end()
            }
        }
    }
}

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionTransactionStatus";

#[async_trait]
impl RpcSubscriptionFlow for SubscribeTransactionStatus {
    type Params = Params;
    type Notification = Notification;

    #[allow(clippy::collapsible_if)]
    async fn subscribe(
        state: RpcContext,
        params: Self::Params,
        tx: mpsc::Sender<SubscriptionMessage<Self::Notification>>,
    ) -> Result<(), RpcError> {
        'reorg: loop {
            let tx_hash = params.transaction_hash;
            let mut sender = Sender {
                tx: &tx,
                tx_hash,
                last_finality_status: None,
                last_execution_status: None,
                last_block_number: BlockNumber::GENESIS, // Initial value not important.
            };
            let mut pending_data = state.pending_data.0.clone();
            let mut l2_blocks = state.notifications.l2_blocks.subscribe();
            let mut reorgs = state.notifications.reorgs.subscribe();
            let storage = state.storage.clone();
            if let Some(first_block) = params.block_id {
                // Check if we have the transaction in our database, and if so, send the
                // relevant transaction status updates.
                let (first_block, l1_state, tx_with_receipt) =
                    tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
                        let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                        let db = conn.transaction().map_err(RpcError::InternalError)?;
                        let first_block = db
                            .block_number(first_block.try_into().map_err(|_| {
                                RpcError::ApplicationError(ApplicationError::CallOnPending)
                            })?)
                            .map_err(RpcError::InternalError)?;
                        let l1_block_number =
                            db.latest_l1_state().map_err(RpcError::InternalError)?;
                        let tx_with_receipt = db
                            .transaction_with_receipt(tx_hash)
                            .map_err(RpcError::InternalError)?;
                        Ok((first_block, l1_block_number, tx_with_receipt))
                    })
                    .await
                    .map_err(|e| RpcError::InternalError(e.into()))??;
                let first_block = first_block
                    .ok_or_else(|| RpcError::ApplicationError(ApplicationError::BlockNotFound))?;
                if let Some((_, receipt, _, block_number)) = tx_with_receipt {
                    // We already have the transaction in the database.
                    if let Some(parent) = block_number.parent() {
                        // This transaction was pending in the parent block.
                        if first_block <= parent {
                            if sender
                                .send(parent, FinalityStatus::Received, None)
                                .await
                                .is_err()
                            {
                                // Subscription closing.
                                break;
                            }
                        }
                    }
                    if first_block <= block_number {
                        if sender
                            .send(
                                block_number,
                                FinalityStatus::AcceptedOnL2,
                                Some(receipt.execution_status.clone()),
                            )
                            .await
                            .is_err()
                        {
                            // Subscription closing.
                            break;
                        }
                    }
                    if let Some(l1_state) = l1_state {
                        if l1_state.block_number >= block_number {
                            if sender
                                .send(
                                    l1_state.block_number,
                                    FinalityStatus::AcceptedOnL1,
                                    Some(receipt.execution_status.clone()),
                                )
                                .await
                                .is_err()
                            {
                                // Subscription closing.
                                break;
                            }
                        }
                    }
                }
            }
            let pending = pending_data.borrow_and_update().clone();
            if pending
                .block
                .transactions
                .iter()
                .any(|tx| tx.hash == tx_hash)
            {
                if sender
                    .send(pending.number, FinalityStatus::Received, None)
                    .await
                    .is_err()
                {
                    // Subscription closing.
                    break;
                }
            }
            // Stream transaction status updates.
            let mut interval = tokio::time::interval(if cfg!(test) {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(60)
            });
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match state.sequencer.transaction_status(params.transaction_hash).await {
                            Ok(status) => {
                                if matches!(status.execution_status, Some(status::ExecutionStatus::Rejected)) {
                                    // Transaction has been rejected.
                                    sender
                                        .send(BlockNumber::GENESIS, FinalityStatus::Rejected {
                                            reason: status.tx_failure_reason.map(|reason| reason.error_message)
                                        }, None)
                                        .await
                                        .ok();
                                    // No more updates needed. Even in case of reorg, the transaction will
                                    // always be rejected.
                                    break 'reorg;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to get transaction status for subscription: {:?}",
                                    e
                                );
                            }
                        }
                    }
                    reorg = reorgs.recv() => {
                        match reorg {
                            Ok(reorg) => {
                                let block_number = sender.last_block_number;
                                if tx.send(SubscriptionMessage {
                                    notification: Notification::Reorg(reorg),
                                    block_number,
                                    subscription_name: REORG_SUBSCRIPTION_NAME,
                                }).await.is_err() {
                                    // Subscription closing.
                                    break;
                                }
                                continue 'reorg;
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::debug!("Reorg channel closed, stopping subscription");
                                break 'reorg;
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                tracing::warn!("Reorg channel lagged");
                            }
                        }
                    }
                    r = pending_data.changed() => {
                        if r.is_err() {
                            tracing::debug!("Pending data channel closed, stopping subscription");
                            break 'reorg;
                        }
                        let pending = pending_data.borrow_and_update().clone();
                        if pending
                            .block
                            .transactions
                            .iter()
                            .any(|tx| tx.hash == tx_hash)
                        {
                            if sender
                                .send(pending.number, FinalityStatus::Received, None)
                                .await
                                .is_err()
                            {
                                // Subscription closing.
                                break;
                            }
                        }
                    }
                    l2_block = l2_blocks.recv() => {
                        match l2_block {
                            Ok(l2_block) => {
                                let receipt = l2_block.transaction_receipts.iter().find(|(receipt, _)| {
                                    receipt.transaction_hash == tx_hash
                                });
                                if let Some((receipt, _)) = receipt {
                                    // Send both received and accepted updates.
                                    if sender
                                        .send(l2_block.block_number, FinalityStatus::Received, None)
                                        .await
                                        .is_err()
                                    {
                                        // Subscription closing.
                                        break;
                                    }
                                    if sender
                                        .send(
                                            l2_block.block_number,
                                            FinalityStatus::AcceptedOnL2,
                                            Some(receipt.execution_status.clone())
                                        )
                                        .await
                                        .is_err()
                                    {
                                        // Subscription closing.
                                        break;
                                    }
                                }
                                // Check if our transaction has been confirmed on L1. This is done
                                // here because it guarantees that the ACCEPTED_ON_L2 update will be
                                // sent before the ACCEPTED_ON_L1 update.
                                let storage = state.storage.clone();
                                let l1_state = tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
                                    let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                                    let db = conn.transaction().map_err(RpcError::InternalError)?;
                                    let l1_state = db.latest_l1_state().map_err(RpcError::InternalError)?;
                                    Ok(l1_state)
                                }).await.map_err(|e| RpcError::InternalError(e.into()))??;
                                if let Some(l1_state) = l1_state {
                                    if l1_state.block_number >= sender.last_block_number && sender.last_execution_status.is_some() {
                                        if sender
                                            .send(
                                                l1_state.block_number,
                                                FinalityStatus::AcceptedOnL1,
                                                sender.last_execution_status.clone(),
                                            )
                                            .await
                                            .is_err()
                                        {
                                            // Subscription closing.
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::debug!("L2 block channel closed, stopping subscription");
                                break 'reorg;
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                tracing::warn!("L2 block channel lagged");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

struct Sender<'a> {
    tx: &'a mpsc::Sender<SubscriptionMessage<Notification>>,
    tx_hash: TransactionHash,
    last_finality_status: Option<FinalityStatus>,
    last_execution_status: Option<ExecutionStatus>,
    last_block_number: BlockNumber,
}

impl Sender<'_> {
    async fn send(
        &mut self,
        block_number: BlockNumber,
        finality_status: FinalityStatus,
        execution_status: Option<ExecutionStatus>,
    ) -> Result<(), mpsc::error::SendError<()>> {
        if let Some(last_finality_status) = &self.last_finality_status {
            if finality_status.as_num() <= last_finality_status.as_num() {
                // Transaction status has not progressed.
                return Ok(());
            }
        }
        self.last_finality_status = Some(finality_status.clone());
        self.last_execution_status = execution_status.clone();
        self.last_block_number = block_number;
        self.tx
            .send(SubscriptionMessage {
                notification: Notification::TransactionStatus(
                    self.tx_hash,
                    finality_status,
                    execution_status,
                ),
                block_number,
                subscription_name: SUBSCRIPTION_NAME,
            })
            .await
            .map_err(|_| mpsc::error::SendError(()))?;
        Ok(())
    }
}

impl FinalityStatus {
    pub fn as_num(&self) -> u8 {
        match self {
            FinalityStatus::Received => 0,
            FinalityStatus::AcceptedOnL2 => 1,
            FinalityStatus::AcceptedOnL1 => 2,
            FinalityStatus::Rejected { .. } => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;
    use pathfinder_common::receipt::{ExecutionStatus, Receipt};
    use pathfinder_common::transaction::Transaction;
    use pathfinder_common::{
        BlockHash,
        BlockHeader,
        BlockNumber,
        ChainId,
        TransactionHash,
        TransactionIndex,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_ethereum::{EthereumClient, EthereumStateUpdate};
    use pathfinder_storage::StorageBuilder;
    use pretty_assertions_sorted::assert_eq;
    use primitive_types::H160;
    use starknet_gateway_client::Client;
    use starknet_gateway_types::reply::{Block, PendingBlock};
    use tokio::sync::mpsc;

    use crate::context::{RpcConfig, RpcContext};
    use crate::jsonrpc::{handle_json_rpc_socket, RpcResponse, RpcRouter};
    use crate::pending::PendingWatcher;
    use crate::types::syncing::Syncing;
    use crate::{v08, Notifications, PendingData, Reorg, SubscriptionId, SyncState};

    #[tokio::test]
    async fn transaction_already_exists_in_db_accepted_on_l2_succeeded() {
        let (router, mut rx, pending_sender, subscription_id) =
            test_transaction_already_exists_in_db(
                ExecutionStatus::Succeeded,
                None,
                |subscription_id| {
                    vec![
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "starknet_subscriptionTransactionStatus",
                            "params": {
                                "result": {
                                    "transaction_hash": "0x1",
                                    "status": {
                                        "finality_status": "RECEIVED",
                                    }
                                },
                                "subscription_id": subscription_id
                            }
                        }),
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "starknet_subscriptionTransactionStatus",
                            "params": {
                                "result": {
                                    "transaction_hash": "0x1",
                                    "status": {
                                        "finality_status": "ACCEPTED_ON_L2",
                                        "execution_status": "SUCCEEDED",
                                    }
                                },
                                "subscription_id": subscription_id
                            }
                        }),
                    ]
                },
            )
            .await;

        // Test streaming updates after L2 update from DB.

        // Irrelevant pending update.
        pending_sender.send_modify(|pending| {
            pending.number = BlockNumber::GENESIS + 1;
        });

        // No message expected.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err());

        // Irrelevant L2 update.
        router
            .context
            .notifications
            .l2_blocks
            .send(
                Block {
                    block_number: BlockNumber::GENESIS + 1,
                    block_hash: BlockHash(Felt::from_u64(1)),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap();

        // No message expected.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err());

        // Update L1.
        tokio::task::spawn_blocking({
            let storage = router.context.storage.clone();
            move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                db.upsert_l1_state(&EthereumStateUpdate {
                    state_root: Default::default(),
                    block_number: BlockNumber::GENESIS + 2,
                    block_hash: Default::default(),
                })
                .unwrap();
                db.commit().unwrap();
            }
        })
        .await
        .unwrap();
        // Streaming update.
        router
            .context
            .notifications
            .l2_blocks
            .send(
                Block {
                    block_number: BlockNumber::GENESIS + 2,
                    block_hash: BlockHash(Felt::from_u64(2)),
                    ..Default::default()
                }
                .into(),
            )
            .unwrap();
        let status = rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match status {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(
            json,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "starknet_subscriptionTransactionStatus",
                "params": {
                    "result": {
                        "transaction_hash": "0x1",
                        "status": {
                            "finality_status": "ACCEPTED_ON_L1",
                            "execution_status": "SUCCEEDED",
                        }
                    },
                    "subscription_id": subscription_id,
                }
            })
        );

        // No more messages expected.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn transaction_already_exists_in_db_accepted_on_l2_reverted() {
        test_transaction_already_exists_in_db(
            ExecutionStatus::Reverted {
                reason: "tx revert".to_string(),
            },
            None,
            |subscription_id| {
                vec![
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "RECEIVED",
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "ACCEPTED_ON_L2",
                                    "execution_status": "REVERTED",
                                    "failure_reason": "tx revert"
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                ]
            },
        )
        .await;
    }

    #[tokio::test]
    async fn transaction_already_exists_in_db_accepted_on_l1_succeeded() {
        test_transaction_already_exists_in_db(
            ExecutionStatus::Succeeded,
            Some(EthereumStateUpdate {
                state_root: Default::default(),
                block_number: BlockNumber::GENESIS + 1,
                block_hash: Default::default(),
            }),
            |subscription_id| {
                vec![
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "RECEIVED",
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "ACCEPTED_ON_L2",
                                    "execution_status": "SUCCEEDED"
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "ACCEPTED_ON_L1",
                                    "execution_status": "SUCCEEDED"
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                ]
            },
        )
        .await;
    }

    #[tokio::test]
    async fn transaction_already_exists_in_db_accepted_on_l1_reverted() {
        test_transaction_already_exists_in_db(
            ExecutionStatus::Reverted {
                reason: "tx revert".to_string(),
            },
            Some(EthereumStateUpdate {
                state_root: Default::default(),
                block_number: BlockNumber::GENESIS + 1,
                block_hash: Default::default(),
            }),
            |subscription_id| {
                vec![
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "RECEIVED",
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "ACCEPTED_ON_L2",
                                    "execution_status": "REVERTED",
                                    "failure_reason": "tx revert"
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_subscriptionTransactionStatus",
                        "params": {
                            "result": {
                                "transaction_hash": "0x1",
                                "status": {
                                    "finality_status": "ACCEPTED_ON_L1",
                                    "execution_status": "REVERTED",
                                    "failure_reason": "tx revert"
                                }
                            },
                            "subscription_id": subscription_id
                        }
                    }),
                ]
            },
        )
        .await;
    }

    #[tokio::test]
    async fn transaction_status_streaming() {
        test_transaction_status_streaming(|subscription_id| {
            vec![
                TestEvent::Pending(PendingData {
                    block: PendingBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(2)),
                            variant: Default::default(),
                        }],
                        ..Default::default()
                    }
                    .into(),
                    state_update: Default::default(),
                    number: BlockNumber::GENESIS + 1,
                }),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 1,
                        block_hash: BlockHash(Felt::from_u64(1)),
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Pending(PendingData {
                    block: PendingBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(1)),
                            variant: Default::default(),
                        }],
                        ..Default::default()
                    }
                    .into(),
                    state_update: Default::default(),
                    number: BlockNumber::GENESIS + 2,
                }),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 2,
                        block_hash: BlockHash(Felt::from_u64(2)),
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TransactionHash(Felt::from_u64(1)),
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionTransactionStatus",
                    "params": {
                        "result": {
                            "transaction_hash": "0x1",
                            "status": {
                                "finality_status": "RECEIVED",
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionTransactionStatus",
                    "params": {
                        "result": {
                            "transaction_hash": "0x1",
                            "status": {
                                "finality_status": "ACCEPTED_ON_L2",
                                "execution_status": "SUCCEEDED"
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
                // Irrelevant block.
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 3,
                        block_hash: BlockHash(Felt::from_u64(3)),
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TransactionHash(Felt::from_u64(5)),
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::L1State(EthereumStateUpdate {
                    state_root: Default::default(),
                    block_number: BlockNumber::GENESIS + 3,
                    block_hash: Default::default(),
                }),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 4,
                        block_hash: BlockHash(Felt::from_u64(4)),
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TransactionHash(Felt::from_u64(5)),
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionTransactionStatus",
                    "params": {
                        "result": {
                            "transaction_hash": "0x1",
                            "status": {
                                "finality_status": "ACCEPTED_ON_L1",
                                "execution_status": "SUCCEEDED"
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
                TestEvent::Reorg(Reorg {
                    first_block_number: BlockNumber::GENESIS + 4,
                    first_block_hash: BlockHash(Felt::from_u64(4)),
                    last_block_number: BlockNumber::GENESIS + 5,
                    last_block_hash: BlockHash(Felt::from_u64(5)),
                }),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionReorg",
                    "params": {
                        "subscription_id": subscription_id,
                        "result": {
                            "first_block_number": 4,
                            "first_block_hash": "0x4",
                            "last_block_number": 5,
                            "last_block_hash": "0x5",
                        }
                    }
                })),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionTransactionStatus",
                    "params": {
                        "result": {
                            "transaction_hash": "0x1",
                            "status": {
                                "finality_status": "RECEIVED",
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
            ]
        })
        .await;
    }

    async fn test_transaction_status_streaming(
        events: impl FnOnce(serde_json::Value) -> Vec<TestEvent>,
    ) {
        let (router, pending_sender) = setup().await;
        tokio::task::spawn_blocking({
            let storage = router.context.storage.clone();
            move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                db.insert_block_header(&BlockHeader {
                    hash: BlockHash::ZERO,
                    number: BlockNumber::GENESIS,
                    parent_hash: BlockHash::ZERO,
                    ..Default::default()
                })
                .unwrap();
                db.commit().unwrap();
            }
        })
        .await
        .unwrap();
        let tx_hash = TransactionHash(Felt::from_u64(1));
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {"block_id": {"block_number": 0}, "transaction_hash": tx_hash}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeTransactionStatus",
                    "params": params
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let subscription_id = match res {
            Message::Text(json) => {
                let mut json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].take()
            }
            _ => panic!("Expected text message"),
        };
        for event in events(subscription_id) {
            match event {
                TestEvent::Pending(pending_data) => {
                    pending_sender.send_modify(|pending| {
                        *pending = pending_data;
                    });
                }
                TestEvent::L2Block(block) => {
                    tokio::task::spawn_blocking({
                        let storage = router.context.storage.clone();
                        let block = block.clone();
                        move || {
                            let mut conn = storage.connection().unwrap();
                            let db = conn.transaction().unwrap();
                            db.insert_block_header(&BlockHeader {
                                hash: block.block_hash,
                                number: block.block_number,
                                parent_hash: BlockHash(block.block_hash.0 - Felt::from_u64(1)),
                                ..Default::default()
                            })
                            .unwrap();
                            db.commit().unwrap();
                        }
                    })
                    .await
                    .unwrap();
                    router
                        .context
                        .notifications
                        .l2_blocks
                        .send(block.into())
                        .unwrap();
                }
                TestEvent::Reorg(reorg) => {
                    router
                        .context
                        .notifications
                        .reorgs
                        .send(reorg.into())
                        .unwrap();
                }
                TestEvent::L1State(l1_state) => {
                    tokio::task::spawn_blocking({
                        let storage = router.context.storage.clone();
                        move || {
                            let mut conn = storage.connection().unwrap();
                            let db = conn.transaction().unwrap();
                            db.upsert_l1_state(&l1_state).unwrap();
                            db.commit().unwrap();
                        }
                    })
                    .await
                    .unwrap();
                }
                TestEvent::Message(msg) => {
                    let status = sender_rx.recv().await.unwrap().unwrap();
                    let json: serde_json::Value = match status {
                        Message::Text(json) => serde_json::from_str(&json).unwrap(),
                        _ => panic!("Expected text message"),
                    };
                    assert_eq!(json, msg);
                }
            }
        }
        // No more messages expected.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(sender_rx.try_recv().is_err());
    }

    async fn test_transaction_already_exists_in_db(
        execution_status: ExecutionStatus,
        l1_state: Option<EthereumStateUpdate>,
        expected: impl FnOnce(SubscriptionId) -> Vec<serde_json::Value>,
    ) -> (
        RpcRouter,
        mpsc::Receiver<Result<Message, RpcResponse>>,
        tokio::sync::watch::Sender<PendingData>,
        SubscriptionId,
    ) {
        let (router, pending_sender) = setup().await;
        let tx_hash = TransactionHash(Felt::from_u64(1));
        let block_number = BlockNumber::new_or_panic(1);
        tokio::task::spawn_blocking({
            let storage = router.context.storage.clone();
            move || {
                let mut conn = storage.connection().unwrap();
                let db = conn.transaction().unwrap();
                db.insert_block_header(&BlockHeader {
                    hash: BlockHash::ZERO,
                    number: BlockNumber::GENESIS,
                    parent_hash: BlockHash::ZERO,
                    ..Default::default()
                })
                .unwrap();
                db.insert_block_header(&BlockHeader {
                    hash: BlockHash(Felt::from_u64(1)),
                    number: block_number,
                    parent_hash: BlockHash(Felt::from_u64(1)),
                    ..Default::default()
                })
                .unwrap();
                db.insert_transaction_data(
                    block_number,
                    &[(
                        Transaction {
                            hash: tx_hash,
                            variant: Default::default(),
                        },
                        Receipt {
                            transaction_hash: tx_hash,
                            transaction_index: TransactionIndex::new_or_panic(0),
                            execution_status,
                            ..Default::default()
                        },
                    )],
                    Some(&[vec![]]),
                )
                .unwrap();
                if let Some(l1_state) = l1_state {
                    db.upsert_l1_state(&l1_state).unwrap();
                }
                db.commit().unwrap();
            }
        })
        .await
        .unwrap();
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {"block_id": {"block_number": 0}, "transaction_hash": tx_hash}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeTransactionStatus",
                    "params": params
                })
                .to_string(),
            )))
            .await
            .unwrap();
        let res = sender_rx.recv().await.unwrap().unwrap();
        let subscription_id = match res {
            Message::Text(json) => {
                let mut json: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(json["jsonrpc"], "2.0");
                assert_eq!(json["id"], 1);
                json["result"].take()
            }
            _ => panic!("Expected text message"),
        };
        let subscription_id: SubscriptionId = serde_json::from_value(subscription_id).unwrap();
        for msg in expected(subscription_id) {
            let status = sender_rx.recv().await.unwrap().unwrap();
            let json: serde_json::Value = match status {
                Message::Text(json) => serde_json::from_str(&json).unwrap(),
                _ => panic!("Expected text message"),
            };
            assert_eq!(json, msg);
        }
        // No more messages expected.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(sender_rx.try_recv().is_err());
        (router, sender_rx, pending_sender, subscription_id)
    }

    #[derive(Debug)]
    enum TestEvent {
        Pending(PendingData),
        L2Block(Box<Block>),
        Reorg(Reorg),
        L1State(EthereumStateUpdate),
        Message(serde_json::Value),
    }

    async fn setup() -> (RpcRouter, tokio::sync::watch::Sender<PendingData>) {
        let storage = StorageBuilder::in_memory().unwrap();
        let (pending_data_sender, pending_data) = tokio::sync::watch::channel(Default::default());
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
        (v08::register_routes().build(ctx), pending_data_sender)
    }
}
