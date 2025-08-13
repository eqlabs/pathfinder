use std::sync::Arc;
use std::time::Duration;

use pathfinder_common::receipt::ExecutionStatus;
use pathfinder_common::{BlockNumber, TransactionHash};
use reply::transaction_status as status;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply;
use tokio::sync::watch::Receiver as WatchReceiver;
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;

use super::REORG_SUBSCRIPTION_NAME;
use crate::context::RpcContext;
use crate::jsonrpc::{RpcError, RpcSubscriptionFlow, SubscriptionMessage};
use crate::pending::PendingBlockVariant;
use crate::{tracker, PendingData, Reorg, RpcVersion};

pub struct SubscribeTransactionStatus;

#[derive(Debug, Clone, Default)]
pub struct Params {
    transaction_hash: TransactionHash,
}

impl crate::dto::DeserializeForVersion for Params {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value.deserialize("transaction_hash").map(TransactionHash)?,
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
    Candidate,
    PreConfirmed,
    AcceptedOnL2,
    AcceptedOnL1,
    Rejected { reason: Option<String> },
}

impl crate::dto::SerializeForVersion for Notification {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
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

        impl crate::dto::SerializeForVersion for TransactionStatus<'_> {
            fn serialize(
                &self,
                serializer: crate::dto::Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field(
                    "finality_status",
                    &match self.finality_status {
                        FinalityStatus::Received => "RECEIVED",
                        FinalityStatus::Candidate => "CANDIDATE",
                        FinalityStatus::PreConfirmed => "PRE_CONFIRMED",
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

impl RpcSubscriptionFlow for SubscribeTransactionStatus {
    type Params = Params;
    type Notification = Notification;

    #[allow(clippy::collapsible_if)]
    async fn subscribe(
        state: RpcContext,
        _version: RpcVersion,
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
            let storage = state.storage.clone();

            if let Some((block_number, finality_status, execution_status)) =
                current_known_tx_status(
                    storage,
                    &mut pending_data,
                    &state.submission_tracker,
                    tx_hash,
                )
                .await?
            {
                if sender
                    .send_and_update(block_number, finality_status, execution_status)
                    .await
                    .is_err()
                {
                    // Subscription closing.
                    break;
                }
            }

            let mut l2_blocks = state.notifications.l2_blocks.subscribe();
            let mut reorgs = state.notifications.reorgs.subscribe();

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
                                        .send_and_update(BlockNumber::GENESIS, FinalityStatus::Rejected {
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
                        if let Some((block, finality_status, execution_status)) =
                            pending_data_tx_status(&pending, tx_hash)
                        {
                            if sender
                                .send_and_update(
                                    block,
                                    finality_status,
                                    execution_status
                                )
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
                                // Perform a series of checks in the order that they are supposed
                                // to be transmitted. Perform it all in one place so that it is
                                // ensured that the user will always get them in the correct
                                // order.

                                // 1. Submitted transactions.
                                if let Some(block) = state.submission_tracker.get(&tx_hash) {
                                    if sender
                                        .send_and_update(
                                            block,
                                            FinalityStatus::Received,
                                            None
                                        )
                                        .await
                                        .is_err()
                                    {
                                        // Subscription closing.
                                        break;
                                    }
                                }

                                // 2. Transactions accepted on L2.
                                if let Some(receipt) = find_tx_receipt(&l2_block.transaction_receipts, tx_hash) {
                                    if sender
                                        .send_and_update(
                                            l2_block.block_number,
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

                                // 3. Transactions accepted on L1.
                                let storage = state.storage.clone();
                                let l1_state = util::task::spawn_blocking(move |_| -> Result<_, RpcError> {
                                    let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                                    let db = conn.transaction().map_err(RpcError::InternalError)?;
                                    let l1_state = db.latest_l1_state().map_err(RpcError::InternalError)?;
                                    Ok(l1_state)
                                }).await.map_err(|e| RpcError::InternalError(e.into()))??;
                                if let Some(l1_state) = l1_state {
                                    if l1_state.block_number >= sender.last_block_number && sender.last_execution_status.is_some() {
                                        if sender
                                            .send_and_update(
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

/// Check if the transaction is either in the database, pending data or
/// in the [submitted transactions](tracker::SubmittedTransactionTracker) and
/// provide the corresponding status.
async fn current_known_tx_status(
    storage: pathfinder_storage::Storage,
    pending_data: &mut WatchReceiver<PendingData>,
    submission_tracker: &tracker::SubmittedTransactionTracker,
    tx_hash: TransactionHash,
) -> Result<Option<(BlockNumber, FinalityStatus, Option<ExecutionStatus>)>, RpcError> {
    // Check the DB first since, in case the transaction can be found both in the
    // pending data and DB, the DB would contain "fresher" transaction status
    // information.
    let (l1_state, tx_with_receipt) = util::task::spawn_blocking(move |_| -> Result<_, RpcError> {
        let mut conn = storage.connection().map_err(RpcError::InternalError)?;
        let db = conn.transaction().map_err(RpcError::InternalError)?;
        let l1_block_number = db.latest_l1_state().map_err(RpcError::InternalError)?;
        let tx_with_receipt = db
            .transaction_with_receipt(tx_hash)
            .map_err(RpcError::InternalError)?;
        Ok((l1_block_number, tx_with_receipt))
    })
    .await
    .map_err(|e| RpcError::InternalError(e.into()))??;

    if let Some((_, receipt, _, block_number)) = tx_with_receipt {
        // We already have the transaction in the database.
        let execution_status = receipt.execution_status.clone();

        let (block_number, finality_status, execution_status) = match l1_state {
            Some(l1_state) if l1_state.block_number >= block_number => (
                // NOTE: This is not necessarily the block in which the transaction was accepted on
                // L1, but the block at which we are certain that the L1 state contains the
                // transaction.
                //
                // I don't think there is a way for us to provide the information on the former.
                l1_state.block_number,
                FinalityStatus::AcceptedOnL1,
                execution_status,
            ),
            _ => (block_number, FinalityStatus::AcceptedOnL2, execution_status),
        };

        return Ok(Some((
            block_number,
            finality_status,
            Some(execution_status),
        )));
    }

    let pending = pending_data.borrow_and_update().clone();
    let status = pending_data_tx_status(&pending, tx_hash).or_else(|| {
        submission_tracker
            .get(&tx_hash)
            .map(|block| (block, FinalityStatus::Received, None))
    });

    Ok(status)
}

fn pending_data_tx_status(
    pending_data: &PendingData,
    tx_hash: TransactionHash,
) -> Option<(BlockNumber, FinalityStatus, Option<ExecutionStatus>)> {
    let block_number = pending_data.block_number();
    match pending_data.block().as_ref() {
        PendingBlockVariant::Pending(block) => {
            find_tx_receipt(&block.transaction_receipts, tx_hash).map(|receipt| {
                (
                    block_number,
                    FinalityStatus::AcceptedOnL2,
                    Some(receipt.execution_status.clone()),
                )
            })
        }
        PendingBlockVariant::PreConfirmed {
            block,
            candidate_transactions,
        } => {
            let is_candidate = candidate_transactions.iter().any(|tx| tx.hash == tx_hash);
            if is_candidate {
                return Some((block_number, FinalityStatus::Candidate, None));
            }

            let is_pre_confirmed = block.transactions.iter().any(|tx| tx.hash == tx_hash);
            if is_pre_confirmed {
                let execution_status = find_tx_receipt(&block.transaction_receipts, tx_hash)
                    .expect("Pre-confirmed transaction should have a receipt")
                    .execution_status
                    .clone();
                return Some((
                    block_number,
                    FinalityStatus::PreConfirmed,
                    Some(execution_status),
                ));
            }

            None
        }
    }
}

fn find_tx_receipt(
    receipts: &[(
        pathfinder_common::receipt::Receipt,
        Vec<pathfinder_common::event::Event>,
    )],
    tx_hash: TransactionHash,
) -> Option<&pathfinder_common::receipt::Receipt> {
    receipts
        .iter()
        .find(|(receipt, _)| receipt.transaction_hash == tx_hash)
        .map(|(receipt, _)| receipt)
}

struct Sender<'a> {
    tx: &'a mpsc::Sender<SubscriptionMessage<Notification>>,
    tx_hash: TransactionHash,
    last_finality_status: Option<FinalityStatus>,
    last_execution_status: Option<ExecutionStatus>,
    last_block_number: BlockNumber,
}

impl Sender<'_> {
    async fn send_and_update(
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
            FinalityStatus::Candidate => 1,
            FinalityStatus::PreConfirmed => 2,
            FinalityStatus::AcceptedOnL2 => 3,
            FinalityStatus::AcceptedOnL1 => 4,
            FinalityStatus::Rejected { .. } => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::extract::ws::Message;
    use pathfinder_common::prelude::*;
    use pathfinder_common::receipt::{ExecutionStatus, Receipt};
    use pathfinder_common::transaction::Transaction;
    use pathfinder_crypto::Felt;
    use pathfinder_ethereum::EthereumStateUpdate;
    use pathfinder_storage::StorageBuilder;
    use pretty_assertions_sorted::assert_eq;
    use starknet_gateway_types::reply::{Block, PendingBlock, PreConfirmedBlock};
    use tokio::sync::mpsc;

    use crate::context::{RpcContext, WebsocketContext};
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::jsonrpc::websocket::WebsocketHistory;
    use crate::jsonrpc::{handle_json_rpc_socket, RpcResponse, RpcRouter};
    use crate::{v08, PendingData, Reorg, RpcVersion, SubscriptionId};

    const TARGET_TX_HASH: TransactionHash = TransactionHash(Felt::from_u64(1));

    #[tokio::test]
    async fn transaction_already_exists_in_db_accepted_on_l2_succeeded() {
        let (router, mut rx, pending_sender, subscription_id) =
            test_transaction_already_exists_in_db(
                ExecutionStatus::Succeeded,
                None,
                |subscription_id| {
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
                            "subscription_id": subscription_id.serialize(Serializer::new(RpcVersion::V08)).unwrap(),
                        }
                    })
                },
            )
            .await;

        // Test streaming updates after L2 update from DB.

        // Irrelevant pending update.
        pending_sender.send_modify(|pending| {
            *pending.block_number_mut() = BlockNumber::GENESIS + 1;
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
                    "subscription_id": subscription_id.serialize(Serializer::new(RpcVersion::V08)).unwrap(),
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
                        "subscription_id": subscription_id.serialize(Serializer::new(RpcVersion::V08)).unwrap(),
                    }
                })
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
                        "subscription_id": subscription_id.serialize(Serializer::new(RpcVersion::V08)).unwrap(),
                    }
                })
            }
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
                        "subscription_id": subscription_id.serialize(Serializer::new(RpcVersion::V08)).unwrap(),
                    }
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn transaction_status_streaming() {
        test_transaction_status_streaming(|subscription_id| {
            vec![
                TestEvent::Pending(PendingData::from_pending_block(
                    PendingBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(2)),
                            variant: Default::default(),
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TransactionHash(Felt::from_u64(2)),
                                execution_status: ExecutionStatus::Succeeded,
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    },
                    StateUpdate::default(),
                    BlockNumber::GENESIS + 1,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 1,
                        block_hash: BlockHash(Felt::from_u64(1)),
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Pending(PendingData::from_pending_block(
                    PendingBlock {
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            variant: Default::default(),
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
                                execution_status: ExecutionStatus::Succeeded,
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    },
                    StateUpdate::default(),
                    BlockNumber::GENESIS + 2,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 2,
                        block_hash: BlockHash(Felt::from_u64(2)),
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            ..Default::default()
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
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
                                "finality_status": "ACCEPTED_ON_L2",
                                "execution_status": "SUCCEEDED",
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
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(5)),
                            ..Default::default()
                        }],
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
                    starting_block_number: BlockNumber::GENESIS + 4,
                    starting_block_hash: BlockHash(Felt::from_u64(4)),
                    ending_block_number: BlockNumber::GENESIS + 5,
                    ending_block_hash: BlockHash(Felt::from_u64(5)),
                }),
                TestEvent::Message(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "starknet_subscriptionReorg",
                    "params": {
                        "subscription_id": subscription_id,
                        "result": {
                            "starting_block_number": 4,
                            "starting_block_hash": "0x4",
                            "ending_block_number": 5,
                            "ending_block_hash": "0x5",
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
                                "finality_status": "ACCEPTED_ON_L1",
                                "execution_status": "SUCCEEDED"
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
            ]
        })
        .await;
    }

    #[tokio::test]
    async fn transaction_found_in_pending_block() {
        test_transaction_status_streaming(|subscription_id| {
            vec![
                TestEvent::Pending(PendingData::from_pending_block(
                    PendingBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(2)),
                            variant: Default::default(),
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TransactionHash(Felt::from_u64(2)),
                                execution_status: ExecutionStatus::Succeeded,
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    },
                    StateUpdate::default(),
                    BlockNumber::GENESIS + 1,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 1,
                        block_hash: BlockHash(Felt::from_u64(1)),
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Pending(PendingData::from_pending_block(
                    PendingBlock {
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            variant: Default::default(),
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
                                execution_status: ExecutionStatus::Succeeded,
                                ..Default::default()
                            },
                            vec![],
                        )],
                        ..Default::default()
                    },
                    StateUpdate::default(),
                    BlockNumber::GENESIS + 2,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 2,
                        block_hash: BlockHash(Felt::from_u64(2)),
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            ..Default::default()
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
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
                                "finality_status": "ACCEPTED_ON_L2",
                                "execution_status": "SUCCEEDED",
                            }
                        },
                        "subscription_id": subscription_id
                    }
                })),
            ]
        })
        .await;
    }

    #[tokio::test]
    async fn transaction_found_in_pre_confirmed_block() {
        test_transaction_status_streaming(|subscription_id| {
            vec![
                TestEvent::Pending(PendingData::from_pre_confirmed_block(
                    PreConfirmedBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(2)),
                            variant: Default::default(),
                        }],
                        ..Default::default()
                    },
                    BlockNumber::GENESIS + 1,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 1,
                        block_hash: BlockHash(Felt::from_u64(1)),
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Pending(PendingData::from_pre_confirmed_block(
                    PreConfirmedBlock {
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            variant: Default::default(),
                        }],
                        // The fact that the receipt is present for this transaction means that it
                        // belongs to the pre-confirmed block.
                        transaction_receipts: vec![Some((
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
                                ..Default::default()
                            },
                            vec![],
                        ))],
                        ..Default::default()
                    },
                    BlockNumber::GENESIS + 2,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 2,
                        block_hash: BlockHash(Felt::from_u64(2)),
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            ..Default::default()
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
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
                                "finality_status": "PRE_CONFIRMED",
                                "execution_status": "SUCCEEDED"
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
            ]
        })
        .await;
    }

    #[tokio::test]
    async fn transaction_found_in_candidate_transactions() {
        test_transaction_status_streaming(|subscription_id| {
            vec![
                TestEvent::Pending(PendingData::from_pre_confirmed_block(
                    PreConfirmedBlock {
                        transactions: vec![Transaction {
                            hash: TransactionHash(Felt::from_u64(2)),
                            variant: Default::default(),
                        }],
                        ..Default::default()
                    },
                    BlockNumber::GENESIS + 1,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 1,
                        block_hash: BlockHash(Felt::from_u64(1)),
                        ..Default::default()
                    }
                    .into(),
                ),
                TestEvent::Pending(PendingData::from_pre_confirmed_block(
                    PreConfirmedBlock {
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            variant: Default::default(),
                        }],
                        // The fact that the receipt is missing for this transaction means that it
                        // belongs to the candidate transactions.
                        transaction_receipts: vec![None],
                        ..Default::default()
                    },
                    BlockNumber::GENESIS + 2,
                )),
                TestEvent::L2Block(
                    Block {
                        block_number: BlockNumber::GENESIS + 2,
                        block_hash: BlockHash(Felt::from_u64(2)),
                        transactions: vec![Transaction {
                            hash: TARGET_TX_HASH,
                            ..Default::default()
                        }],
                        transaction_receipts: vec![(
                            Receipt {
                                transaction_hash: TARGET_TX_HASH,
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
                                "finality_status": "CANDIDATE",
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
            ]
        })
        .await;
    }

    #[tokio::test]
    async fn transaction_found_in_submission_tracker() {
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
        let tx_hash = TARGET_TX_HASH;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);

        // Begin the subscription.
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {"transaction_hash": tx_hash}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeTransactionStatus",
                    "params": params
                })
                .to_string()
                .into(),
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

        // Place something into the submission tracker.
        router.context.submission_tracker.insert(
            TARGET_TX_HASH,
            crate::method::get_latest_block_or_genesis(&router.context.storage).unwrap(),
        );

        // Verify the transaction status subscription.
        handle_test_events(
            |subscription_id| {
                vec![
                    TestEvent::Pending(PendingData::from_pending_block(
                        // Irrelevant pending update.
                        PendingBlock {
                            transactions: vec![Transaction {
                                hash: TransactionHash(Felt::from_u64(2)),
                                variant: Default::default(),
                            }],
                            transaction_receipts: vec![(
                                Receipt {
                                    transaction_hash: TransactionHash(Felt::from_u64(2)),
                                    ..Default::default()
                                },
                                vec![],
                            )],
                            ..Default::default()
                        },
                        StateUpdate::default(),
                        BlockNumber::GENESIS + 1,
                    )),
                    // Irrelevant block update.
                    TestEvent::L2Block(
                        Block {
                            block_number: BlockNumber::GENESIS + 1,
                            block_hash: BlockHash(Felt::from_u64(1)),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    TestEvent::L2Block(
                        Block {
                            block_number: BlockNumber::GENESIS + 2,
                            block_hash: BlockHash(Felt::from_u64(2)),
                            transactions: vec![Transaction {
                                hash: TARGET_TX_HASH,
                                ..Default::default()
                            }],
                            transaction_receipts: vec![(
                                Receipt {
                                    transaction_hash: TARGET_TX_HASH,
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
                ]
            },
            subscription_id,
            router,
            pending_sender,
            sender_rx,
        )
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
        let tx_hash = TARGET_TX_HASH;
        let (sender_tx, mut sender_rx) = mpsc::channel(1024);
        let (receiver_tx, receiver_rx) = mpsc::channel(1024);
        handle_json_rpc_socket(router.clone(), sender_tx, receiver_rx);
        let params = serde_json::json!(
            {"transaction_hash": tx_hash}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeTransactionStatus",
                    "params": params
                })
                .to_string()
                .into(),
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

        handle_test_events(events, subscription_id, router, pending_sender, sender_rx).await;
    }

    async fn handle_test_events(
        events: impl FnOnce(serde_json::Value) -> Vec<TestEvent>,
        subscription_id: serde_json::Value,
        router: RpcRouter,
        pending_sender: tokio::sync::watch::Sender<PendingData>,
        mut sender_rx: mpsc::Receiver<Result<Message, RpcResponse>>,
    ) {
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
                            let (transactions, events_per_tx): (Vec<_>, Vec<_>) = block
                                .transactions
                                .into_iter()
                                .zip(block.transaction_receipts)
                                .map(|(tx, (receipt, events))| ((tx, receipt), events))
                                .unzip();
                            db.insert_transaction_data(
                                block.block_number,
                                &transactions,
                                Some(&events_per_tx),
                            )
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
        expected: impl FnOnce(SubscriptionId) -> serde_json::Value,
    ) -> (
        RpcRouter,
        mpsc::Receiver<Result<Message, RpcResponse>>,
        tokio::sync::watch::Sender<PendingData>,
        SubscriptionId,
    ) {
        let (router, pending_sender) = setup().await;
        let tx_hash = TARGET_TX_HASH;
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
            {"transaction_hash": tx_hash}
        );
        receiver_tx
            .send(Ok(Message::Text(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "starknet_subscribeTransactionStatus",
                    "params": params
                })
                .to_string()
                .into(),
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

        let subscription_id = crate::dto::Value::new(subscription_id, RpcVersion::V08);
        let subscription_id: SubscriptionId = subscription_id.deserialize().unwrap();
        let expected_msg = expected(subscription_id);
        let status = sender_rx.recv().await.unwrap().unwrap();
        let json: serde_json::Value = match status {
            Message::Text(json) => serde_json::from_str(&json).unwrap(),
            _ => panic!("Expected text message"),
        };
        assert_eq!(json, expected_msg);

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
        let ctx = RpcContext::for_tests()
            .with_storage(storage)
            .with_pending_data(pending_data.clone())
            .with_websockets(WebsocketContext::new(WebsocketHistory::Unlimited));
        (v08::register_routes().build(ctx), pending_data_sender)
    }
}
