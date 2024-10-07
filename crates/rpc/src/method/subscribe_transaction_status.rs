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

pub struct SubscribeEvents;

#[derive(Debug, Clone, Default)]
pub struct Params {
    transaction_hash: TransactionHash,
    block: Option<BlockId>,
}

impl crate::dto::DeserializeForVersion for Params {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value.deserialize("transaction_hash").map(TransactionHash)?,
                block: value.deserialize_optional_serde("block")?,
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

const SUBSCRIPTION_NAME: &str = "starknet_subscriptionTransactionsStatus";

#[async_trait]
impl RpcSubscriptionFlow for SubscribeEvents {
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
            if let Some(first_block) = params.block {
                // Check if we have the transaction in our database, and if so, send the
                // relevant transaction status updates.
                let (first_block, l1_state, tx_with_receipt) =
                    tokio::task::spawn_blocking(move || -> Result<_, RpcError> {
                        let mut conn = storage.connection().map_err(RpcError::InternalError)?;
                        let db = conn.transaction().map_err(RpcError::InternalError)?;
                        let first_block = db
                            .block_number(first_block.try_into().map_err(|_| {
                                RpcError::InvalidParams("block cannot be pending".to_string())
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
                        match state.sequencer.transaction(params.transaction_hash).await {
                            Ok(status) => {
                                if status.execution_status == status::ExecutionStatus::Rejected {
                                    // Transaction has been rejected.
                                    sender
                                        .send(BlockNumber::GENESIS, FinalityStatus::Rejected {
                                            reason: status.transaction_failure_reason.map(|reason| reason.error_message)
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
                                    if l1_state.block_number >= l2_block.block_number {
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
