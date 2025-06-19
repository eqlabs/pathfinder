use anyhow::Context;
use pathfinder_common::TransactionHash;

use crate::context::RpcContext;
use crate::dto::TxnFinalityStatus;
use crate::pending::PendingBlockVariant;

#[derive(Debug, PartialEq, Eq)]
pub struct GetGatewayTransactionInput {
    transaction_hash: TransactionHash,
}

crate::error::generate_rpc_error_subset!(GetGatewayTransactionError:);

impl crate::dto::DeserializeForVersion for GetGatewayTransactionInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: TransactionHash(value.deserialize("transaction_hash")?),
            })
        })
    }
}

pub async fn get_transaction_status(
    context: RpcContext,
    input: GetGatewayTransactionInput,
) -> Result<TransactionStatus, GetGatewayTransactionError> {
    let span = tracing::Span::current();
    let db_status = util::task::spawn_blocking(move |_| {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let db_tx = db.transaction().context("Creating database transaction")?;

        // Check pending transactions first.
        let pending = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?;
        if let Some(status) = pending_status(pending.block().as_ref(), &input.transaction_hash) {
            return Ok(Some(status));
        }

        let Some((_, receipt, _, block_hash)) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Fetching receipt from database")?
        else {
            return anyhow::Ok(None);
        };

        if receipt.is_reverted() {
            return Ok(Some(TransactionStatus::Reverted));
        }

        let l1_accepted = db_tx
            .block_is_l1_accepted(block_hash.into())
            .context("Querying block's status")?;

        if l1_accepted {
            Ok(Some(TransactionStatus::AcceptedOnL1))
        } else {
            Ok(Some(TransactionStatus::AcceptedOnL2))
        }
    })
    .await
    .context("Joining database task")??;

    if let Some(db_status) = db_status {
        return Ok(db_status);
    }

    // Check gateway for rejected transactions.
    use starknet_gateway_client::GatewayApi;
    context
        .sequencer
        .transaction_status(input.transaction_hash)
        .await
        .context("Fetching transaction status from gateway")
        .map(|tx| tx.tx_status.into())
        .map_err(GetGatewayTransactionError::Internal)
}

fn pending_status(
    pending: &PendingBlockVariant,
    tx_hash: &TransactionHash,
) -> Option<TransactionStatus> {
    pending
        .transaction_receipts_and_events()
        .iter()
        .find_map(|(rx, _)| {
            if &rx.transaction_hash == tx_hash {
                if rx.is_reverted() {
                    Some(TransactionStatus::Reverted)
                } else {
                    Some(match pending.finality_status() {
                        TxnFinalityStatus::PreConfirmed => TransactionStatus::Preconfirmed,
                        TxnFinalityStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
                        TxnFinalityStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                    })
                }
            } else {
                None
            }
        })
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransactionStatus {
    NotReceived,
    Received,
    Pending,
    Rejected,
    AcceptedOnL1,
    AcceptedOnL2,
    Reverted,
    Aborted,
    Candidate,
    Preconfirmed,
}

impl crate::dto::SerializeForVersion for TransactionStatus {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            TransactionStatus::NotReceived => serializer.serialize_str("NOT_RECEIVED"),
            TransactionStatus::Received => serializer.serialize_str("RECEIVED"),
            TransactionStatus::Pending => serializer.serialize_str("PENDING"),
            TransactionStatus::Rejected => serializer.serialize_str("REJECTED"),
            TransactionStatus::AcceptedOnL1 => serializer.serialize_str("ACCEPTED_ON_L1"),
            TransactionStatus::AcceptedOnL2 => serializer.serialize_str("ACCEPTED_ON_L2"),
            TransactionStatus::Reverted => serializer.serialize_str("REVERTED"),
            TransactionStatus::Aborted => serializer.serialize_str("ABORTED"),
            TransactionStatus::Candidate => serializer.serialize_str("CANDIDATE"),
            TransactionStatus::Preconfirmed => serializer.serialize_str("PRE_CONFIRMED"),
        }
    }
}

impl From<starknet_gateway_types::reply::Status> for TransactionStatus {
    fn from(value: starknet_gateway_types::reply::Status) -> Self {
        use starknet_gateway_types::reply::Status;
        match value {
            Status::NotReceived => Self::NotReceived,
            Status::Received => Self::Received,
            Status::Pending => Self::Pending,
            Status::Rejected => Self::Rejected,
            Status::AcceptedOnL1 => Self::AcceptedOnL1,
            Status::AcceptedOnL2 => Self::AcceptedOnL2,
            Status::Reverted => Self::Reverted,
            Status::Aborted => Self::Aborted,
            Status::Candidate => Self::Candidate,
            Status::PreConfirmed => Self::Preconfirmed,
        }
    }
}

#[cfg(test)]
mod tests {

    use pathfinder_common::macro_prelude::*;

    use super::*;

    #[tokio::test]
    async fn l1_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 0 which is L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 0");
        let input = GetGatewayTransactionInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, TransactionStatus::AcceptedOnL1);
    }

    #[tokio::test]
    async fn l2_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = GetGatewayTransactionInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, TransactionStatus::AcceptedOnL2);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = GetGatewayTransactionInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, TransactionStatus::AcceptedOnL2);
    }

    #[tokio::test]
    async fn rejected() {
        let input = GetGatewayTransactionInput {
            // Transaction hash known to be rejected by the testnet gateway.
            transaction_hash: transaction_hash!(
                "0x4fef839b57a7ac72c8738dc821897cc605b5cc5aafa487e445e9282ac37ac23"
            ),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, TransactionStatus::Rejected);
    }

    #[tokio::test]
    async fn reverted() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetGatewayTransactionInput {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let status = get_transaction_status(context.clone(), input)
            .await
            .unwrap();
        assert_eq!(status, TransactionStatus::Reverted);

        let input = GetGatewayTransactionInput {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let status = get_transaction_status(context, input).await.unwrap();
        assert_eq!(status, TransactionStatus::Reverted);
    }
}
