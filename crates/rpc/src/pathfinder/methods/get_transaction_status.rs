use anyhow::Context;
use pathfinder_common::TransactionHash;
use starknet_gateway_types::reply::transaction::ExecutionStatus;
use starknet_gateway_types::reply::PendingBlock;

use crate::context::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetGatewayTransactionInput {
    transaction_hash: TransactionHash,
}

crate::error::generate_rpc_error_subset!(GetGatewayTransactionError:);

pub async fn get_transaction_status(
    context: RpcContext,
    input: GetGatewayTransactionInput,
) -> Result<TransactionStatus, GetGatewayTransactionError> {
    let span = tracing::Span::current();

    let db_status = tokio::task::spawn_blocking(move || {
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
        if let Some(status) = pending_status(&pending.block, &input.transaction_hash) {
            return Ok(Some(status));
        }

        let Some((_, receipt, block_hash)) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Fetching receipt from database")?
        else {
            return anyhow::Ok(None);
        };

        if receipt.execution_status == ExecutionStatus::Reverted {
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
        .transaction(input.transaction_hash)
        .await
        .context("Fetching transaction from gateway")
        .map(|tx| tx.status.into())
        .map_err(GetGatewayTransactionError::Internal)
}

fn pending_status(pending: &PendingBlock, tx_hash: &TransactionHash) -> Option<TransactionStatus> {
    pending.transaction_receipts.iter().find_map(|rx| {
        if &rx.transaction_hash == tx_hash {
            if rx.execution_status == ExecutionStatus::Reverted {
                Some(TransactionStatus::Reverted)
            } else {
                Some(TransactionStatus::AcceptedOnL2)
            }
        } else {
            None
        }
    })
}

#[derive(Copy, Clone, Debug, serde::Serialize, PartialEq)]
pub enum TransactionStatus {
    #[serde(rename = "NOT_RECEIVED")]
    NotReceived,
    #[serde(rename = "RECEIVED")]
    Received,
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "REJECTED")]
    Rejected,
    #[serde(rename = "ACCEPTED_ON_L1")]
    AcceptedOnL1,
    #[serde(rename = "ACCEPTED_ON_L2")]
    AcceptedOnL2,
    #[serde(rename = "REVERTED")]
    Reverted,
    #[serde(rename = "ABORTED")]
    Aborted,
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
                "0x07c64b747bdb0831e7045925625bfa6309c422fded9527bacca91199a1c8d212"
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
