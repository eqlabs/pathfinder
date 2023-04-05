use anyhow::Context;
use pathfinder_common::{StarknetBlockNumber, StarknetTransactionHash};
use pathfinder_storage::Storage;
use rusqlite::OptionalExtension;
use starknet_gateway_types::pending::PendingData;

use crate::context::RpcContext;
use crate::v02::common::get_block_status;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetGatewayTransactionInput {
    transaction_hash: StarknetTransactionHash,
}

crate::error::generate_rpc_error_subset!(GetGatewayTransactionError:);

pub async fn get_transaction_status(
    context: RpcContext,
    input: GetGatewayTransactionInput,
) -> Result<GatewayStatus, GetGatewayTransactionError> {
    // Check in pending block.
    if let Some(pending) = &context.pending_data {
        if is_pending_tx(pending, &input.transaction_hash).await {
            return Ok(GatewayStatus::Pending);
        }
    }

    // Check database.
    let span = tracing::Span::current();

    let db_status = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        check_database(&context.storage, &input.transaction_hash)
    })
    .await
    .context("Database read panic or shutting down")?
    .context("Checking database for transaction")?;
    if let Some(status) = db_status {
        return Ok(status);
    }

    // Check gateway for rejected transactions.
    use starknet_gateway_client::ClientApi;
    context
        .sequencer
        .transaction(input.transaction_hash)
        .await
        .context("Fetching transaction from gateway")
        .map(|tx| tx.status.into())
        .map_err(GetGatewayTransactionError::Internal)
}

async fn is_pending_tx(pending: &PendingData, tx_hash: &StarknetTransactionHash) -> bool {
    pending
        .block()
        .await
        .map(|block| block.transactions.iter().any(|tx| &tx.hash() == tx_hash))
        .unwrap_or_default()
}

fn check_database(
    storage: &Storage,
    transaction_hash: &StarknetTransactionHash,
) -> anyhow::Result<Option<GatewayStatus>> {
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let db_tx = db.transaction().context("Creating database transaction")?;

    // Get the transaction from storage.
    let block_number = db_tx
        .query_row(
            r"SELECT starknet_blocks.number FROM starknet_transactions 
    JOIN starknet_blocks ON starknet_transactions.block_hash = starknet_blocks.hash
    WHERE starknet_transactions.hash = ?",
            [transaction_hash],
            |row| {
                let number = row.get_ref_unwrap(0).as_i64()?;
                Ok(StarknetBlockNumber::new_or_panic(number as u64))
            },
        )
        .optional()
        .context("Fetching transaction's block number from database")?;

    let block_number = match block_number {
        Some(block_number) => block_number,
        None => return anyhow::Ok(None),
    };

    let status =
        get_block_status(&db_tx, block_number).context("Fetching block status from database")?;
    use crate::v02::types::reply::BlockStatus;
    let status = match status {
        BlockStatus::Pending => GatewayStatus::Pending,
        BlockStatus::AcceptedOnL2 => GatewayStatus::AcceptedOnL2,
        BlockStatus::AcceptedOnL1 => GatewayStatus::AcceptedOnL1,
        BlockStatus::Rejected => GatewayStatus::Rejected,
    };

    Ok(Some(status))
}

/// A local definition of the [gateway's status type](starknet_gateway_types::reply::Status) to decouple this from the official gateway types.
#[derive(Copy, Clone, Debug, serde::Serialize, PartialEq)]
pub enum GatewayStatus {
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

impl From<starknet_gateway_types::reply::Status> for GatewayStatus {
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
    use pathfinder_common::{felt, felt_bytes};

    use super::*;

    #[test]
    fn database() {
        let context = RpcContext::for_tests();

        let status = check_database(
            &context.storage,
            &StarknetTransactionHash(felt_bytes!(b"txn 0")),
        )
        .unwrap()
        .unwrap();

        assert_eq!(status, GatewayStatus::AcceptedOnL2);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = StarknetTransactionHash(felt_bytes!(b"pending tx hash 0"));
        assert!(is_pending_tx(&context.pending_data.unwrap(), &tx_hash).await);
    }

    #[tokio::test]
    async fn rejected() {
        let input = GetGatewayTransactionInput {
            transaction_hash: StarknetTransactionHash(felt!(
                // Transaction hash known to be rejected by the testnet gateway.
                "0x07c64b747bdb0831e7045925625bfa6309c422fded9527bacca91199a1c8d212"
            )),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, GatewayStatus::Rejected);
    }
}
