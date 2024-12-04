use anyhow::Context;
use pathfinder_common::TransactionHash;
use serde_with::skip_serializing_none;

use crate::context::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetTransactionStatusInput {
    transaction_hash: TransactionHash,
}

impl crate::dto::DeserializeForVersion for GetTransactionStatusInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

#[derive(Debug, PartialEq, Eq)]
#[skip_serializing_none]
pub enum GetTransactionStatusOutput {
    Received,
    Rejected,
    AcceptedOnL1(ExecutionStatus),
    AcceptedOnL2(ExecutionStatus),
}

impl serde::Serialize for GetTransactionStatusOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        match self {
            GetTransactionStatusOutput::Received => {
                let mut s = serializer.serialize_struct("GetTransactionStatusOutput", 1)?;
                s.serialize_field("finality_status", "RECEIVED")?;
                s.end()
            }
            GetTransactionStatusOutput::Rejected => {
                let mut s = serializer.serialize_struct("GetTransactionStatusOutput", 1)?;
                s.serialize_field("finality_status", "REJECTED")?;
                s.end()
            }
            GetTransactionStatusOutput::AcceptedOnL1(execution_status) => {
                let mut s = serializer.serialize_struct("GetTransactionStatusOutput", 2)?;
                s.serialize_field("finality_status", "ACCEPTED_ON_L1")?;
                s.serialize_field("execution_status", execution_status)?;
                s.end()
            }
            GetTransactionStatusOutput::AcceptedOnL2(execution_status) => {
                let mut s = serializer.serialize_struct("GetTransactionStatusOutput", 2)?;
                s.serialize_field("finality_status", "ACCEPTED_ON_L2")?;
                s.serialize_field("execution_status", execution_status)?;
                s.end()
            }
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Succeeded,
    Reverted,
}

impl From<pathfinder_common::receipt::ExecutionStatus> for ExecutionStatus {
    fn from(value: pathfinder_common::receipt::ExecutionStatus) -> Self {
        match value {
            pathfinder_common::receipt::ExecutionStatus::Succeeded => Self::Succeeded,
            pathfinder_common::receipt::ExecutionStatus::Reverted { .. } => Self::Reverted,
        }
    }
}

crate::error::generate_rpc_error_subset!(GetTransactionStatusError: TxnHashNotFound);

pub async fn get_transaction_status(
    context: RpcContext,
    input: GetTransactionStatusInput,
) -> Result<GetTransactionStatusOutput, GetTransactionStatusError> {
    // Check database.
    let span = tracing::Span::current();

    let db_status = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let db_tx = db.transaction().context("Creating database transaction")?;

        if let Some((receipt, _)) = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?
            .block
            .transaction_receipts
            .iter()
            .find(|(rx, _)| rx.transaction_hash == input.transaction_hash)
        {
            return Ok(Some(GetTransactionStatusOutput::AcceptedOnL2(
                receipt.execution_status.clone().into(),
            )));
        }

        let Some((_, receipt, _, block_hash)) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Fetching receipt from database")?
        else {
            return anyhow::Ok(None);
        };

        let l1_accepted = db_tx
            .block_is_l1_accepted(block_hash.into())
            .context("Querying block's status")?;

        Ok(Some(if l1_accepted {
            GetTransactionStatusOutput::AcceptedOnL1(receipt.execution_status.into())
        } else {
            GetTransactionStatusOutput::AcceptedOnL2(receipt.execution_status.into())
        }))
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
        .context("Fetching transaction from gateway")
        .map_err(GetTransactionStatusError::Internal)
        .and_then(|tx| {
            use starknet_gateway_types::reply::transaction_status::{
                ExecutionStatus as GatewayExecutionStatus,
                FinalityStatus as GatewayFinalityStatus,
            };

            let execution_status = tx.execution_status.unwrap_or_default();

            match (tx.finality_status, execution_status) {
                (GatewayFinalityStatus::NotReceived, _) => {
                    Err(GetTransactionStatusError::TxnHashNotFound)
                }
                (_, GatewayExecutionStatus::Rejected) => Ok(GetTransactionStatusOutput::Rejected),
                (GatewayFinalityStatus::Received, _) => Ok(GetTransactionStatusOutput::Received),
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Reverted) => Ok(
                    GetTransactionStatusOutput::AcceptedOnL1(ExecutionStatus::Reverted),
                ),
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Succeeded) => Ok(
                    GetTransactionStatusOutput::AcceptedOnL1(ExecutionStatus::Succeeded),
                ),
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Reverted) => Ok(
                    GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Reverted),
                ),
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Succeeded) => Ok(
                    GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Succeeded),
                ),
            }
        })
}

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;

    use super::*;

    #[rstest::rstest]
    #[case::rejected(
        GetTransactionStatusOutput::Rejected,
        r#"{"finality_status":"REJECTED"}"#
    )]
    #[case::reverted(
        GetTransactionStatusOutput::Received,
        r#"{"finality_status":"RECEIVED"}"#
    )]
    #[case::accepted_on_l1_succeeded(
        GetTransactionStatusOutput::AcceptedOnL1(ExecutionStatus::Succeeded),
        r#"{"finality_status":"ACCEPTED_ON_L1","execution_status":"SUCCEEDED"}"#
    )]
    #[case::accepted_on_l2_reverted(
        GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Reverted),
        r#"{"finality_status":"ACCEPTED_ON_L2","execution_status":"REVERTED"}"#
    )]
    fn output_serialization(#[case] output: GetTransactionStatusOutput, #[case] expected: &str) {
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(json, expected);
    }

    #[tokio::test]
    async fn l1_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 0 which is L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 0");
        let input = GetTransactionStatusInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(
            status,
            GetTransactionStatusOutput::AcceptedOnL1(ExecutionStatus::Succeeded)
        );
    }

    #[tokio::test]
    async fn l2_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = GetTransactionStatusInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(
            status,
            GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Succeeded)
        );
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = GetTransactionStatusInput {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(
            status,
            GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Succeeded)
        );
    }

    #[tokio::test]
    async fn rejected() {
        let input = GetTransactionStatusInput {
            // Transaction hash known to be rejected by the testnet gateway.
            transaction_hash: transaction_hash!(
                "0x4fef839b57a7ac72c8738dc821897cc605b5cc5aafa487e445e9282ac37ac23"
            ),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, GetTransactionStatusOutput::Rejected);
    }

    #[tokio::test]
    async fn reverted() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetTransactionStatusInput {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let status = get_transaction_status(context.clone(), input)
            .await
            .unwrap();
        assert_eq!(
            status,
            GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Reverted)
        );

        let input = GetTransactionStatusInput {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let status = get_transaction_status(context, input).await.unwrap();
        assert_eq!(
            status,
            GetTransactionStatusOutput::AcceptedOnL2(ExecutionStatus::Reverted)
        );
    }

    #[tokio::test]
    async fn txn_hash_not_found() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetTransactionStatusInput {
            transaction_hash: transaction_hash_bytes!(b"non-existent"),
        };
        let err = get_transaction_status(context.clone(), input)
            .await
            .unwrap_err();

        assert_matches!(err, GetTransactionStatusError::TxnHashNotFound);
    }
}
