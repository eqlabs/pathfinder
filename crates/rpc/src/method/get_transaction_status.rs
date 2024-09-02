use anyhow::Context;
use pathfinder_common::TransactionHash;

use crate::context::RpcContext;
use crate::dto::TxnExecutionStatus;

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    transaction_hash: TransactionHash,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value.deserialize("transaction_hash").map(TransactionHash)?,
            })
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum Output {
    Received,
    Rejected,
    AcceptedOnL1(TxnExecutionStatus),
    AcceptedOnL2(TxnExecutionStatus),
}

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub async fn get_transaction_status(context: RpcContext, input: Input) -> Result<Output, Error> {
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
            return Ok(Some(Output::AcceptedOnL2(
                (&receipt.execution_status).into(),
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
            Output::AcceptedOnL1((&receipt.execution_status).into())
        } else {
            Output::AcceptedOnL2((&receipt.execution_status).into())
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
        .transaction(input.transaction_hash)
        .await
        .context("Fetching transaction from gateway")
        .map_err(Error::Internal)
        .and_then(|tx| {
            use starknet_gateway_types::reply::transaction_status::{
                ExecutionStatus as GatewayExecutionStatus,
                FinalityStatus as GatewayFinalityStatus,
            };

            match (tx.finality_status, tx.execution_status) {
                (GatewayFinalityStatus::NotReceived, _) => Err(Error::TxnHashNotFound),
                (_, GatewayExecutionStatus::Rejected) => Ok(Output::Rejected),
                (GatewayFinalityStatus::Received, _) => Ok(Output::Received),
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Reverted) => {
                    Ok(Output::AcceptedOnL1(TxnExecutionStatus::Reverted))
                }
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Succeeded) => {
                    Ok(Output::AcceptedOnL1(TxnExecutionStatus::Succeeded))
                }
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Reverted) => {
                    Ok(Output::AcceptedOnL2(TxnExecutionStatus::Reverted))
                }
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Succeeded) => {
                    Ok(Output::AcceptedOnL2(TxnExecutionStatus::Succeeded))
                }
            }
        })
}

impl Output {
    fn finality_status(&self) -> crate::dto::TxnStatus {
        use crate::dto::TxnStatus;
        match self {
            Output::Received => TxnStatus::Received,
            Output::Rejected => TxnStatus::Rejected,
            Output::AcceptedOnL1(_) => TxnStatus::AcceptedOnL1,
            Output::AcceptedOnL2(_) => TxnStatus::AcceptedOnL2,
        }
    }

    fn execution_status(&self) -> Option<TxnExecutionStatus> {
        match self {
            Output::Received | Output::Rejected => None,
            Output::AcceptedOnL1(x) => Some(*x),
            Output::AcceptedOnL2(x) => Some(*x),
        }
    }
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("finality_status", &self.finality_status())?;
        serializer.serialize_optional("execution_status", self.execution_status())?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use serde_json::json;

    use super::*;

    #[rstest::rstest]
    #[case::rejected(Output::Rejected, json!({"finality_status":"REJECTED"}))]
    #[case::reverted(Output::Received, json!({"finality_status":"RECEIVED"}))]
    #[case::accepted_on_l1_succeeded(
        Output::AcceptedOnL1(TxnExecutionStatus::Succeeded),
        json!({"finality_status":"ACCEPTED_ON_L1","execution_status":"SUCCEEDED"})
    )]
    #[case::accepted_on_l2_reverted(
        Output::AcceptedOnL2(TxnExecutionStatus::Reverted),
        json!({"finality_status":"ACCEPTED_ON_L2","execution_status":"REVERTED"})
    )]
    fn output_serialization(#[case] output: Output, #[case] expected: serde_json::Value) {
        use crate::dto::serialize::SerializeForVersion;
        let encoded = output.serialize(Default::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    #[tokio::test]
    async fn l1_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 0 which is L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, Output::AcceptedOnL1(TxnExecutionStatus::Succeeded));
    }

    #[tokio::test]
    async fn l2_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, Output::AcceptedOnL2(TxnExecutionStatus::Succeeded));
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, Output::AcceptedOnL2(TxnExecutionStatus::Succeeded));
    }

    #[tokio::test]
    async fn rejected() {
        let input = Input {
            // Transaction hash known to be rejected by the testnet gateway.
            transaction_hash: transaction_hash!(
                "0x4fef839b57a7ac72c8738dc821897cc605b5cc5aafa487e445e9282ac37ac23"
            ),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input).await.unwrap();

        assert_eq!(status, Output::Rejected);
    }

    #[tokio::test]
    async fn reverted() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let status = get_transaction_status(context.clone(), input)
            .await
            .unwrap();
        assert_eq!(status, Output::AcceptedOnL2(TxnExecutionStatus::Reverted));

        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let status = get_transaction_status(context, input).await.unwrap();
        assert_eq!(status, Output::AcceptedOnL2(TxnExecutionStatus::Reverted));
    }

    #[tokio::test]
    async fn txn_hash_not_found() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"non-existent"),
        };
        let err = get_transaction_status(context.clone(), input)
            .await
            .unwrap_err();

        assert_matches!(err, Error::TxnHashNotFound);
    }
}
