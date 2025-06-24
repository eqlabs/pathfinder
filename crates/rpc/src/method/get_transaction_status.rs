use anyhow::Context;
use pathfinder_common::TransactionHash;

use crate::context::RpcContext;
use crate::dto::TxnExecutionStatus;
use crate::RpcVersion;

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    transaction_hash: TransactionHash,
}

impl Input {
    pub fn new(transaction_hash: TransactionHash) -> Self {
        Self { transaction_hash }
    }
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
    Rejected {
        // Reject error message optional for backward compatibility with gateway.
        error_message: Option<String>,
    },
    PreConfirmed(TxnExecutionStatus),
    AcceptedOnL1(TxnExecutionStatus),
    AcceptedOnL2(TxnExecutionStatus),
}

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub async fn get_transaction_status(
    context: RpcContext,
    input: Input,
    rpc_version: RpcVersion,
) -> Result<Output, Error> {
    // Check database.
    let span = tracing::Span::current();
    let db_status = util::task::spawn_blocking(move |_| {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let db_tx = db.transaction().context("Creating database transaction")?;

        let pending_data = context
            .pending_data
            .get(&db_tx, rpc_version)
            .context("Querying pending data")?;

        if let Some((receipt, _)) = pending_data
            .transaction_receipts_and_events()
            .iter()
            .find(|(rx, _)| rx.transaction_hash == input.transaction_hash)
        {
            let output = match pending_data.block().finality_status() {
                crate::dto::TxnFinalityStatus::PreConfirmed => {
                    Output::PreConfirmed((&receipt.execution_status).into())
                }
                crate::dto::TxnFinalityStatus::AcceptedOnL2 => {
                    Output::AcceptedOnL2((&receipt.execution_status).into())
                }
                // This is technically not possible: pending data is either PreConfirmed or
                // AcceptedOnL2.
                crate::dto::TxnFinalityStatus::AcceptedOnL1 => {
                    Output::AcceptedOnL1((&receipt.execution_status).into())
                }
            };
            return Ok(Some(output));
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
    let result = context
        .sequencer
        .transaction_status(input.transaction_hash)
        .await
        .context("Fetching transaction from gateway")
        .map_err(Error::Internal)
        .and_then(|tx| {
            use starknet_gateway_types::reply::transaction_status::{
                ExecutionStatus as GatewayExecutionStatus,
                FinalityStatus as GatewayFinalityStatus,
            };

            let execution_status = tx.execution_status.unwrap_or_default();

            match (tx.finality_status, execution_status) {
                (GatewayFinalityStatus::NotReceived, _) => {
                    if context
                        .submission_tracker
                        .contains_key(&input.transaction_hash)
                    {
                        Ok(Output::Received)
                    } else {
                        Err(Error::TxnHashNotFound)
                    }
                }
                (_, GatewayExecutionStatus::Rejected) => Ok(Output::Rejected {
                    error_message: tx.tx_failure_reason.map(|reason| reason.error_message),
                }),
                (GatewayFinalityStatus::Received, _) => Ok(Output::Received),
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Reverted) => {
                    Ok(Output::AcceptedOnL1(TxnExecutionStatus::Reverted {
                        reason: tx.tx_revert_reason,
                    }))
                }
                (GatewayFinalityStatus::AcceptedOnL1, GatewayExecutionStatus::Succeeded) => {
                    Ok(Output::AcceptedOnL1(TxnExecutionStatus::Succeeded))
                }
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Reverted) => {
                    Ok(Output::AcceptedOnL2(TxnExecutionStatus::Reverted {
                        reason: tx.tx_revert_reason,
                    }))
                }
                (GatewayFinalityStatus::AcceptedOnL2, GatewayExecutionStatus::Succeeded) => {
                    Ok(Output::AcceptedOnL2(TxnExecutionStatus::Succeeded))
                }
            }
        });
    context.submission_tracker.flush();
    result
}

impl Output {
    fn finality_status(&self) -> crate::dto::TxnStatus {
        use crate::dto::TxnStatus;
        match self {
            Output::Received => TxnStatus::Received,
            Output::Rejected { .. } => TxnStatus::Rejected,
            Output::PreConfirmed(_) => TxnStatus::PreConfirmed,
            Output::AcceptedOnL1(_) => TxnStatus::AcceptedOnL1,
            Output::AcceptedOnL2(_) => TxnStatus::AcceptedOnL2,
        }
    }

    fn execution_status(&self) -> Option<TxnExecutionStatus> {
        match self {
            Output::Received | Output::Rejected { .. } => None,
            Output::PreConfirmed(x) => Some(x.clone()),
            Output::AcceptedOnL1(x) => Some(x.clone()),
            Output::AcceptedOnL2(x) => Some(x.clone()),
        }
    }

    fn failure_reason(&self) -> Option<String> {
        match self {
            Output::Rejected { error_message } => error_message.clone(),
            Output::PreConfirmed(TxnExecutionStatus::Reverted { reason }) => reason.clone(),
            Output::AcceptedOnL1(TxnExecutionStatus::Reverted { reason }) => reason.clone(),
            Output::AcceptedOnL2(TxnExecutionStatus::Reverted { reason }) => reason.clone(),
            _ => None,
        }
    }
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("finality_status", &self.finality_status())?;
        serializer.serialize_optional("execution_status", self.execution_status())?;
        if serializer.version > RpcVersion::V07 {
            serializer.serialize_optional("failure_reason", self.failure_reason())?;
        }
        serializer.end()
    }
}

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use serde_json::json;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[rstest::rstest]
    #[case::rejected(Output::Rejected { error_message: None }, json!({"finality_status":"REJECTED"}))]
    #[case::reverted(Output::Received, json!({"finality_status":"RECEIVED"}))]
    #[case::accepted_on_l1_succeeded(
        Output::AcceptedOnL1(TxnExecutionStatus::Succeeded),
        json!({"finality_status":"ACCEPTED_ON_L1","execution_status":"SUCCEEDED"})
    )]
    #[case::accepted_on_l2_reverted(
        Output::AcceptedOnL2(TxnExecutionStatus::Reverted{ reason: None }),
        json!({"finality_status":"ACCEPTED_ON_L2","execution_status":"REVERTED"})
    )]
    fn output_serialization(#[case] output: Output, #[case] expected: serde_json::Value) {
        use crate::dto::SerializeForVersion;
        let encoded = output.serialize(Default::default()).unwrap();
        assert_eq!(encoded, expected);
    }

    const RPC_VERSION: RpcVersion = RpcVersion::V09;

    #[tokio::test]
    async fn l1_accepted() {
        let context = RpcContext::for_tests();
        // This transaction is in block 0 which is L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input, RPC_VERSION)
            .await
            .unwrap();

        assert_eq!(status, Output::AcceptedOnL1(TxnExecutionStatus::Succeeded));
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn l2_accepted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input, version)
            .await
            .unwrap();

        let output_json = status.serialize(Serializer { version }).unwrap();

        let expected_status = include_str!("../../fixtures/status/l2_accepted.json");
        let expected_json: serde_json::Value =
            serde_json::from_str(expected_status).expect("Failed to parse fixture as JSON");

        pretty_assertions_sorted::assert_eq!(output_json, expected_json);
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn pending(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let status = get_transaction_status(context, input, version)
            .await
            .unwrap();

        let output_json = status.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/status_pending.json"
        );
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn pre_confirmed(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pre_confirmed().await;
        let tx_hash = transaction_hash_bytes!(b"preconfirmed tx hash 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let result = get_transaction_status(context, input, version).await;

        match version {
            RpcVersion::V06 | RpcVersion::V07 | RpcVersion::V08 => {
                assert_matches::assert_matches!(result, Err(Error::TxnHashNotFound));
            }
            RpcVersion::V09 => {
                let output_json = result.unwrap().serialize(Serializer { version }).unwrap();
                let expected_json: serde_json::Value = serde_json::from_str(include_str!(
                    "../../fixtures/0.9.0/transactions/status_pre_confirmed.json"
                ))
                .unwrap();
                assert_eq!(output_json, expected_json);
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn not_received() {
        let input = Input {
            // Transaction hash known to have `NOT_RECEIVED` status.
            transaction_hash: transaction_hash!("0x6e6f6e2d6578697374656e74"),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input, RPC_VERSION).await;

        assert_matches!(status, Err(Error::TxnHashNotFound));
    }

    #[tokio::test]
    async fn rejected_with_error_message() {
        let input = Input {
            // Transaction hash known to be rejected by the testnet gateway.
            transaction_hash: transaction_hash!(
                "0x4fef839b57a7ac72c8738dc821897cc605b5cc5aafa487e445e9282ac37ac23"
            ),
        };
        let context = RpcContext::for_tests();
        let status = get_transaction_status(context, input, RPC_VERSION)
            .await
            .unwrap();

        assert_eq!(
            status,
            Output::Rejected {
                error_message: Some(
                    "Transaction is too big to fit a batch; Its gas_weight weights 5214072 while \
                     the batch upper bound is set to 5000000.0."
                        .to_string()
                )
            }
        );
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[case::v09(RpcVersion::V09)]
    #[tokio::test]
    async fn reverted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let status = get_transaction_status(context.clone(), input, version)
            .await
            .unwrap();

        let output_json = status.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/status_reverted_with_reason.json"
        );

        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let status = get_transaction_status(context, input, version)
            .await
            .unwrap();

        let output_json = status.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/status_reverted.json"
        );
    }

    #[tokio::test]
    async fn txn_hash_not_found() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"non-existent"),
        };
        let err = get_transaction_status(context.clone(), input, RPC_VERSION)
            .await
            .unwrap_err();

        assert_matches!(err, Error::TxnHashNotFound);
    }
}
