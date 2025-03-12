crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFound);

use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::TransactionHash;

use crate::context::RpcContext;

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

#[derive(Debug, PartialEq, Eq)]
pub struct Output(Transaction);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: Input,
) -> Result<Output, GetTransactionByHashError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Check pending transactions.
        if let Some(tx) = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?
            .block
            .transactions
            .iter()
            .find(|tx| tx.hash == input.transaction_hash)
            .cloned()
        {
            return Ok(Output(tx));
        }

        // Get the transaction from storage.
        db_tx
            .transaction(input.transaction_hash)
            .context("Reading transaction from database")?
            .ok_or(GetTransactionByHashError::TxnHashNotFound)
            .map(Output)
    });

    jh.await.context("Database read panic or shutting down")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize(&crate::dto::TransactionWithHash(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    mod parsing {
        use serde_json::json;

        use super::*;
        use crate::dto::DeserializeForVersion;

        #[test]
        fn positional_args() {
            let positional_json = json!(["0xdeadbeef"]);

            let positional = crate::dto::Value::new(positional_json, crate::RpcVersion::V08);

            let input = Input::deserialize(positional).unwrap();
            assert_eq!(
                input,
                Input {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args_json = json!({
                "transaction_hash": "0xdeadbeef"
            });

            let named = crate::dto::Value::new(named_args_json, crate::RpcVersion::V08);

            let input = Input::deserialize(named).unwrap();
            assert_eq!(
                input,
                Input {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }
    }

    use pathfinder_common::transaction_hash_bytes;

    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn l2_accepted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let output = get_transaction_by_hash(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(output_json, version, "transactions/txn_1.json");
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn pending(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let output = get_transaction_by_hash(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/txn_pending_hash_0.json"
        );
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn reverted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let output = get_transaction_by_hash(context.clone(), input)
            .await
            .unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(output_json, version, "transactions/txn_reverted.json");

        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let output = get_transaction_by_hash(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/txn_pending_reverted.json"
        );
    }
}
