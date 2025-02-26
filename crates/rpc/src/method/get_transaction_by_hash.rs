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
}
