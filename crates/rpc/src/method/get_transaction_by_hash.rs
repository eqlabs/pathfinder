crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFound);

use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::TransactionHash;

use crate::context::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    transaction_hash: TransactionHash,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output(Transaction);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: Input,
) -> Result<Output, GetTransactionByHashError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
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

    jh.await
        .context("Database read panic or shutting down")?
        .map_err(Into::into)
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize(&crate::dto::Transaction(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    mod parsing {
        use serde_json::json;

        use super::*;

        #[test]
        fn positional_args() {
            let positional = json!(["0xdeadbeef"]);

            let input = serde_json::from_value::<Input>(positional).unwrap();
            assert_eq!(
                input,
                Input {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = json!({
                "transaction_hash": "0xdeadbeef"
            });
            let input = serde_json::from_value::<Input>(named_args).unwrap();
            assert_eq!(
                input,
                Input {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }
    }
}
