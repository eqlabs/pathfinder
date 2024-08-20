use anyhow::Context;
use pathfinder_common::{BlockId, TransactionIndex};

use crate::context::RpcContext;
use crate::v06::types::TransactionWithHash;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    block_id: BlockId,
    index: TransactionIndex,
}

crate::error::generate_rpc_error_subset!(
    GetTransactionByBlockIdAndIndexError: BlockNotFound,
    InvalidTxnIndex
);

pub async fn get_transaction_by_block_id_and_index(
    context: RpcContext,
    input: Input,
) -> Result<TransactionWithHash, GetTransactionByBlockIdAndIndexError> {
    let index: usize = input
        .index
        .get()
        .try_into()
        .map_err(|_| GetTransactionByBlockIdAndIndexError::InvalidTxnIndex)?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let result = context
                    .pending_data
                    .get(&db_tx)
                    .context("Querying pending dat")?
                    .block
                    .transactions
                    .get(index)
                    .cloned()
                    .ok_or(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex);
                return result.map(Into::into);
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        // Get the transaction from storage.
        match db_tx
            .transaction_at_block(block_id, index)
            .context("Reading transaction from database")?
        {
            Some(transaction) => Ok(transaction.into()),
            None => {
                // We now need to check whether it was the block hash or transaction index which
                // were invalid. We do this by checking if the block exists
                // at all. If no, then the block hash is invalid. If yes, then the index is
                // invalid.
                let block_exists = db_tx
                    .block_exists(block_id)
                    .context("Querying block existence")?;
                if block_exists {
                    Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex)
                } else {
                    Err(GetTransactionByBlockIdAndIndexError::BlockNotFound)
                }
            }
        }
    });

    jh.await.context("Database read panic or shutting down")?
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
            let positional = json!([
                {"block_hash": "0xdeadbeef"},
                1
            ]);

            let input = serde_json::from_value::<Input>(positional).unwrap();
            assert_eq!(
                input,
                Input {
                    block_id: BlockId::Hash(block_hash!("0xdeadbeef")),
                    index: TransactionIndex::new_or_panic(1),
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = json!({
                "block_id": {"block_hash": "0xdeadbeef"},
                "index": 1
            });

            let input = serde_json::from_value::<Input>(named_args).unwrap();
            assert_eq!(
                input,
                Input {
                    block_id: BlockId::Hash(block_hash!("0xdeadbeef")),
                    index: TransactionIndex::new_or_panic(1),
                }
            )
        }
    }
}
