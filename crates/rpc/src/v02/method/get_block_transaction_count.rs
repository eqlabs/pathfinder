use anyhow::Context;
use pathfinder_common::BlockId;

use crate::context::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GetBlockTransactionCountInput {
    block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for GetBlockTransactionCountInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

type BlockTransactionCount = u64;

crate::error::generate_rpc_error_subset!(GetBlockTransactionCountError: BlockNotFound);

pub async fn get_block_transaction_count(
    context: RpcContext,
    input: GetBlockTransactionCountInput,
) -> Result<BlockTransactionCount, GetBlockTransactionCountError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let count = context
                    .pending_data
                    .get(&tx)
                    .context("Querying pending data")?
                    .block
                    .transactions
                    .len() as u64;
                return Ok(count);
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let block_transaction_count = tx
            .transaction_count(block_id)
            .context("Reading transaction count from database")?;

        // Check if the value was 0 because there were no transactions, or because the
        // block hash is invalid.
        if block_transaction_count == 0 {
            let header = tx
                .block_header(block_id)
                .context("Querying block existence")?;

            return if header.is_some() {
                Ok(0)
            } else {
                Err(GetBlockTransactionCountError::BlockNotFound)
            };
        }
        Ok(block_transaction_count as BlockTransactionCount)
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHash, BlockNumber};
    use pathfinder_crypto::Felt;

    use super::*;

    mod json {
        use super::*;

        fn check(chunk: &str, block_id: BlockId) {
            let json = format!("{{ \"block_id\": {chunk} }}");
            let input =
                serde_json::from_str::<GetBlockTransactionCountInput>(&json).expect("JSON parsing");
            assert_eq!(input.block_id, block_id, "JSON: '{json}'");
        }

        #[test]
        fn test_latest() {
            check("\"latest\"", BlockId::Latest);
        }

        #[test]
        fn test_pending() {
            check("\"pending\"", BlockId::Pending);
        }

        #[test]
        fn test_block_number() {
            check(
                "{ \"block_number\": 42 }",
                BlockId::Number(BlockNumber::new_or_panic(42)),
            );
        }

        #[test]
        fn test_block_hash() {
            check(
                "{ \"block_hash\": \"0xFACE\" }",
                BlockId::Hash(block_hash!("0xface")),
            );
        }
    }

    async fn check_count(context: RpcContext, block_id: BlockId, count: u64) {
        let input = GetBlockTransactionCountInput { block_id };
        let result = get_block_transaction_count(context, input)
            .await
            .expect("block transaction count");
        assert_eq!(result, count);
    }

    async fn check_error(context: RpcContext, block_id: BlockId) {
        let input = GetBlockTransactionCountInput { block_id };
        let result = get_block_transaction_count(context, input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_genesis() {
        let context = RpcContext::for_tests();
        let block_id = BlockId::Hash(block_hash_bytes!(b"genesis"));
        check_count(context, block_id, 1).await;
    }

    #[tokio::test]
    async fn test_latest() {
        let context = RpcContext::for_tests();
        let block_id = BlockId::Latest;
        check_count(context, block_id, 5).await;
    }

    #[tokio::test]
    async fn test_pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let block_id = BlockId::Pending;
        check_count(context, block_id, 3).await;
    }

    #[tokio::test]
    async fn test_invalid_hash() {
        let context = RpcContext::for_tests();
        let block_id = BlockId::Hash(BlockHash(Felt::ZERO));
        check_error(context, block_id).await;
    }

    #[tokio::test]
    async fn test_invalid_number() {
        let context = RpcContext::for_tests();
        let block_id = BlockId::Number(BlockNumber::new_or_panic(123));
        check_error(context, block_id).await;
    }
}
