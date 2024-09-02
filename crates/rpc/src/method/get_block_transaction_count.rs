use anyhow::Context;
use pathfinder_common::BlockId;

use crate::context::RpcContext;

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
            })
        })
    }
}

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

#[derive(Debug)]
pub struct Output(u64);

pub async fn get_block_transaction_count(
    context: RpcContext,
    input: Input,
) -> Result<Output, Error> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let count = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?
                    .block
                    .transactions
                    .len() as u64;
                return Ok(Output(count));
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let exists = db
            .block_exists(block_id)
            .context("Querying block existence")?;

        if !exists {
            return Err(Error::BlockNotFound);
        }

        let count = db
            .transaction_count(block_id)
            .context("Reading transaction count from database")?;

        Ok(Output(count as u64))
    })
    .await
    .context("Joining blocking task")?
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize_u64(self.0)
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    #[rstest::rstest]
    #[case::latest(BlockId::Latest, 5)]
    #[case::pending(BlockId::Pending, 3)]
    #[tokio::test]
    async fn ok(#[case] input: BlockId, #[case] expected: u64) {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input { block_id: input };
        let result = get_block_transaction_count(context, input).await.unwrap();

        assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn block_not_found() {
        let input = Input {
            block_id: block_hash_bytes!(b"invalid").into(),
        };
        let context = RpcContext::for_tests_with_pending().await;
        let result = get_block_transaction_count(context, input).await;

        assert_matches::assert_matches!(result, Err(Error::BlockNotFound));
    }
}
