use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{BlockId, StateUpdate};

use crate::{dto, RpcContext};

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
            })
        })
    }
}

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

#[derive(PartialEq, Debug)]
pub enum Output {
    Full(Box<StateUpdate>),
    Pending(Arc<StateUpdate>),
}

impl dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: dto::serialize::Serializer,
    ) -> Result<dto::serialize::Ok, dto::serialize::Error> {
        match self {
            Output::Full(full) => dto::StateUpdate(full).serialize(serializer),
            Output::Pending(pending) => dto::PendingStateUpdate(pending).serialize(serializer),
        }
    }
}

pub async fn get_state_update(context: RpcContext, input: Input) -> Result<Output, Error> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        if input.block_id.is_pending() {
            let state_update = context
                .pending_data
                .get(&tx)
                .context("Query pending data")?
                .state_update;

            return Ok(Output::Pending(state_update));
        }

        let block_id = input
            .block_id
            .try_into()
            .expect("Only pending cast should fail");

        let state_update = tx
            .state_update(block_id)
            .context("Fetching state diff")?
            .ok_or(Error::BlockNotFound)?;

        Ok(Output::Full(Box::new(state_update)))
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use dto::DeserializeForVersion;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockNumber;
    use pathfinder_storage::fake::Block;
    use serde_json::json;

    use super::*;
    use crate::RpcVersion;

    impl Output {
        fn unwrap_full(self) -> Box<StateUpdate> {
            match self {
                Output::Full(x) => x,
                Output::Pending(_) => panic!("Output was Pending variant"),
            }
        }

        fn unwrap_pending(self) -> Arc<StateUpdate> {
            match self {
                Output::Pending(x) => x,
                Output::Full(_) => panic!("Output was Full variant"),
            }
        }
    }

    #[rstest::rstest]
    #[case::pending_by_position(json!(["pending"]), BlockId::Pending)]
    #[case::pending_by_name(json!({"block_id": "pending"}), BlockId::Pending)]
    #[case::latest_by_position(json!(["latest"]), BlockId::Latest)]
    #[case::latest_by_name(json!({"block_id": "latest"}), BlockId::Latest)]
    #[case::number_by_position(json!([{"block_number":123}]), BlockNumber::new_or_panic(123).into())]
    #[case::number_by_name(json!({"block_id": {"block_number":123}}), BlockNumber::new_or_panic(123).into())]
    #[case::hash_by_position(json!([{"block_hash": "0xbeef"}]), block_hash!("0xbeef").into())]
    #[case::hash_by_name(json!({"block_id": {"block_hash": "0xbeef"}}), block_hash!("0xbeef").into())]
    fn input_parsing(#[case] input: serde_json::Value, #[case] block_id: BlockId) {
        let input = Input::deserialize(crate::dto::Value::new(input, RpcVersion::V07)).unwrap();

        let expected = Input { block_id };

        assert_eq!(input, expected);
    }

    /// Add some dummy state updates to the context for testing
    fn context_with_state_updates() -> (Vec<StateUpdate>, RpcContext) {
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();

        let state_updates = pathfinder_storage::fake::with_n_blocks(&storage, 3)
            .into_iter()
            .map(|Block { state_update, .. }| state_update)
            .collect();

        let context = RpcContext::for_tests().with_storage(storage);

        (state_updates, context)
    }

    impl PartialEq for Error {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    #[tokio::test]
    async fn latest() {
        let (mut in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Latest,
            },
        )
        .await
        .unwrap()
        .unwrap_full();

        assert_eq!(*result, in_storage.pop().unwrap());
    }

    #[tokio::test]
    async fn by_number() {
        let (in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Number(BlockNumber::GENESIS),
            },
        )
        .await
        .unwrap()
        .unwrap_full();

        assert_eq!(*result, in_storage[0].clone());
    }

    #[tokio::test]
    async fn by_hash() {
        let (in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Hash(in_storage[1].block_hash),
            },
        )
        .await
        .unwrap()
        .unwrap_full();

        assert_eq!(*result, in_storage[1].clone());
    }

    #[tokio::test]
    async fn not_found_by_number() {
        let (_in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Number(BlockNumber::MAX),
            },
        )
        .await;

        assert_eq!(result, Err(Error::BlockNotFound));
    }

    #[tokio::test]
    async fn not_found_by_hash() {
        let (_in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Hash(block_hash_bytes!(b"non-existent")),
            },
        )
        .await;

        assert_eq!(result, Err(Error::BlockNotFound));
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            block_id: BlockId::Pending,
        };

        let expected = context.pending_data.get_unchecked().state_update;

        let result = get_state_update(context, input)
            .await
            .unwrap()
            .unwrap_pending();

        assert_eq!(result, expected);
    }
}
