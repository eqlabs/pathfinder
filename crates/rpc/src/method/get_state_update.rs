use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::StateUpdate;

use crate::types::BlockId;
use crate::{dto, RpcContext, RpcVersion};

#[derive(Clone, Debug, PartialEq, Eq)]
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

impl dto::SerializeForVersion for Output {
    fn serialize(&self, serializer: dto::Serializer) -> Result<dto::Ok, dto::Error> {
        match self {
            Output::Full(full) => dto::StateUpdate(full).serialize(serializer),
            Output::Pending(pending) => dto::PendingStateUpdate(pending).serialize(serializer),
        }
    }
}

pub async fn get_state_update(
    context: RpcContext,
    input: Input,
    rpc_version: RpcVersion,
) -> Result<Output, Error> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        if input.block_id.is_pending() {
            let state_update = context
                .pending_data
                .get(&tx, rpc_version)
                .context("Query pending data")?
                .pending_state_update();

            return Ok(Output::Pending(state_update));
        }

        let block_id = input
            .block_id
            .to_common_or_panic(&tx)
            .map_err(|_| Error::BlockNotFound)?;

        let Some(block_number) = tx.block_number(block_id).context("Fetching block number")? else {
            return Err(Error::BlockNotFound);
        };
        if let Some(parent_block) = block_number.checked_sub(1) {
            let parent_exists = tx
                .block_exists(parent_block.into())
                .context("Checking if parent exists")?;

            // Parent block must also be present (not pruned) to obtain
            // `parent_state_commitment`.
            if !parent_exists {
                return Err(Error::BlockNotFound);
            }
        }

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
    use std::collections::{HashMap, HashSet};

    use dto::DeserializeForVersion;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdate};
    use pathfinder_common::BlockNumber;
    use pathfinder_storage::fake::Block;
    use serde_json::json;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
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

    #[rstest::rstest]
    #[case::v09(RpcVersion::V09)]
    #[case::v10(RpcVersion::V10)]
    #[tokio::test]
    async fn serialize_output(#[case] version: RpcVersion) {
        let mut storage = HashMap::new();
        storage.insert(storage_address!("0xf0"), storage_value!("0x55"));
        let storage_update = ContractUpdate {
            storage,
            class: None,
            nonce: None,
        };
        let deploy_class_update = ContractUpdate {
            storage: Default::default(),
            class: Some(ContractClassUpdate::Deploy(class_hash!("0xcdef"))),
            nonce: None,
        };
        let replace_class_update = ContractUpdate {
            storage: Default::default(),
            class: Some(ContractClassUpdate::Replace(class_hash!("0xdac"))),
            nonce: None,
        };
        let nonce_update = ContractUpdate {
            storage: Default::default(),
            class: None,
            nonce: Some(contract_nonce!("0x404ce")),
        };
        let mut contract_updates = HashMap::new();
        contract_updates.insert(contract_address!("0xadc"), storage_update);
        contract_updates.insert(contract_address!("0xadd"), deploy_class_update);
        contract_updates.insert(contract_address!("0xcad"), replace_class_update);
        contract_updates.insert(contract_address!("0xca"), nonce_update);
        let mut declared_cairo_classes = HashSet::new();
        declared_cairo_classes.insert(class_hash!("0xcdef"));
        let mut declared_sierra_classes = HashMap::new();
        declared_sierra_classes.insert(sierra_hash!("0xabcd"), casm_hash!("0xdcba"));
        let state_update = StateUpdate {
            block_hash: block_hash!("0xdeadbeef"),
            state_commitment: state_commitment!("0x1"),
            parent_state_commitment: state_commitment!("0x2"),
            contract_updates,
            system_contract_updates: Default::default(),
            declared_cairo_classes,
            declared_sierra_classes,
            migrated_compiled_classes: HashMap::from([(
                sierra_hash!("0xabcd"),
                casm_hash!("0xdcbb"),
            )]),
        };

        let output_full = Output::Full(Box::new(state_update.clone()));
        let output_json = output_full.serialize(Serializer { version }).unwrap();
        crate::assert_json_matches_fixture!(output_json, version, "state_updates/full.json");

        let output_pending = Output::Pending(Arc::new(state_update));
        let output_json = output_pending.serialize(Serializer { version }).unwrap();
        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "state_updates/pre_confirmed.json"
        );
    }

    /// Add some dummy state updates to the context for testing
    fn context_with_state_updates() -> (Vec<StateUpdate>, RpcContext) {
        let blocks = pathfinder_storage::fake::generate::n_blocks(3);
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();
        pathfinder_storage::fake::fill(&storage, &blocks, None);

        let state_updates = blocks
            .into_iter()
            .map(|Block { state_update, .. }| state_update.unwrap())
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

    const RPC_VERSION: RpcVersion = RpcVersion::V09;

    #[tokio::test]
    async fn latest() {
        let (mut in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            Input {
                block_id: BlockId::Latest,
            },
            RPC_VERSION,
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
            RPC_VERSION,
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
            RPC_VERSION,
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
            RPC_VERSION,
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
            RPC_VERSION,
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

        let expected = context.pending_data.get_unchecked().pending_state_update();

        let result = get_state_update(context, input, RPC_VERSION)
            .await
            .unwrap()
            .unwrap_pending();

        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn pre_confirmed() {
        let context = RpcContext::for_tests_with_pre_confirmed().await;
        let input = Input {
            block_id: BlockId::Pending,
        };

        let expected = context.pending_data.get_unchecked().pending_state_update();

        let result = get_state_update(context.clone(), input.clone(), RpcVersion::V09)
            .await
            .unwrap()
            .unwrap_pending();
        assert_eq!(result, expected);

        let result = get_state_update(context.clone(), input.clone(), RpcVersion::V08)
            .await
            .unwrap()
            .unwrap_pending();
        assert_eq!(
            result,
            StateUpdate::default()
                .with_parent_state_commitment(expected.parent_state_commitment)
                .into()
        );
    }
}
