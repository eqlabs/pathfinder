use anyhow::Context;
use pathfinder_common::BlockId;

use crate::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GetStateUpdateInput {
    block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for GetStateUpdateInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

crate::error::generate_rpc_error_subset!(GetStateUpdateError: BlockNotFound);

pub async fn get_state_update(
    context: RpcContext,
    input: GetStateUpdateInput,
) -> Result<types::StateUpdate, GetStateUpdateError> {
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

            let state_update = (*state_update).clone();

            return Ok(state_update.into());
        }

        let block_id = input
            .block_id
            .try_into()
            .expect("Only pending cast should fail");

        get_state_update_from_storage(&tx, block_id)
    });

    jh.await.context("Database read panic or shutting down")?
}

fn get_state_update_from_storage(
    tx: &pathfinder_storage::Transaction<'_>,
    block: pathfinder_storage::BlockId,
) -> Result<types::StateUpdate, GetStateUpdateError> {
    let state_update = tx
        .state_update(block)
        .context("Fetching state diff")?
        .ok_or(GetStateUpdateError::BlockNotFound)?;

    Ok(state_update.into())
}

pub(crate) mod types {
    use pathfinder_common::state_update::ContractClassUpdate;
    use pathfinder_common::{
        BlockHash,
        CasmHash,
        ClassHash,
        ContractAddress,
        ContractNonce,
        SierraHash,
        StateCommitment,
        StorageAddress,
        StorageValue,
    };
    use serde::Serialize;
    use serde_with::skip_serializing_none;

    use crate::felt::{RpcFelt, RpcFelt251};

    #[serde_with::serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        /// None for `pending`
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub block_hash: Option<BlockHash>,
        /// None for `pending`
        #[serde(default)]
        #[serde_as(as = "Option<RpcFelt>")]
        pub new_root: Option<StateCommitment>,
        #[serde_as(as = "RpcFelt")]
        pub old_root: StateCommitment,
        pub state_diff: StateDiff,
    }

    #[cfg(test)]
    impl StateUpdate {
        // Sorts its vectors so that they can be equated.
        pub fn sort(&mut self) {
            self.state_diff
                .deployed_contracts
                .sort_by_key(|x| x.address);
            self.state_diff
                .declared_classes
                .sort_by_key(|x| x.class_hash);
            self.state_diff
                .replaced_classes
                .sort_by_key(|x| x.contract_address);
            self.state_diff.deprecated_declared_classes.sort();
            self.state_diff.nonces.sort_by_key(|x| x.contract_address);
            self.state_diff.storage_diffs.sort_by_key(|x| x.address);
            self.state_diff.storage_diffs.iter_mut().for_each(|x| {
                x.storage_entries.sort_by_key(|x| x.key);
            });
        }
    }

    impl From<pathfinder_common::StateUpdate> for StateUpdate {
        fn from(value: pathfinder_common::StateUpdate) -> Self {
            let mut storage_diffs = Vec::new();
            let mut deployed_contracts = Vec::new();
            let mut replaced_classes = Vec::new();
            let mut nonces = Vec::new();

            for (contract_address, update) in value.contract_updates {
                if let Some(nonce) = update.nonce {
                    nonces.push(Nonce {
                        contract_address,
                        nonce,
                    });
                }

                match update.class {
                    Some(ContractClassUpdate::Deploy(class_hash)) => {
                        deployed_contracts.push(DeployedContract {
                            address: contract_address,
                            class_hash,
                        })
                    }
                    Some(ContractClassUpdate::Replace(class_hash)) => {
                        replaced_classes.push(ReplacedClass {
                            contract_address,
                            class_hash,
                        })
                    }
                    None => {}
                }

                let storage_entries = update
                    .storage
                    .into_iter()
                    .map(|(key, value)| StorageEntry { key, value })
                    .collect();

                storage_diffs.push(StorageDiff {
                    address: contract_address,
                    storage_entries,
                });
            }

            for (address, update) in value.system_contract_updates {
                let storage_entries = update
                    .storage
                    .into_iter()
                    .map(|(key, value)| StorageEntry { key, value })
                    .collect();

                storage_diffs.push(StorageDiff {
                    address,
                    storage_entries,
                });
            }

            let declared_classes = value
                .declared_sierra_classes
                .into_iter()
                .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
                    class_hash,
                    compiled_class_hash,
                })
                .collect();

            let deprecated_declared_classes = value.declared_cairo_classes.into_iter().collect();

            let state_diff = StateDiff {
                storage_diffs,
                deprecated_declared_classes,
                declared_classes,
                deployed_contracts,
                replaced_classes,
                nonces,
            };

            let block_hash = match value.block_hash {
                BlockHash::ZERO => None,
                other => Some(other),
            };

            let new_root = match value.state_commitment {
                StateCommitment::ZERO => None,
                other => Some(other),
            };

            StateUpdate {
                block_hash,
                new_root,
                old_root: value.parent_state_commitment,
                state_diff,
            }
        }
    }

    /// L2 state diff.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq, Default)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub deprecated_declared_classes: Vec<ClassHash>,
        pub declared_classes: Vec<DeclaredSierraClass>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub replaced_classes: Vec<ReplacedClass>,
        pub nonces: Vec<Nonce>,
    }

    impl From<pathfinder_executor::types::StateDiff> for StateDiff {
        fn from(value: pathfinder_executor::types::StateDiff) -> Self {
            Self {
                storage_diffs: value
                    .storage_diffs
                    .into_iter()
                    .map(|(address, diff)| StorageDiff {
                        address,
                        storage_entries: diff.into_iter().map(Into::into).collect(),
                    })
                    .collect(),
                deprecated_declared_classes: value
                    .deprecated_declared_classes
                    .into_iter()
                    .collect(),
                declared_classes: value.declared_classes.into_iter().map(Into::into).collect(),
                deployed_contracts: value
                    .deployed_contracts
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                replaced_classes: value.replaced_classes.into_iter().map(Into::into).collect(),
                nonces: value
                    .nonces
                    .into_iter()
                    .map(|(contract_address, nonce)| Nonce {
                        contract_address,
                        nonce,
                    })
                    .collect(),
            }
        }
    }

    /// L2 storage diff of a contract.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        #[serde_as(as = "RpcFelt251")]
        pub address: ContractAddress,
        pub storage_entries: Vec<StorageEntry>,
    }

    /// A key-value entry of a storage diff.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageEntry {
        #[serde_as(as = "RpcFelt251")]
        pub key: StorageAddress,
        #[serde_as(as = "RpcFelt")]
        pub value: StorageValue,
    }

    impl From<starknet_gateway_types::reply::state_update::StorageDiff> for StorageEntry {
        fn from(d: starknet_gateway_types::reply::state_update::StorageDiff) -> Self {
            Self {
                key: d.key,
                value: d.value,
            }
        }
    }

    impl From<pathfinder_executor::types::StorageDiff> for StorageEntry {
        fn from(d: pathfinder_executor::types::StorageDiff) -> Self {
            Self {
                key: d.key,
                value: d.value,
            }
        }
    }

    /// L2 state diff declared Sierra class item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredSierraClass {
        #[serde_as(as = "RpcFelt")]
        pub class_hash: SierraHash,
        #[serde_as(as = "RpcFelt")]
        pub compiled_class_hash: CasmHash,
    }

    impl From<pathfinder_executor::types::DeclaredSierraClass> for DeclaredSierraClass {
        fn from(d: pathfinder_executor::types::DeclaredSierraClass) -> Self {
            Self {
                class_hash: d.class_hash,
                compiled_class_hash: d.compiled_class_hash,
            }
        }
    }

    /// L2 state diff deployed contract item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        #[serde_as(as = "RpcFelt251")]
        pub address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,
    }

    impl From<pathfinder_executor::types::DeployedContract> for DeployedContract {
        fn from(d: pathfinder_executor::types::DeployedContract) -> Self {
            Self {
                address: d.address,
                class_hash: d.class_hash,
            }
        }
    }

    /// L2 state diff replaced class item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct ReplacedClass {
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,
    }

    impl From<pathfinder_executor::types::ReplacedClass> for ReplacedClass {
        fn from(d: pathfinder_executor::types::ReplacedClass) -> Self {
            Self {
                contract_address: d.contract_address,
                class_hash: d.class_hash,
            }
        }
    }

    /// L2 state diff nonce item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct Nonce {
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub nonce: ContractNonce,
    }

    #[cfg(test)]
    mod tests {
        use pathfinder_common::macro_prelude::*;

        use super::*;

        #[test]
        fn receipt() {
            let state_update = StateUpdate {
                block_hash: Some(block_hash!("0xdeadbeef")),
                new_root: Some(state_commitment!("0x1")),
                old_root: state_commitment!("0x2"),
                state_diff: StateDiff {
                    storage_diffs: vec![StorageDiff {
                        address: contract_address!("0xadc"),
                        storage_entries: vec![StorageEntry {
                            key: storage_address!("0xf0"),
                            value: storage_value!("0x55"),
                        }],
                    }],
                    deprecated_declared_classes: vec![class_hash!("0xcdef"), class_hash!("0xcdee")],
                    declared_classes: vec![DeclaredSierraClass {
                        class_hash: sierra_hash!("0xabcd"),
                        compiled_class_hash: casm_hash!("0xdcba"),
                    }],
                    deployed_contracts: vec![DeployedContract {
                        address: contract_address!("0xadd"),
                        class_hash: class_hash!("0xcdef"),
                    }],
                    replaced_classes: vec![ReplacedClass {
                        contract_address: contract_address!("0xcad"),
                        class_hash: class_hash!("0xdac"),
                    }],
                    nonces: vec![Nonce {
                        contract_address: contract_address!("0xca"),
                        nonce: contract_nonce!("0x404ce"),
                    }],
                },
            };
            let data = vec![
                state_update.clone(),
                StateUpdate {
                    block_hash: None,
                    ..state_update
                },
            ];

            let fixture =
                include_str!("../../../fixtures/0.50.0/state_update.json").replace([' ', '\n'], "");

            pretty_assertions_sorted::assert_eq!(serde_json::to_string(&data).unwrap(), fixture);
            pretty_assertions_sorted::assert_eq!(
                serde_json::from_str::<Vec<StateUpdate>>(&fixture).unwrap(),
                data
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockNumber;
    use pathfinder_storage::fake::Block;
    use serde_json::json;

    use super::types::StateUpdate;
    use super::*;

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
        let input = serde_json::from_value::<GetStateUpdateInput>(input).unwrap();

        let expected = GetStateUpdateInput { block_id };

        assert_eq!(input, expected);
    }

    /// Add some dummy state updates to the context for testing
    fn context_with_state_updates() -> (Vec<types::StateUpdate>, RpcContext) {
        let storage = pathfinder_storage::StorageBuilder::in_memory().unwrap();

        let state_updates = pathfinder_storage::fake::with_n_blocks(&storage, 3)
            .into_iter()
            .map(|Block { state_update, .. }| state_update.into())
            .collect();

        let context = RpcContext::for_tests().with_storage(storage);

        (state_updates, context)
    }

    impl PartialEq for GetStateUpdateError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    /// Compares the sorted state updates.
    fn sort_assert_eq(mut left: StateUpdate, mut right: StateUpdate) {
        left.sort();
        right.sort();

        pretty_assertions_sorted::assert_eq!(left, right);
    }

    #[tokio::test]
    async fn latest() {
        let (mut in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            GetStateUpdateInput {
                block_id: BlockId::Latest,
            },
        )
        .await
        .unwrap();

        sort_assert_eq(result, in_storage.pop().unwrap());
    }

    #[tokio::test]
    async fn by_number() {
        let (in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            GetStateUpdateInput {
                block_id: BlockId::Number(BlockNumber::GENESIS),
            },
        )
        .await
        .unwrap();

        sort_assert_eq(result, in_storage[0].clone());
    }

    #[tokio::test]
    async fn by_hash() {
        let (in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            GetStateUpdateInput {
                block_id: BlockId::Hash(in_storage[1].block_hash.unwrap()),
            },
        )
        .await
        .unwrap();

        sort_assert_eq(result, in_storage[1].clone());
    }

    #[tokio::test]
    async fn not_found_by_number() {
        let (_in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            GetStateUpdateInput {
                block_id: BlockId::Number(BlockNumber::MAX),
            },
        )
        .await;

        assert_eq!(result, Err(GetStateUpdateError::BlockNotFound));
    }

    #[tokio::test]
    async fn not_found_by_hash() {
        let (_in_storage, ctx) = context_with_state_updates();

        let result = get_state_update(
            ctx,
            GetStateUpdateInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"non-existent")),
            },
        )
        .await;

        assert_eq!(result, Err(GetStateUpdateError::BlockNotFound));
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetStateUpdateInput {
            block_id: BlockId::Pending,
        };

        let expected = context.pending_data.get_unchecked().state_update;
        let expected = (*expected).clone().into();

        let result = get_state_update(context, input).await.unwrap();

        sort_assert_eq(result, expected);
    }
}
