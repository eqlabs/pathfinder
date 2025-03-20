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

impl dto::SerializeForVersion for Output {
    fn serialize(&self, serializer: dto::Serializer) -> Result<dto::Ok, dto::Error> {
        match self {
            Output::Full(full) => dto::StateUpdate(full).serialize(serializer),
            Output::Pending(pending) => dto::PendingStateUpdate(pending).serialize(serializer),
        }
    }
}

pub async fn get_state_update(context: RpcContext, input: Input) -> Result<Output, Error> {
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
                .get(&tx)
                .context("Query pending data")?
                .state_update;

            return Ok(Output::Pending(state_update));
        }

        let block_id = input
            .block_id
            .try_into()
            .expect("Only pending cast should fail");

        let pruned = tx
            .block_pruned(block_id)
            .context("Querying block pruned status")?;
        if pruned {
            return Err(Error::BlockNotFound);
        }

        let state_update = tx
            .state_update(block_id)
            .context("Fetching state diff")?
            .ok_or(Error::BlockNotFound)?;

        Ok(Output::Full(Box::new(state_update)))
    });

    jh.await.context("Database read panic or shutting down")?
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
    #[cfg(test)]
    use serde_with::serde_as;

    use crate::felt::{RpcFelt, RpcFelt251};

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct StateUpdate {
        /// None for `pending`
        pub block_hash: Option<BlockHash>,
        /// None for `pending`
        pub new_root: Option<StateCommitment>,
        pub old_root: StateCommitment,
        pub state_diff: StateDiff,
    }

    impl crate::dto::SerializeForVersion for StateUpdate {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;
            if let Some(block_hash) = self.block_hash {
                serializer.serialize_field("block_hash", &RpcFelt(block_hash.0))?;
            }
            if let Some(new_root) = self.new_root {
                serializer.serialize_field("new_root", &RpcFelt(new_root.0))?;
            }
            serializer.serialize_field("old_root", &RpcFelt(self.old_root.0))?;
            serializer.serialize_field("state_diff", &self.state_diff)?;
            serializer.end()
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
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
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

    impl crate::dto::SerializeForVersion for StateDiff {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_iter(
                "storage_diffs",
                self.storage_diffs.len(),
                &mut self.storage_diffs.clone().into_iter(),
            )?;
            serializer.serialize_iter(
                "deprecated_declared_classes",
                self.deprecated_declared_classes.len(),
                &mut self
                    .deprecated_declared_classes
                    .clone()
                    .into_iter()
                    .map(|x| RpcFelt(x.0)),
            )?;
            serializer.serialize_iter(
                "declared_classes",
                self.declared_classes.len(),
                &mut self.declared_classes.clone().into_iter(),
            )?;
            serializer.serialize_iter(
                "deployed_contracts",
                self.deployed_contracts.len(),
                &mut self.deployed_contracts.clone().into_iter(),
            )?;
            serializer.serialize_iter(
                "replaced_classes",
                self.replaced_classes.len(),
                &mut self.replaced_classes.clone().into_iter(),
            )?;
            serializer.serialize_iter(
                "nonces",
                self.nonces.len(),
                &mut self.nonces.clone().into_iter(),
            )?;

            serializer.end()
        }
    }

    /// L2 storage diff of a contract.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    #[cfg_attr(test, serde(deny_unknown_fields))]
    pub struct StorageDiff {
        #[cfg_attr(test, serde_as(as = "RpcFelt251"))]
        pub address: ContractAddress,
        pub storage_entries: Vec<StorageEntry>,
    }

    impl crate::dto::SerializeForVersion for StorageDiff {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("address", &RpcFelt251(RpcFelt(self.address.0)))?;
            serializer.serialize_iter(
                "storage_entries",
                self.storage_entries.len(),
                &mut self.storage_entries.clone().into_iter(),
            )?;

            serializer.end()
        }
    }

    /// A key-value entry of a storage diff.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct StorageEntry {
        #[cfg_attr(test, serde_as(as = "RpcFelt251"))]
        pub key: StorageAddress,
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
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

    impl crate::dto::SerializeForVersion for StorageEntry {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("key", &RpcFelt(self.key.0))?;
            serializer.serialize_field("value", &RpcFelt(self.value.0))?;

            serializer.end()
        }
    }

    /// L2 state diff declared Sierra class item.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct DeclaredSierraClass {
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
        pub class_hash: SierraHash,
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
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

    impl crate::dto::SerializeForVersion for DeclaredSierraClass {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("class_hash", &RpcFelt(self.class_hash.0))?;
            serializer
                .serialize_field("compiled_class_hash", &RpcFelt(self.compiled_class_hash.0))?;

            serializer.end()
        }
    }

    /// L2 state diff deployed contract item.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct DeployedContract {
        #[cfg_attr(test, serde_as(as = "RpcFelt251"))]
        pub address: ContractAddress,
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
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

    impl crate::dto::SerializeForVersion for DeployedContract {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("address", &RpcFelt(self.address.0))?;
            serializer.serialize_field("class_hash", &RpcFelt(self.class_hash.0))?;

            serializer.end()
        }
    }

    /// L2 state diff replaced class item.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct ReplacedClass {
        #[cfg_attr(test, serde_as(as = "RpcFelt251"))]
        pub contract_address: ContractAddress,
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
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

    impl crate::dto::SerializeForVersion for ReplacedClass {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("contract_address", &RpcFelt(self.contract_address.0))?;
            serializer.serialize_field("class_hash", &RpcFelt(self.class_hash.0))?;

            serializer.end()
        }
    }

    /// L2 state diff nonce item.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(test, serde_as)]
    #[cfg_attr(test, derive(serde::Deserialize))]
    pub struct Nonce {
        #[cfg_attr(test, serde_as(as = "RpcFelt251"))]
        pub contract_address: ContractAddress,
        #[cfg_attr(test, serde_as(as = "RpcFelt"))]
        pub nonce: ContractNonce,
    }

    impl crate::dto::SerializeForVersion for Nonce {
        fn serialize(
            &self,
            serializer: crate::dto::Serializer,
        ) -> Result<crate::dto::Ok, crate::dto::Error> {
            let mut serializer = serializer.serialize_struct()?;

            serializer.serialize_field("contract_address", &RpcFelt(self.contract_address.0))?;
            serializer.serialize_field("nonce", &RpcFelt(self.nonce.0))?;

            serializer.end()
        }
    }

    #[cfg(test)]
    mod tests {
        use pathfinder_common::macro_prelude::*;

        use super::*;
        use crate::RpcVersion;

        #[test]
        fn state_update() {
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
                // a pending update
                StateUpdate {
                    block_hash: None,
                    new_root: None,
                    ..state_update
                },
            ];

            let fixture =
                include_str!("../../fixtures/0.50.0/state_update.json").replace([' ', '\n'], "");

            let fixture_pretty = serde_json::to_string_pretty(
                &serde_json::from_str::<serde_json::Value>(&fixture).unwrap(),
            )
            .unwrap();

            let serializer = crate::dto::Serializer::new(RpcVersion::V07);
            let serialized = serde_json::to_string_pretty(
                &serializer
                    .serialize_iter(data.len(), &mut data.clone().into_iter())
                    .unwrap(),
            )
            .unwrap();

            pretty_assertions_sorted::assert_eq!(serialized, fixture_pretty);
            pretty_assertions_sorted::assert_eq!(
                serde_json::from_str::<Vec<StateUpdate>>(&fixture).unwrap(),
                data
            );
        }
    }
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
