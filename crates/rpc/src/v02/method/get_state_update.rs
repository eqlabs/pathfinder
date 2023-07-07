use crate::context::RpcContext;
use anyhow::{anyhow, Context};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetStateUpdateInput {
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(GetStateUpdateError: BlockNotFound);

pub async fn get_state_update(
    context: RpcContext,
    input: GetStateUpdateInput,
) -> Result<types::StateUpdate, GetStateUpdateError> {
    let block_id = match input.block_id {
        BlockId::Pending => {
            match &context
                .pending_data
                .ok_or_else(|| anyhow!("Pending data not supported in this configuration"))?
                .state_update()
                .await
            {
                Some(update) => {
                    let update = update.as_ref().clone().into();
                    return Ok(update);
                }
                None => return Err(GetStateUpdateError::BlockNotFound),
            }
        }
        other => other.try_into().expect("Only pending cast should fail"),
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

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

mod types {
    use crate::felt::{RpcFelt, RpcFelt251};
    use pathfinder_common::state_update::ContractClassUpdate;
    use pathfinder_common::{
        BlockHash, ClassHash, ContractAddress, ContractNonce, StateCommitment, StorageAddress,
        StorageValue,
    };
    use serde::Serialize;
    use serde_with::skip_serializing_none;

    #[serde_with::serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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
            self.state_diff.declared_contract_hashes.sort();
            self.state_diff.nonces.sort_by_key(|x| x.contract_address);
            self.state_diff.storage_diffs.sort_by_key(|x| x.address);
        }
    }

    impl From<pathfinder_common::StateUpdate> for StateUpdate {
        fn from(value: pathfinder_common::StateUpdate) -> Self {
            let mut storage_diffs = Vec::new();
            let mut deployed_contracts = Vec::new();
            let mut nonces = Vec::new();

            for (contract_address, update) in value.contract_updates {
                if let Some(nonce) = update.nonce {
                    nonces.push(Nonce {
                        contract_address,
                        nonce,
                    });
                }

                if let Some(ContractClassUpdate::Deploy(class_hash)) = update.class {
                    deployed_contracts.push(DeployedContract {
                        address: contract_address,
                        class_hash,
                    });
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

            let declared_contract_hashes = value
                .declared_sierra_classes
                .into_keys()
                .map(|class_hash| ClassHash(class_hash.0))
                .chain(value.declared_cairo_classes.iter().copied())
                .collect();

            let state_diff = StateDiff {
                storage_diffs,
                declared_contract_hashes,
                deployed_contracts,
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
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub declared_contract_hashes: Vec<ClassHash>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub nonces: Vec<Nonce>,
    }

    /// L2 storage diff of a contract.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        #[serde_as(as = "RpcFelt251")]
        pub address: ContractAddress,
        pub storage_entries: Vec<StorageEntry>,
    }

    /// A key-value entry of a storage diff.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageEntry {
        #[serde_as(as = "RpcFelt251")]
        pub key: StorageAddress,
        #[serde_as(as = "RpcFelt")]
        pub value: StorageValue,
    }

    impl From<starknet_gateway_types::reply::state_update::StorageDiff> for StorageEntry {
        fn from(diff: starknet_gateway_types::reply::state_update::StorageDiff) -> Self {
            Self {
                key: diff.key,
                value: diff.value,
            }
        }
    }

    /// L2 state diff deployed contract item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        #[serde_as(as = "RpcFelt251")]
        pub address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,
    }

    /// L2 state diff nonce item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct Nonce {
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub nonce: ContractNonce,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use pathfinder_common::macro_prelude::*;

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
                    declared_contract_hashes: vec![class_hash!("0xcdef"), class_hash!("0xcdee")],
                    deployed_contracts: vec![DeployedContract {
                        address: contract_address!("0xadd"),
                        class_hash: class_hash!("0xcdef"),
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
                include_str!("../../../fixtures/0.44.0/state_update.json").replace([' ', '\n'], "");

            pretty_assertions::assert_eq!(serde_json::to_string(&data).unwrap(), fixture);
            pretty_assertions::assert_eq!(
                serde_json::from_str::<Vec<StateUpdate>>(&fixture).unwrap(),
                data
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::types::StateUpdate;
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockNumber, Chain};
    use starknet_gateway_types::pending::PendingData;

    #[test]
    fn parsing() {
        let number = BlockId::Number(BlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(block_hash!("0xbeef"));

        [
            (r#"["pending"]"#, BlockId::Pending),
            (r#"{"block_id": "pending"}"#, BlockId::Pending),
            (r#"["latest"]"#, BlockId::Latest),
            (r#"{"block_id": "latest"}"#, BlockId::Latest),
            (r#"[{"block_number":123}]"#, number),
            (r#"{"block_id": {"block_number":123}}"#, number),
            (r#"[{"block_hash": "0xbeef"}]"#, hash),
            (r#"{"block_id": {"block_hash": "0xbeef"}}"#, hash),
        ]
        .into_iter()
        .enumerate()
        .for_each(|(i, (input, expected))| {
            let actual = Params::new(Some(input))
                .parse::<GetStateUpdateInput>()
                .unwrap_or_else(|error| panic!("test case {i}: {input}, {error}"));
            assert_eq!(
                actual,
                GetStateUpdateInput { block_id: expected },
                "test case {i}: {input}"
            );
        });
    }

    type TestCaseHandler = Box<dyn Fn(usize, &Result<types::StateUpdate, GetStateUpdateError>)>;

    /// Add some dummy state updates to the context for testing
    fn context_with_state_updates() -> (Vec<types::StateUpdate>, RpcContext) {
        use pathfinder_common::ChainId;

        let storage = pathfinder_storage::Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let state_updates = pathfinder_storage::test_fixtures::init::with_n_state_updates(&tx, 3);
        tx.commit().unwrap();

        let sync_state = std::sync::Arc::new(crate::SyncState::default());
        let sequencer = starknet_gateway_client::Client::new(Chain::Testnet).unwrap();
        let context = RpcContext::new(storage, sync_state, ChainId::TESTNET, sequencer);
        let state_updates = state_updates.into_iter().map(Into::into).collect();

        (state_updates, context)
    }

    /// Execute a single test case and check its outcome.
    async fn check(test_case_idx: usize, test_case: &(RpcContext, BlockId, TestCaseHandler)) {
        let (context, block_id, f) = test_case;
        let mut result = get_state_update(
            context.clone(),
            GetStateUpdateInput {
                block_id: *block_id,
            },
        )
        .await;
        if let Ok(r) = result.as_mut() {
            r.sort();
        }
        f(test_case_idx, &result);
    }

    /// Common assertion type for most of the test cases
    fn assert_ok(mut expected: types::StateUpdate) -> TestCaseHandler {
        expected.sort();
        use pretty_assertions::assert_eq;
        Box::new(move |i: usize, result| {
            assert_matches!(result, Ok(actual) => assert_eq!(
                *actual,
                expected,
                "test case {i}"
            ), "test case {i}");
        })
    }

    impl PartialEq for GetStateUpdateError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    /// Common assertion type for most of the error paths
    fn assert_error(expected: GetStateUpdateError) -> TestCaseHandler {
        Box::new(move |i: usize, result| {
            assert_matches!(result, Err(error) => assert_eq!(*error, expected, "test case {i}"), "test case {i}");
        })
    }

    #[tokio::test]
    async fn happy_paths_and_major_errors() {
        let (in_storage, ctx) = context_with_state_updates();
        let ctx_with_pending_empty = ctx.clone().with_pending_data(PendingData::default());

        let cases: &[(RpcContext, BlockId, TestCaseHandler)] = &[
            // Successful
            (
                ctx.clone(),
                BlockId::Latest,
                assert_ok(in_storage[2].clone()),
            ),
            (
                ctx.clone(),
                BlockId::Number(BlockNumber::GENESIS),
                assert_ok(in_storage[0].clone()),
            ),
            (
                ctx.clone(),
                BlockId::Hash(in_storage[0].block_hash.unwrap()),
                assert_ok(in_storage[0].clone()),
            ),
            // Errors
            (
                ctx.clone(),
                BlockId::Number(BlockNumber::new_or_panic(9999)),
                assert_error(GetStateUpdateError::BlockNotFound),
            ),
            (
                ctx.clone(),
                BlockId::Hash(block_hash_bytes!(b"non-existent")),
                assert_error(GetStateUpdateError::BlockNotFound),
            ),
            (
                // Pending is disabled for this context
                ctx,
                BlockId::Pending,
                assert_error(GetStateUpdateError::Internal(anyhow!(
                    "Pending data not supported in this configuration"
                ))),
            ),
            (
                ctx_with_pending_empty,
                BlockId::Pending,
                assert_error(GetStateUpdateError::BlockNotFound),
            ),
        ];

        for (i, test_case) in cases.iter().enumerate() {
            check(i, test_case).await;
        }
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;
        let input = GetStateUpdateInput {
            block_id: BlockId::Pending,
        };

        let expected: StateUpdate = context
            .pending_data
            .as_ref()
            .unwrap()
            .state_update()
            .await
            .unwrap()
            .as_ref()
            .to_owned()
            .into();

        let result = get_state_update(context, input).await.unwrap();

        pretty_assertions::assert_eq!(result, expected);
    }
}
