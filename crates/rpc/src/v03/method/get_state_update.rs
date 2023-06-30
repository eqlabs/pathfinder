use crate::RpcContext;
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
    use pathfinder_common::{
        BlockHash, CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash,
        StateCommitment, StorageAddress, StorageValue,
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

    impl From<pathfinder_common::StateUpdate> for StateUpdate {
        fn from(_value: pathfinder_common::StateUpdate) -> Self {
            todo!()
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
        pub deprecated_declared_classes: Vec<ClassHash>,
        pub declared_classes: Vec<DeclaredSierraClass>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub replaced_classes: Vec<ReplacedClass>,
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

    /// L2 state diff declared Sierra class item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredSierraClass {
        #[serde_as(as = "RpcFelt")]
        pub class_hash: SierraHash,
        #[serde_as(as = "RpcFelt")]
        pub compiled_class_hash: CasmHash,
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

    /// L2 state diff replaced class item.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct ReplacedClass {
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
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
        use pathfinder_common::felt;

        #[test]
        fn receipt() {
            let state_update = StateUpdate {
                block_hash: Some(BlockHash(felt!("0xdeadbeef"))),
                new_root: Some(StateCommitment(felt!("0x1"))),
                old_root: StateCommitment(felt!("0x2")),
                state_diff: StateDiff {
                    storage_diffs: vec![StorageDiff {
                        address: ContractAddress::new_or_panic(felt!("0xadc")),
                        storage_entries: vec![StorageEntry {
                            key: StorageAddress::new_or_panic(felt!("0xf0")),
                            value: StorageValue(felt!("0x55")),
                        }],
                    }],
                    deprecated_declared_classes: vec![
                        ClassHash(felt!("0xcdef")),
                        ClassHash(felt!("0xcdee")),
                    ],
                    declared_classes: vec![DeclaredSierraClass {
                        class_hash: SierraHash(felt!("0xabcd")),
                        compiled_class_hash: CasmHash(felt!("0xdcba")),
                    }],
                    deployed_contracts: vec![DeployedContract {
                        address: ContractAddress::new_or_panic(felt!("0xadd")),
                        class_hash: ClassHash(felt!("0xcdef")),
                    }],
                    replaced_classes: vec![ReplacedClass {
                        contract_address: ContractAddress::new_or_panic(felt!("0xcad")),
                        class_hash: ClassHash(felt!("0xdac")),
                    }],
                    nonces: vec![Nonce {
                        contract_address: ContractAddress::new_or_panic(felt!("0xca")),
                        nonce: ContractNonce(felt!("0x404ce")),
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
    use super::types::{
        DeployedContract, ReplacedClass, StateDiff, StateUpdate, StorageDiff, StorageEntry,
    };
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;
    use pathfinder_common::{felt, felt_bytes};
    use pathfinder_common::{
        BlockHash, BlockNumber, Chain, ClassHash, ContractAddress, StateCommitment, StorageAddress,
        StorageValue,
    };
    use starknet_gateway_types::pending::PendingData;

    #[test]
    fn parsing() {
        let number = BlockId::Number(BlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(BlockHash(felt!("0xbeef")));

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
        let result = get_state_update(
            context.clone(),
            GetStateUpdateInput {
                block_id: *block_id,
            },
        )
        .await;
        f(test_case_idx, &result);
    }

    /// Common assertion type for most of the test cases
    fn assert_ok(expected: types::StateUpdate) -> TestCaseHandler {
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
                BlockId::Hash(BlockHash(pathfinder_common::felt_bytes!(b"non-existent"))),
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

        let result = get_state_update(context, input).await.unwrap();

        let expected = StateUpdate {
            block_hash: None,
            new_root: None,
            old_root: StateCommitment(felt!(
                "0x057B695C82AF81429FDC8966088B0196105DFB5AA22B54CBC86FC95DC3B3ECE1"
            )),
            state_diff: StateDiff {
                storage_diffs: vec![StorageDiff {
                    address: ContractAddress::new_or_panic(felt_bytes!(
                        b"pending contract 1 address"
                    )),
                    storage_entries: vec![
                        StorageEntry {
                            key: StorageAddress::new_or_panic(felt_bytes!(
                                b"pending storage key 0"
                            )),
                            value: StorageValue(felt_bytes!(b"pending storage value 0")),
                        },
                        StorageEntry {
                            key: StorageAddress::new_or_panic(felt_bytes!(
                                b"pending storage key 1"
                            )),
                            value: StorageValue(felt_bytes!(b"pending storage value 1")),
                        },
                    ],
                }],
                deprecated_declared_classes: vec![],
                declared_classes: vec![],
                deployed_contracts: vec![
                    DeployedContract {
                        address: ContractAddress::new_or_panic(felt_bytes!(
                            b"pending contract 0 address"
                        )),
                        class_hash: ClassHash(felt_bytes!(b"pending class 0 hash")),
                    },
                    DeployedContract {
                        address: ContractAddress::new_or_panic(felt_bytes!(
                            b"pending contract 1 address"
                        )),
                        class_hash: ClassHash(felt_bytes!(b"pending class 1 hash")),
                    },
                ],
                replaced_classes: vec![ReplacedClass {
                    contract_address: ContractAddress::new_or_panic(felt_bytes!(
                        b"pending contract 2 (replaced)"
                    )),
                    class_hash: ClassHash(felt_bytes!(b"pending class 2 hash (replaced)")),
                }],
                nonces: vec![],
            },
        };
        pretty_assertions::assert_eq!(result, expected);
    }
}
