use crate::rpc::v02::RpcContext;
use crate::storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetStateUpdatesTable};
use anyhow::{anyhow, Context};
use pathfinder_common::BlockId;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetStateUpdateInput {
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetStateUpdateError: BlockNotFound);

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
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        let block_hash = match block_id {
            StarknetBlocksBlockId::Hash(h) => h,
            StarknetBlocksBlockId::Number(_) | StarknetBlocksBlockId::Latest => {
                StarknetBlocksTable::get_hash(
                    &tx,
                    block_id.try_into().expect("block_id is not a hash"),
                )
                .context("Read block from database")?
                .ok_or(GetStateUpdateError::BlockNotFound)?
            }
        };

        let state_update = StarknetStateUpdatesTable::get(&tx, block_hash)
            .context("Read state update from database")?
            .ok_or(GetStateUpdateError::BlockNotFound)?;

        Ok(state_update.into())
    });

    jh.await.context("Database read panic or shutting down")?
}

mod types {
    use pathfinder_common::{
        ClassHash, ContractAddress, ContractNonce, GlobalRoot, StarknetBlockHash, StorageAddress,
        StorageValue,
    };
    use serde::Serialize;
    use serde_with::skip_serializing_none;
    use std::collections::HashMap;

    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        /// None for `pending`
        #[serde(default)]
        pub block_hash: Option<StarknetBlockHash>,
        pub new_root: GlobalRoot,
        pub old_root: GlobalRoot,
        pub state_diff: StateDiff,
    }

    impl From<crate::sequencer::reply::StateUpdate> for StateUpdate {
        fn from(x: crate::sequencer::reply::StateUpdate) -> Self {
            Self {
                block_hash: x.block_hash,
                new_root: x.new_root,
                old_root: x.old_root,
                state_diff: x.state_diff.into(),
            }
        }
    }

    impl From<crate::rpc::v01::types::reply::StateUpdate> for StateUpdate {
        fn from(x: crate::rpc::v01::types::reply::StateUpdate) -> Self {
            Self {
                block_hash: x.block_hash,
                new_root: x.new_root,
                old_root: x.old_root,
                state_diff: x.state_diff.into(),
            }
        }
    }

    /// L2 state diff.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        pub declared_contract_hashes: Vec<ClassHash>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub nonces: Vec<Nonce>,
    }

    impl From<crate::sequencer::reply::state_update::StateDiff> for StateDiff {
        fn from(state_diff: crate::sequencer::reply::state_update::StateDiff) -> Self {
            let storage_diffs: Vec<StorageDiff> = state_diff
                .storage_diffs
                .into_iter()
                .map(|(address, storage_diffs)| StorageDiff {
                    address,
                    storage_entries: storage_diffs.into_iter().map(StorageEntry::from).collect(),
                })
                .collect();
            Self {
                storage_diffs,
                declared_contract_hashes: state_diff.declared_contracts,
                deployed_contracts: state_diff
                    .deployed_contracts
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                nonces: state_diff
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

    /// Convert from the v0.1.0 representation we have in the storage to the new one.
    ///
    /// We need this conversion because the representation of storage diffs have changed
    /// in v0.2.0 of the JSON-RPC specification and we're storing v0.1.0 formatted JSONs
    /// in our storage.
    /// Storage updates are now grouped per-contract and individual update entries no
    /// longer contain the contract address.
    impl From<crate::rpc::v01::types::reply::state_update::StateDiff> for StateDiff {
        fn from(diff: crate::rpc::v01::types::reply::state_update::StateDiff) -> Self {
            let mut per_contract_diff: HashMap<ContractAddress, Vec<StorageEntry>> = HashMap::new();
            for storage_diff in diff.storage_diffs {
                per_contract_diff
                    .entry(storage_diff.address)
                    .and_modify(|entries| {
                        entries.push(StorageEntry {
                            key: storage_diff.key,
                            value: storage_diff.value,
                        })
                    })
                    .or_insert_with(|| {
                        vec![StorageEntry {
                            key: storage_diff.key,
                            value: storage_diff.value,
                        }]
                    });
            }
            let storage_diffs: Vec<StorageDiff> = per_contract_diff
                .into_iter()
                .map(|(address, storage_entries)| StorageDiff {
                    address,
                    storage_entries,
                })
                .collect();
            Self {
                storage_diffs,
                declared_contract_hashes: diff
                    .declared_contracts
                    .into_iter()
                    .map(|d| d.class_hash)
                    .collect(),
                deployed_contracts: diff
                    .deployed_contracts
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                nonces: diff.nonces.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// L2 storage diff of a contract.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub address: ContractAddress,
        pub storage_entries: Vec<StorageEntry>,
    }

    /// A key-value entry of a storage diff.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StorageEntry {
        pub key: StorageAddress,
        pub value: StorageValue,
    }

    impl From<crate::sequencer::reply::state_update::StorageDiff> for StorageEntry {
        fn from(diff: crate::sequencer::reply::state_update::StorageDiff) -> Self {
            Self {
                key: diff.key,
                value: diff.value,
            }
        }
    }

    /// L2 state diff deployed contract item.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        pub address: ContractAddress,
        pub class_hash: ClassHash,
    }

    impl From<crate::sequencer::reply::state_update::DeployedContract> for DeployedContract {
        fn from(d: crate::sequencer::reply::state_update::DeployedContract) -> Self {
            Self {
                address: d.address,
                class_hash: d.class_hash,
            }
        }
    }

    impl From<crate::rpc::v01::types::reply::state_update::DeployedContract> for DeployedContract {
        fn from(c: crate::rpc::v01::types::reply::state_update::DeployedContract) -> Self {
            Self {
                address: c.address,
                class_hash: c.class_hash,
            }
        }
    }

    /// L2 state diff nonce item.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct Nonce {
        pub contract_address: ContractAddress,
        pub nonce: ContractNonce,
    }

    impl From<crate::rpc::v01::types::reply::state_update::Nonce> for Nonce {
        fn from(n: crate::rpc::v01::types::reply::state_update::Nonce) -> Self {
            Self {
                contract_address: n.contract_address,
                nonce: n.nonce,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pathfinder_common::starkhash;

        #[test]
        fn receipt() {
            let state_update = StateUpdate {
                block_hash: Some(StarknetBlockHash(starkhash!("deadbeef"))),
                new_root: GlobalRoot(starkhash!("01")),
                old_root: GlobalRoot(starkhash!("02")),
                state_diff: StateDiff {
                    storage_diffs: vec![StorageDiff {
                        address: ContractAddress::new_or_panic(starkhash!("0adc")),
                        storage_entries: vec![StorageEntry {
                            key: StorageAddress::new_or_panic(starkhash!("f0")),
                            value: StorageValue(starkhash!("55")),
                        }],
                    }],
                    declared_contract_hashes: vec![
                        ClassHash(starkhash!("cdef")),
                        ClassHash(starkhash!("cdee")),
                    ],
                    deployed_contracts: vec![DeployedContract {
                        address: ContractAddress::new_or_panic(starkhash!("0add")),
                        class_hash: ClassHash(starkhash!("cdef")),
                    }],
                    nonces: vec![Nonce {
                        contract_address: ContractAddress::new_or_panic(starkhash!("ca")),
                        nonce: ContractNonce(starkhash!("0404ce")),
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

            let fixture = include_str!("../../../../fixtures/rpc/0.44.0/state_update.json")
                .replace([' ', '\n'], "");

            assert_eq!(serde_json::to_string(&data).unwrap(), fixture);
            assert_eq!(
                serde_json::from_str::<Vec<StateUpdate>>(&fixture).unwrap(),
                data
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::types::{DeployedContract, StateDiff, StateUpdate, StorageDiff, StorageEntry};
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;
    use pathfinder_common::{starkhash, starkhash_bytes};
    use pathfinder_common::{
        Chain, ClassHash, ContractAddress, GlobalRoot, StarknetBlockHash, StarknetBlockNumber,
        StorageAddress, StorageValue,
    };
    use stark_hash::StarkHash;

    #[test]
    fn parsing() {
        let number = BlockId::Number(StarknetBlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(StarknetBlockHash(starkhash!("beef")));

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
        let storage = crate::storage::Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let state_updates = crate::storage::fixtures::init::with_n_state_updates(&tx, 3);
        tx.commit().unwrap();

        let sync_state = std::sync::Arc::new(crate::state::SyncState::default());
        let chain = Chain::Testnet;
        let sequencer = crate::sequencer::Client::new(chain).unwrap();
        let context = RpcContext::new(storage, sync_state, chain, sequencer);
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
        let ctx_with_pending_empty = ctx
            .clone()
            .with_pending_data(crate::state::PendingData::default());

        let cases: &[(RpcContext, BlockId, TestCaseHandler)] = &[
            // Successful
            (
                ctx.clone(),
                BlockId::Latest,
                assert_ok(in_storage[2].clone()),
            ),
            (
                ctx.clone(),
                BlockId::Number(StarknetBlockNumber::GENESIS),
                assert_ok(in_storage[0].clone()),
            ),
            (
                ctx.clone(),
                // The fixture happens to init this to zero for genesis block
                BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)),
                assert_ok(in_storage[0].clone()),
            ),
            // Errors
            (
                ctx.clone(),
                BlockId::Number(StarknetBlockNumber::new_or_panic(9999)),
                assert_error(GetStateUpdateError::BlockNotFound),
            ),
            (
                ctx.clone(),
                BlockId::Hash(StarknetBlockHash(pathfinder_common::starkhash_bytes!(
                    b"non-existent"
                ))),
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
            new_root: GlobalRoot(starkhash!(
                "06df64b357468b371e8a81e438914cd3a5fe4a6b693129149c382aa3d03f9674"
            )),
            old_root: GlobalRoot(starkhash!(
                "0300e3d0ce5f0da1a086ab49734bab6f302efbf544b56226b7db665716b621c8"
            )),
            state_diff: StateDiff {
                storage_diffs: vec![StorageDiff {
                    address: ContractAddress::new_or_panic(starkhash_bytes!(
                        b"pending contract 1 address"
                    )),
                    storage_entries: vec![
                        StorageEntry {
                            key: StorageAddress::new_or_panic(starkhash_bytes!(
                                b"pending storage key 0"
                            )),
                            value: StorageValue(starkhash_bytes!(b"pending storage value 0")),
                        },
                        StorageEntry {
                            key: StorageAddress::new_or_panic(starkhash_bytes!(
                                b"pending storage key 1"
                            )),
                            value: StorageValue(starkhash_bytes!(b"pending storage value 1")),
                        },
                    ],
                }],
                declared_contract_hashes: vec![],
                deployed_contracts: vec![
                    DeployedContract {
                        address: ContractAddress::new_or_panic(starkhash_bytes!(
                            b"pending contract 0 address"
                        )),
                        class_hash: ClassHash(starkhash_bytes!(b"pending contract 0 hash")),
                    },
                    DeployedContract {
                        address: ContractAddress::new_or_panic(starkhash_bytes!(
                            b"pending contract 1 address"
                        )),
                        class_hash: ClassHash(starkhash_bytes!(b"pending contract 1 hash")),
                    },
                ],
                nonces: vec![],
            },
        };
        assert_eq!(result, expected);
    }
}
