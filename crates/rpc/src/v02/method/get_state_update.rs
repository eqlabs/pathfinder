use std::collections::HashMap;

use crate::context::RpcContext;
use anyhow::{anyhow, Context};
use pathfinder_common::{
    BlockHash, BlockId, BlockNumber, ClassHash, ContractAddress, StateCommitment, StorageAddress,
    StorageValue,
};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable};
use stark_hash::Felt;

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

        get_state_update_from_storage(&tx, block_id)
    });

    jh.await.context("Database read panic or shutting down")?
}

pub(crate) fn block_info(
    tx: &rusqlite::Transaction<'_>,
    block: StarknetBlocksBlockId,
) -> anyhow::Result<Option<(BlockNumber, BlockHash, StateCommitment, StateCommitment)>> {
    let block = StarknetBlocksTable::get(tx, block)?;
    Ok(match block {
        None => None,
        Some(block) => {
            let old_root = if block.number == BlockNumber::GENESIS {
                Some(StateCommitment(Felt::ZERO))
            } else {
                let previous_block_number = BlockNumber::new_or_panic(block.number.get() - 1);
                StarknetBlocksTable::get(tx, StarknetBlocksBlockId::Number(previous_block_number))?
                    .map(|b| b.state_commmitment)
            };

            old_root.map(|old_root| (block.number, block.hash, block.state_commmitment, old_root))
        }
    })
}

fn get_state_update_from_storage(
    tx: &rusqlite::Transaction<'_>,
    block: StarknetBlocksBlockId,
) -> Result<types::StateUpdate, GetStateUpdateError> {
    let (number, block_hash, new_root, old_root) =
        block_info(tx, block)?.ok_or(GetStateUpdateError::BlockNotFound)?;

    let mut stmt = tx
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;
    let nonces = stmt
        .query_map([number], |row| {
            let contract_address = row.get(0)?;
            let nonce = row.get(1)?;

            Ok(types::Nonce {
                contract_address,
                nonce,
            })
        })
        .context("Querying nonce updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over nonce query rows")?;

    let mut stmt = tx
        .prepare_cached(
            "SELECT contract_address, storage_address, storage_value FROM storage_updates WHERE block_number = ?"
        )
        .context("Preparing storage update query statement")?;
    let storage_tuples = stmt
        .query_map([number], |row| {
            let contract_address: ContractAddress = row.get(0)?;
            let storage_address: StorageAddress = row.get(1)?;
            let storage_value: StorageValue = row.get(2)?;

            Ok((contract_address, storage_address, storage_value))
        })
        .context("Querying storage updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over storage query rows")?;
    // Convert storage tuples to contract based mapping.
    let mut storage_updates: HashMap<ContractAddress, Vec<types::StorageEntry>> = HashMap::new();
    for (addr, key, value) in storage_tuples {
        storage_updates
            .entry(addr)
            .or_default()
            .push(types::StorageEntry { key, value });
    }
    let storage_diffs = storage_updates
        .into_iter()
        .map(|(address, storage_entries)| types::StorageDiff {
            address,
            storage_entries,
        })
        .collect();

    let mut stmt = tx
        .prepare_cached("SELECT hash FROM class_definitions WHERE block_number = ?")
        .context("Preparing class declaration query statement")?;
    // This is a change from previous implementation as this also includes sierra hashes..
    // which is probably more correct?
    let declared_contract_hashes = stmt
        .query_map([number], |row| row.get(0))
        .context("Querying class declarations")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over class declaration query rows")?;

    let mut stmt = tx
        .prepare_cached(
            r"SELECT
                cu1.contract_address,
                cu1.class_hash
            FROM
                contract_updates cu1
            LEFT OUTER JOIN
                contract_updates cu2 ON cu1.contract_address = cu2.contract_address AND cu2.block_number < cu1.block_number
            WHERE
                cu1.block_number = ? AND
                cu2.block_number IS NULL",
        )
        .context("Preparing contract update query statement")?;
    let deployed_contracts = stmt
        .query_map([number], |row| {
            let address: ContractAddress = row.get(0)?;
            let class_hash: ClassHash = row.get(1)?;

            Ok(types::DeployedContract {
                address,
                class_hash,
            })
        })
        .context("Querying contract deployments")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over contract deployment query rows")?;

    let state_update = types::StateUpdate {
        block_hash: Some(block_hash),
        new_root: Some(new_root),
        old_root,
        state_diff: types::StateDiff {
            storage_diffs,
            declared_contract_hashes,
            deployed_contracts,
            nonces,
        },
    };

    Ok(state_update)
}

mod types {
    use crate::felt::{RpcFelt, RpcFelt251};
    use pathfinder_common::{
        BlockHash, ClassHash, ContractAddress, ContractNonce, StateCommitment, StorageAddress,
        StorageValue,
    };
    use serde::Serialize;
    use serde_with::skip_serializing_none;
    use std::collections::HashMap;

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

    impl From<starknet_gateway_types::reply::PendingStateUpdate> for StateUpdate {
        fn from(x: starknet_gateway_types::reply::PendingStateUpdate) -> Self {
            Self {
                block_hash: None,
                new_root: None,
                old_root: x.old_root,
                state_diff: x.state_diff.into(),
            }
        }
    }

    impl From<pathfinder_storage::types::StateUpdate> for StateUpdate {
        fn from(x: pathfinder_storage::types::StateUpdate) -> Self {
            Self {
                block_hash: x.block_hash,
                new_root: Some(x.new_root),
                old_root: x.old_root,
                state_diff: x.state_diff.into(),
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

    impl From<starknet_gateway_types::reply::state_update::StateDiff> for StateDiff {
        fn from(state_diff: starknet_gateway_types::reply::state_update::StateDiff) -> Self {
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
                // For the v02 API we're returning  Cairo _and_ Sierra class hashes here
                declared_contract_hashes: state_diff
                    .old_declared_contracts
                    .into_iter()
                    .chain(
                        state_diff
                            .declared_classes
                            .into_iter()
                            .map(|d| ClassHash(d.class_hash.0)),
                    )
                    .collect(),
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
    impl From<pathfinder_storage::types::state_update::StateDiff> for StateDiff {
        fn from(diff: pathfinder_storage::types::state_update::StateDiff) -> Self {
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
                // For the v02 API we're returning  Cairo _and_ Sierra class hashes here
                declared_contract_hashes: diff
                    .declared_contracts
                    .into_iter()
                    .map(|d| d.class_hash)
                    .chain(
                        diff.declared_sierra_classes
                            .into_iter()
                            .map(|d| ClassHash(d.class_hash.0)),
                    )
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

    impl From<starknet_gateway_types::reply::state_update::DeployedContract> for DeployedContract {
        fn from(d: starknet_gateway_types::reply::state_update::DeployedContract) -> Self {
            Self {
                address: d.address,
                class_hash: d.class_hash,
            }
        }
    }

    impl From<pathfinder_storage::types::state_update::DeployedContract> for DeployedContract {
        fn from(c: pathfinder_storage::types::state_update::DeployedContract) -> Self {
            Self {
                address: c.address,
                class_hash: c.class_hash,
            }
        }
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

    impl From<pathfinder_storage::types::state_update::Nonce> for Nonce {
        fn from(n: pathfinder_storage::types::state_update::Nonce) -> Self {
            Self {
                contract_address: n.contract_address,
                nonce: n.nonce,
            }
        }
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
                    declared_contract_hashes: vec![
                        ClassHash(felt!("0xcdef")),
                        ClassHash(felt!("0xcdee")),
                    ],
                    deployed_contracts: vec![DeployedContract {
                        address: ContractAddress::new_or_panic(felt!("0xadd")),
                        class_hash: ClassHash(felt!("0xcdef")),
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
    use super::types::{DeployedContract, StateDiff, StateUpdate, StorageDiff, StorageEntry};
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;
    use pathfinder_common::{felt, felt_bytes};
    use pathfinder_common::{
        BlockHash, BlockNumber, Chain, ClassHash, ContractAddress, StateCommitment, StorageAddress,
        StorageValue,
    };
    use stark_hash::Felt;
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
                // The fixture happens to init this to zero for genesis block
                BlockId::Hash(BlockHash(Felt::ZERO)),
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
                declared_contract_hashes: vec![],
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
                nonces: vec![],
            },
        };
        pretty_assertions::assert_eq!(result, expected);
    }
}
