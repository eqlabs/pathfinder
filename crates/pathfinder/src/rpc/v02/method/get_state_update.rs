use crate::core::BlockId;
use crate::rpc::v02::RpcContext;
use crate::storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetStateUpdatesTable};
use anyhow::{anyhow, Context};

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
    use serde::Serialize;
    use serde_with::skip_serializing_none;

    use std::collections::HashMap;

    use crate::core::{
        ClassHash, ContractAddress, ContractNonce, GlobalRoot, StarknetBlockHash, StorageAddress,
        StorageValue,
    };

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

        use crate::starkhash;

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
                .replace(&[' ', '\n'], "");

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

    use crate::core::{
        ClassHash, ContractAddress, GlobalRoot, StarknetBlockHash, StarknetBlockNumber,
        StorageAddress, StorageValue,
    };
    use crate::{starkhash, starkhash_bytes};

    use stark_hash::StarkHash;

    mod parsing {
        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                {"block_hash": "0xdeadbeef"}
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetStateUpdateInput>().unwrap();
            assert_eq!(
                input,
                GetStateUpdateInput {
                    block_id: BlockId::Hash(StarknetBlockHash(starkhash!("deadbeef")))
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = r#"{
                "block_id": {"block_hash": "0xdeadbeef"}
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<GetStateUpdateInput>().unwrap();
            assert_eq!(
                input,
                GetStateUpdateInput {
                    block_id: BlockId::Hash(StarknetBlockHash(starkhash!("deadbeef")))
                }
            )
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn block_not_found() {
            let context = RpcContext::for_tests();
            let input = GetStateUpdateInput {
                block_id: BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"invalid"))),
            };

            let result = get_state_update(context, input).await;

            assert_matches::assert_matches!(result, Err(GetStateUpdateError::BlockNotFound));
        }
    }

    fn context_with_state_updates() -> (Vec<StateUpdate>, RpcContext) {
        let storage = crate::storage::Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();
        let state_updates = crate::storage::fixtures::init::with_n_state_updates(&tx, 1);
        tx.commit().unwrap();

        let sync_state = std::sync::Arc::new(crate::state::SyncState::default());
        let chain = crate::core::Chain::Testnet;
        let sequencer = crate::sequencer::Client::new(chain).unwrap();

        let context = RpcContext::new(storage, sync_state, chain, sequencer);

        let state_updates = state_updates.into_iter().map(Into::into).collect();

        (state_updates, context)
    }

    #[tokio::test]
    async fn by_hash() {
        let (state_updates, context) = context_with_state_updates();
        let input = GetStateUpdateInput {
            block_id: BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)),
        };

        let result = get_state_update(context, input).await.unwrap();

        assert_eq!(result, state_updates[0]);
    }

    #[tokio::test]
    async fn by_number() {
        let (state_updates, context) = context_with_state_updates();
        let input = GetStateUpdateInput {
            block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(0)),
        };

        let result = get_state_update(context, input).await.unwrap();

        assert_eq!(result, state_updates[0]);
    }

    #[tokio::test]
    async fn latest() {
        let (state_updates, context) = context_with_state_updates();
        let input = GetStateUpdateInput {
            block_id: BlockId::Latest,
        };

        let result = get_state_update(context, input).await.unwrap();

        assert_eq!(result, state_updates[0]);
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
