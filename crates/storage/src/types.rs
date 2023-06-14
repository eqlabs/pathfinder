use pathfinder_common::{BlockHash, StateCommitment};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// L2 state update as returned by the [RPC API v0.1.0](https://github.com/starkware-libs/starknet-specs/blob/30e5bafcda60c31b5fb4021b4f5ddcfc18d2ff7d/api/starknet_api_openrpc.json#L846)
/// and currently the format in which we store the state updates.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateUpdate {
    /// Keeping optional because not sure if all serialized state updates contain this field
    // FIXME regenesis: remove Option<> around block_hash
    #[serde(default)]
    pub block_hash: Option<BlockHash>,
    pub new_root: StateCommitment,
    pub old_root: StateCommitment,
    pub state_diff: state_update::StateDiff,
}

impl From<starknet_gateway_types::reply::StateUpdate> for StateUpdate {
    fn from(x: starknet_gateway_types::reply::StateUpdate) -> Self {
        Self {
            block_hash: Some(x.block_hash),
            new_root: x.new_root,
            old_root: x.old_root,
            state_diff: x.state_diff.into(),
        }
    }
}

/// State update related substructures.
///
/// # Serialization
///
/// All structures in this module derive [serde::Deserialize] without depending
/// on the `rpc-full-serde` feature because state updates are
/// stored in the DB as compressed raw JSON bytes.
pub mod state_update {
    use pathfinder_common::{
        CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress,
        StorageValue,
    };
    use serde::{Deserialize, Serialize};

    /// L2 state diff.
    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        /// Refers to Declare V0 & V1 txns, these contain Cairo classes
        pub declared_contracts: Vec<DeclaredCairoClass>,
        /// Refers to pre-Starknet-0.11.0 Deploy txns
        pub deployed_contracts: Vec<DeployedContract>,
        pub nonces: Vec<Nonce>,
        /// Refers to Declare V2 txns, these contain Sierra classes
        #[serde(default)]
        pub declared_sierra_classes: Vec<DeclaredSierraClass>,
        /// Replaced classes, introduced in Starknet 0.11.0
        #[serde(default)]
        pub replaced_classes: Vec<ReplacedClass>,
    }

    impl StateDiff {
        pub fn add_deployed_contract(
            mut self,
            address: ContractAddress,
            class_hash: ClassHash,
        ) -> Self {
            self.deployed_contracts.push(DeployedContract {
                address,
                class_hash,
            });
            self
        }

        pub fn add_declared_cairo_class(mut self, cairo_hash: ClassHash) -> Self {
            self.declared_contracts.push(DeclaredCairoClass {
                class_hash: cairo_hash,
            });
            self
        }

        pub fn add_declared_sierra_class(
            mut self,
            sierra_hash: SierraHash,
            casm_hash: CasmHash,
        ) -> Self {
            self.declared_sierra_classes.push(DeclaredSierraClass {
                class_hash: sierra_hash,
                compiled_class_hash: casm_hash,
            });
            self
        }

        pub fn add_replaced_class(
            mut self,
            address: ContractAddress,
            class_hash: ClassHash,
        ) -> Self {
            self.replaced_classes.push(ReplacedClass {
                address,
                class_hash,
            });
            self
        }

        pub fn add_nonce_update(
            mut self,
            contract_address: ContractAddress,
            nonce: ContractNonce,
        ) -> Self {
            self.nonces.push(Nonce {
                contract_address,
                nonce,
            });
            self
        }

        pub fn add_storage_update(
            mut self,
            contract_address: ContractAddress,
            key: StorageAddress,
            value: StorageValue,
        ) -> Self {
            self.storage_diffs.push(StorageDiff {
                address: contract_address,
                key,
                value,
            });
            self
        }
    }

    impl From<starknet_gateway_types::reply::state_update::StateDiff> for StateDiff {
        fn from(x: starknet_gateway_types::reply::state_update::StateDiff) -> Self {
            Self {
                storage_diffs: x
                    .storage_diffs
                    .into_iter()
                    .flat_map(|(contract_address, storage_diffs)| {
                        storage_diffs.into_iter().map(move |x| StorageDiff {
                            address: contract_address,
                            key: x.key,
                            value: x.value,
                        })
                    })
                    .collect(),
                declared_contracts: x
                    .old_declared_contracts
                    .into_iter()
                    .map(|class_hash| DeclaredCairoClass { class_hash })
                    .collect(),
                deployed_contracts: x
                    .deployed_contracts
                    .into_iter()
                    .map(|deployed_contract| DeployedContract {
                        address: deployed_contract.address,
                        class_hash: deployed_contract.class_hash,
                    })
                    .collect(),
                nonces: x
                    .nonces
                    .into_iter()
                    .map(|(contract_address, nonce)| Nonce {
                        contract_address,
                        nonce,
                    })
                    .collect(),
                declared_sierra_classes: x.declared_classes.into_iter().map(Into::into).collect(),
                replaced_classes: x.replaced_classes.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// L2 storage diff of a contract.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub address: ContractAddress,
        pub key: StorageAddress,
        pub value: StorageValue,
    }

    /// L2 state diff Declared V1 class item.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredCairoClass {
        pub class_hash: ClassHash,
    }

    /// L2 state diff deployed contract item.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        pub address: ContractAddress,
        pub class_hash: ClassHash,
    }

    /// L2 state diff nonce item.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Nonce {
        pub contract_address: ContractAddress,
        pub nonce: ContractNonce,
    }

    /// L2 state diff Declared V2 class item. Maps Sierra class hash to a Casm hash.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredSierraClass {
        pub class_hash: SierraHash,
        pub compiled_class_hash: CasmHash,
    }

    impl From<starknet_gateway_types::reply::state_update::DeclaredSierraClass>
        for DeclaredSierraClass
    {
        fn from(x: starknet_gateway_types::reply::state_update::DeclaredSierraClass) -> Self {
            Self {
                class_hash: x.class_hash,
                compiled_class_hash: x.compiled_class_hash,
            }
        }
    }

    /// L2 state diff replaced class item. Maps contract address to a new class.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct ReplacedClass {
        pub address: ContractAddress,
        pub class_hash: ClassHash,
    }

    impl From<starknet_gateway_types::reply::state_update::ReplacedClass> for ReplacedClass {
        fn from(x: starknet_gateway_types::reply::state_update::ReplacedClass) -> Self {
            Self {
                address: x.address,
                class_hash: x.class_hash,
            }
        }
    }
}

/// A more user-friendly state update structs
pub mod v2 {
    use pathfinder_common::{BlockHash, StateCommitment};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StateUpdate {
        pub block_hash: Option<BlockHash>,
        pub new_root: StateCommitment,
        pub old_root: StateCommitment,
        pub state_diff: state_update::StateDiff,
    }

    pub mod state_update {
        use super::super::state_update::{
            DeclaredSierraClass, DeployedContract, Nonce, ReplacedClass,
        };
        use pathfinder_common::{ClassHash, ContractAddress, StorageAddress, StorageValue};
        use std::collections::HashMap;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct StateDiff {
            pub storage_diffs: Vec<StorageDiff>,
            pub deprecated_declared_classes: Vec<ClassHash>,
            pub declared_classes: Vec<DeclaredSierraClass>,
            pub deployed_contracts: Vec<DeployedContract>,
            pub replaced_classes: Vec<ReplacedClass>,
            pub nonces: Vec<Nonce>,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct StorageDiff {
            pub address: ContractAddress,
            pub storage_entries: Vec<StorageEntry>,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct StorageEntry {
            pub key: StorageAddress,
            pub value: StorageValue,
        }

        /// Convert from the v0.1.0 representation we have in the storage to the new one.
        ///
        /// We need this conversion because the representation of storage diffs have changed
        /// in v0.2.0 of the JSON-RPC specification and we're storing v0.1.0 formatted JSONs
        /// in our storage.
        /// Storage updates are now grouped per-contract and individual update entries no
        /// longer contain the contract address.
        impl From<crate::types::state_update::StateDiff> for StateDiff {
            fn from(diff: crate::types::state_update::StateDiff) -> Self {
                let mut per_contract_diff: HashMap<ContractAddress, Vec<StorageEntry>> =
                    HashMap::new();
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
                    deprecated_declared_classes: diff
                        .declared_contracts
                        .into_iter()
                        .map(|d| d.class_hash)
                        .collect(),
                    declared_classes: diff
                        .declared_sierra_classes
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    deployed_contracts: diff
                        .deployed_contracts
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                    replaced_classes: diff.replaced_classes.into_iter().map(Into::into).collect(),
                    nonces: diff.nonces.into_iter().map(Into::into).collect(),
                }
            }
        }
    }

    impl From<super::StateUpdate> for StateUpdate {
        fn from(x: super::StateUpdate) -> Self {
            Self {
                block_hash: x.block_hash,
                new_root: x.new_root,
                old_root: x.old_root,
                state_diff: x.state_diff.into(),
            }
        }
    }
}
