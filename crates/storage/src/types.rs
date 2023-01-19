use pathfinder_common::{ClassHash, StarknetBlockHash, StateCommitment};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Clone, PartialEq, Eq)]
pub struct CompressedContract {
    pub abi: Vec<u8>,
    pub bytecode: Vec<u8>,
    pub definition: Vec<u8>,
    pub hash: ClassHash,
}

impl std::fmt::Debug for CompressedContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompressedContract {{ sizes: {:?}, hash: {} }}",
            (self.abi.len(), self.bytecode.len(), self.definition.len()),
            self.hash.0
        )
    }
}

/// L2 state update as returned by the [RPC API v0.1.0](https://github.com/starkware-libs/starknet-specs/blob/30e5bafcda60c31b5fb4021b4f5ddcfc18d2ff7d/api/starknet_api_openrpc.json#L846)
/// and currently the format in which we store the state updates.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateUpdate {
    /// None for `pending`
    #[serde(default)]
    pub block_hash: Option<StarknetBlockHash>,
    pub new_root: StateCommitment,
    pub old_root: StateCommitment,
    pub state_diff: state_update::StateDiff,
}

impl From<starknet_gateway_types::reply::StateUpdate> for StateUpdate {
    fn from(x: starknet_gateway_types::reply::StateUpdate) -> Self {
        Self {
            block_hash: x.block_hash,
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
        ClassHash, ContractAddress, ContractNonce, StorageAddress, StorageValue,
    };
    use serde::{Deserialize, Serialize};

    /// L2 state diff.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        pub storage_diffs: Vec<StorageDiff>,
        pub declared_contracts: Vec<DeclaredContract>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub nonces: Vec<Nonce>,
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
                    .old_declared_classes
                    .into_iter()
                    .map(|class_hash| DeclaredContract { class_hash })
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

    /// L2 state diff declared contract item.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredContract {
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
}
