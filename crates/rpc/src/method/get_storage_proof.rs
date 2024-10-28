use std::collections::HashSet;

use anyhow::Context;
use pathfinder_common::trie::TrieNode;
use pathfinder_common::{
    BlockHash,
    BlockId,
    ClassHash,
    ContractAddress,
    ContractNonce,
    StorageAddress,
};
use pathfinder_crypto::Felt;
use pathfinder_merkle_tree::tree::GetProofError;
use pathfinder_merkle_tree::{ClassCommitmentTree, ContractsStorageTree, StorageCommitmentTree};

use crate::context::RpcContext;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::DeserializeForVersion;

#[derive(Debug, PartialEq, Eq)]
pub struct ContractStorageKeys {
    contract_address: ContractAddress,
    storage_keys: Vec<StorageAddress>,
}

impl DeserializeForVersion for ContractStorageKeys {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                contract_address: value.deserialize("contract_address").map(ContractAddress)?,
                storage_keys: value.deserialize_array("storage_keys", |value| {
                    value.deserialize().map(StorageAddress)
                })?,
            })
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Internal(anyhow::Error),
    BlockNotFound,
    ProofLimitExceeded { limit: u32, requested: u32 },
    StorageProofNotSupported,
    ProofMissing,
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<GetProofError> for Error {
    fn from(e: GetProofError) -> Self {
        match e {
            GetProofError::Internal(e) => Self::Internal(e),
            GetProofError::StorageNodeMissing(index) => {
                tracing::warn!("Storage node missing: {}", index);
                Self::ProofMissing
            }
        }
    }
}

// Doing this manually since `generate_rpc_error_subset!`
// does not support enum struct variants.
impl From<Error> for crate::error::ApplicationError {
    fn from(e: Error) -> Self {
        match e {
            Error::ProofLimitExceeded { limit, requested } => {
                Self::ProofLimitExceeded { limit, requested }
            }
            Error::BlockNotFound => Self::BlockNotFound,
            Error::Internal(internal) => Self::Internal(internal),
            Error::StorageProofNotSupported => Self::StorageProofNotSupported,
            Error::ProofMissing => Self::ProofMissing,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    pub block_id: BlockId,
    pub class_hashes: Option<Vec<ClassHash>>,
    pub contract_addresses: Option<Vec<ContractAddress>>,
    pub contracts_storage_keys: Option<Vec<ContractStorageKeys>>,
}

impl DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                class_hashes: value.deserialize_optional_array("class_hashes", |value| {
                    value.deserialize().map(ClassHash)
                })?,
                contract_addresses: value
                    .deserialize_optional_array("contract_addresses", |value| {
                        value.deserialize().map(ContractAddress)
                    })?,
                contracts_storage_keys: value
                    .deserialize_optional_array("contracts_storage_keys", |value| {
                        value.deserialize()
                    })?,
            })
        })
    }
}

/// Wrapper around [`TrieNode`] to implement [`SerializeForVersion`].
#[derive(Debug, PartialEq, Eq, Hash)]
struct ProofNode(TrieNode);

impl SerializeForVersion for ProofNode {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        match &self.0 {
            TrieNode::Binary { left, right } => {
                s.serialize_field("left", &left)?;
                s.serialize_field("right", &right)?;
            }
            TrieNode::Edge { child, path } => {
                let p = Felt::from_bits(path).unwrap();
                let len = path.len();

                s.serialize_field("path", &p)?;
                s.serialize_field("length", &len)?;
                s.serialize_field("child", &child)?;
            }
        }
        s.end()
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct NodeHashToNodeMapping {
    node_hash: Felt,
    node: ProofNode,
}

impl SerializeForVersion for &NodeHashToNodeMapping {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("node_hash", &self.node_hash)?;
        s.serialize_field("node", &self.node)?;
        s.end()
    }
}

#[derive(Debug)]
struct NodeHashToNodeMappings(Vec<NodeHashToNodeMapping>);

impl SerializeForVersion for &NodeHashToNodeMappings {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.iter())
    }
}

#[derive(Debug)]
struct ContractLeafData {
    nonce: ContractNonce,
    class_hash: ClassHash,
}

impl SerializeForVersion for &ContractLeafData {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("nonce", &self.nonce)?;
        s.serialize_field("class_hash", &self.class_hash)?;
        s.end()
    }
}

#[derive(Debug)]
struct ContractsProof {
    nodes: NodeHashToNodeMappings,
    contract_leaves_data: Vec<ContractLeafData>,
}

impl SerializeForVersion for ContractsProof {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_iter("nodes", self.nodes.0.len(), &mut self.nodes.0.iter())?;
        s.serialize_iter(
            "contract_leaves_data",
            self.contract_leaves_data.len(),
            &mut self.contract_leaves_data.iter(),
        )?;
        s.end()
    }
}

#[derive(Debug)]
struct GlobalRoots {
    contracts_tree_root: Felt,
    classes_tree_root: Felt,
    block_hash: BlockHash,
}

impl SerializeForVersion for GlobalRoots {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("contracts_tree_root", &self.contracts_tree_root)?;
        s.serialize_field("classes_tree_root", &self.classes_tree_root)?;
        s.serialize_field("block_hash", &self.block_hash)?;
        s.end()
    }
}

#[derive(Debug)]
pub struct Output {
    classes_proof: NodeHashToNodeMappings,
    contracts_proof: ContractsProof,
    contracts_storage_proofs: Vec<NodeHashToNodeMappings>,
    global_roots: GlobalRoots,
}

impl SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_iter(
            "classes_proof",
            self.classes_proof.0.len(),
            &mut self.classes_proof.0.iter(),
        )?;
        s.serialize_field("contracts_proof", &self.contracts_proof)?;
        s.serialize_iter(
            "contracts_storage_proofs",
            self.contracts_storage_proofs.len(),
            &mut self.contracts_storage_proofs.iter(),
        )?;
        s.serialize_field("global_roots", &self.global_roots)?;
        s.end()
    }
}

/// Returns all the necessary data to trustlessly verify:
/// 1) Membership in the class trie.
/// 2) Membership in the global state trie.
/// 3) Membership in the contract storage trie.
pub async fn get_storage_proof(context: RpcContext, input: Input) -> Result<Output, Error> {
    const MAX_KEYS: usize = 100;
    let mut total_keys = 0;

    total_keys += input.class_hashes.as_ref().map_or(0, |hashes| hashes.len());
    total_keys += input
        .contract_addresses
        .as_ref()
        .map_or(0, |addresses| addresses.len());
    total_keys += input.contracts_storage_keys.as_ref().map_or(0, |keys| {
        keys.iter().map(|csk| csk.storage_keys.len()).sum::<usize>()
    });

    if total_keys > MAX_KEYS {
        return Err(Error::ProofLimitExceeded {
            limit: MAX_KEYS as u32,
            requested: total_keys as u32,
        });
    }

    let block_id = match input.block_id {
        BlockId::Pending => {
            // Getting proof of a pending block is not supported.
            return Err(Error::ProofMissing);
        }
        other => other.try_into().expect("Only pending cast should fail"),
    };

    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        // Use internal error to indicate that the process of querying for a particular
        // block failed, which is not the same as being sure that the block is
        // not in the db.
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .ok_or(Error::BlockNotFound)?;

        let class_root_idx = tx
            .class_root_index(header.number)
            .context("Querying class root index")?
            .ok_or(Error::StorageProofNotSupported)?;

        let class_root_hash = match tx
            .class_trie_node_hash(class_root_idx)
            .context("Querying class root hash")?
        {
            None if input.class_hashes.is_some() => return Err(Error::StorageProofNotSupported),
            None => Felt::default(),
            Some(hash) => hash,
        };

        let classes_proof = if let Some(class_hashes) = input.class_hashes {
            let nodes: Vec<NodeHashToNodeMapping> =
                ClassCommitmentTree::get_proofs(&tx, header.number, &class_hashes, class_root_idx)?
                    .into_iter()
                    .flatten()
                    .map(|(node, node_hash)| NodeHashToNodeMapping {
                        node_hash,
                        node: ProofNode(node),
                    })
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

            NodeHashToNodeMappings(nodes)
        } else {
            NodeHashToNodeMappings(vec![])
        };

        let storage_root_idx = tx
            .storage_root_index(header.number)
            .context("Querying storage root index")?
            .ok_or(Error::StorageProofNotSupported)?;

        let storage_root_hash = match tx
            .storage_trie_node_hash(storage_root_idx)
            .context("Querying class root hash")?
        {
            None if input.contract_addresses.is_some() => {
                return Err(Error::StorageProofNotSupported)
            }
            None => Felt::default(),
            Some(hash) => hash,
        };

        let (contract_proof_nodes, contract_leaves_data) =
            if let Some(contract_addresses) = input.contract_addresses {
                let nodes = StorageCommitmentTree::get_proofs(
                    &tx,
                    header.number,
                    &contract_addresses,
                    storage_root_idx,
                )?
                .into_iter()
                .flatten()
                .map(|(node, node_hash)| NodeHashToNodeMapping {
                    node_hash,
                    node: ProofNode(node),
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

                let contract_leaves_data = contract_addresses
                    .iter()
                    .map(|&address| {
                        let class_hash = tx
                            .contract_class_hash(header.number.into(), address)
                            .context("Querying contract's class hash")?
                            .unwrap_or_default();

                        let nonce = tx
                            .contract_nonce(address, header.number.into())
                            .context("Querying contract's nonce")?
                            .unwrap_or_default();

                        Ok(ContractLeafData { nonce, class_hash })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                (NodeHashToNodeMappings(nodes), contract_leaves_data)
            } else {
                (NodeHashToNodeMappings(vec![]), vec![])
            };

        let contracts_storage_proofs = match input.contracts_storage_keys {
            None => vec![],
            Some(contracts_storage_keys) => {
                let mut proofs = vec![];
                for csk in contracts_storage_keys {
                    let root = tx
                        .contract_root_index(header.number, csk.contract_address)
                        .context("Querying contract root index")?;

                    if let Some(root) = root {
                        let nodes: Vec<NodeHashToNodeMapping> = ContractsStorageTree::get_proofs(
                            &tx,
                            csk.contract_address,
                            header.number,
                            &csk.storage_keys,
                            root,
                        )?
                        .into_iter()
                        .flatten()
                        .map(|(node, node_hash)| NodeHashToNodeMapping {
                            node_hash,
                            node: ProofNode(node),
                        })
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect();

                        proofs.push(NodeHashToNodeMappings(nodes));
                    } else {
                        proofs.push(NodeHashToNodeMappings(vec![]));
                    }
                }

                proofs
            }
        };

        let contracts_proof = ContractsProof {
            nodes: contract_proof_nodes,
            contract_leaves_data,
        };

        let global_roots = GlobalRoots {
            contracts_tree_root: storage_root_hash,
            classes_tree_root: class_root_hash,
            block_hash: header.hash,
        };

        Ok(Output {
            classes_proof,
            contracts_proof,
            contracts_storage_proofs,
            global_roots,
        })
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::*;

    use super::*;
    use crate::dto::serialize::SerializeForVersion;

    mod serialization {
        use bitvec::bitvec;
        use bitvec::prelude::Msb0;
        use serde_json::json;

        use super::*;
        use crate::RpcVersion;

        #[rstest::rstest]
        #[case::named_all_optionals_present(
            json!({
                "block_id": {
                    "block_hash": "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                },
                "class_hashes": ["0x12345", "0x2345", "0x345"],
                "contract_addresses": ["0x12345", "0x2345", "0x345"],
                "contracts_storage_keys": [{
                    "contract_address": "0x111",
                    "storage_keys": ["0x123", "0x234", "0x345"]
                }]
            }),
            Input {
                block_id: BlockId::Hash(block_hash!(
                    "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                )),
                class_hashes: Some(vec![
                    class_hash!("0x12345"),
                    class_hash!("0x2345"),
                    class_hash!("0x345"),
                ]),
                contract_addresses: Some(vec![
                    contract_address!("0x12345"),
                    contract_address!("0x2345"),
                    contract_address!("0x345"),
                ]),
                contracts_storage_keys: Some(vec![ContractStorageKeys {
                    contract_address: contract_address!("0x111"),
                    storage_keys: vec![
                        storage_address!("0x123"),
                        storage_address!("0x234"),
                        storage_address!("0x345"),
                    ],
                }]),
            }
        )]
        #[case::positional_all_optionals_present(
            json!([
                {
                    "block_hash": "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                },
                ["0x12345", "0x2345", "0x345"],
                ["0x12345", "0x2345", "0x345"],
                [{
                    "contract_address": "0x111",
                    "storage_keys": ["0x123", "0x234", "0x345"]
                }]
            ]),
            Input {
                block_id: BlockId::Hash(block_hash!(
                    "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                )),
                class_hashes: Some(vec![
                    class_hash!("0x12345"),
                    class_hash!("0x2345"),
                    class_hash!("0x345"),
                ]),
                contract_addresses: Some(vec![
                    contract_address!("0x12345"),
                    contract_address!("0x2345"),
                    contract_address!("0x345"),
                ]),
                contracts_storage_keys: Some(vec![ContractStorageKeys {
                    contract_address: contract_address!("0x111"),
                    storage_keys: vec![
                        storage_address!("0x123"),
                        storage_address!("0x234"),
                        storage_address!("0x345"),
                    ],
                }]),
            }
        )]
        #[case::named_all_optionals_missing(
            json!({
                "block_id": {
                    "block_hash": "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                }
            }),
            Input {
                block_id: BlockId::Hash(block_hash!(
                    "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                )),
                class_hashes: None,
                contract_addresses: None,
                contracts_storage_keys: None,
            }
        )]
        #[case::positional_all_optionals_missing(
            json!({
                "block_id": {
                    "block_hash": "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                },
            }),
            Input {
                block_id: BlockId::Hash(block_hash!(
                    "0x02ea95751155e45acac9186684306684ee328c99610a7a855a8685907a60746c"
                )),
                class_hashes: None,
                contract_addresses: None,
                contracts_storage_keys: None,
            }
        )]
        fn parsing_input(#[case] input: serde_json::Value, #[case] expected: Input) {
            let input = Input::deserialize(crate::dto::Value::new(input, RpcVersion::V07)).unwrap();

            assert_eq!(input, expected);
        }

        #[rstest::rstest]
        #[case::empty_output(
            Output {
                classes_proof: NodeHashToNodeMappings(vec![]),
                contracts_proof: ContractsProof {
                    nodes: NodeHashToNodeMappings(vec![]),
                    contract_leaves_data: vec![],
                },
                contracts_storage_proofs: vec![],
                global_roots: GlobalRoots {
                    contracts_tree_root: Felt::default(),
                    classes_tree_root: Felt::default(),
                    block_hash: BlockHash::default(),
                },
            },
            json!({
                "classes_proof": [],
                "contracts_proof": {
                    "nodes": [],
                    "contract_leaves_data": []
                },
                "contracts_storage_proofs": [],
                "global_roots": {
                    "contracts_tree_root": "0x0",
                    "classes_tree_root": "0x0",
                    "block_hash": "0x0"
                }
            }),
        )]
        #[case::non_empty_output(
            Output {
                classes_proof: NodeHashToNodeMappings(vec![NodeHashToNodeMapping {
                    node_hash: Felt::from_hex_str("0x123").unwrap(),
                    node: ProofNode(TrieNode::Binary {
                        left: Felt::from_hex_str("0x123").unwrap(),
                        right: Felt::from_hex_str("0x123").unwrap(),
                    }),
                }]),
                contracts_proof: ContractsProof {
                    nodes: NodeHashToNodeMappings(vec![NodeHashToNodeMapping {
                        node_hash: Felt::from_hex_str("0x123").unwrap(),
                        node: ProofNode(TrieNode::Edge {
                            child: Felt::from_hex_str("0x123").unwrap(),
                            path: bitvec![u8, Msb0; 0; 8],
                        }),
                    }]),
                    contract_leaves_data: vec![ContractLeafData {
                        nonce: ContractNonce::ZERO,
                        class_hash: ClassHash(Felt::from_hex_str("0x123").unwrap()),
                    }],
                },
                contracts_storage_proofs: vec![NodeHashToNodeMappings(vec![NodeHashToNodeMapping {
                    node_hash: Felt::from_hex_str("0x123").unwrap(),
                    node: ProofNode(TrieNode::Binary {
                        left: Felt::from_hex_str("0x123").unwrap(),
                        right: Felt::from_hex_str("0x123").unwrap(),
                    }),
                }])],
                global_roots: GlobalRoots {
                    contracts_tree_root: Felt::from_hex_str("0x123").unwrap(),
                    classes_tree_root: Felt::from_hex_str("0x123").unwrap(),
                    block_hash: BlockHash(Felt::from_hex_str("0x123").unwrap()),
                },
            },
            json!({
                "classes_proof": [
                    {
                        "node_hash": "0x123",
                        "node": {
                            "left": "0x123",
                            "right": "0x123"
                        }
                    }
                ],
                "contracts_proof": {
                    "nodes": [
                        {
                            "node_hash": "0x123",
                            "node": {
                                "child": "0x123",
                                "length": 8,
                                "path": "0x0",
                            }
                        }
                    ],
                    "contract_leaves_data": [
                        {
                            "nonce": "0x0",
                            "class_hash": "0x123"
                        }
                    ]
                },
                "contracts_storage_proofs": [
                    [
                        {
                            "node_hash": "0x123",
                            "node": {
                                "left": "0x123",
                                "right": "0x123"
                            }
                        }
                    ]
                ],
                "global_roots": {
                    "contracts_tree_root": "0x123",
                    "classes_tree_root": "0x123",
                    "block_hash": "0x123"
                }
            }),
        )]
        fn serialization_output(#[case] output: Output, #[case] expected: serde_json::Value) {
            let output = output
                .serialize(crate::dto::serialize::Serializer::default())
                .unwrap();

            assert_eq!(output, expected);
        }
    }

    #[tokio::test]
    async fn proof_limit_exceeded() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Number(pathfinder_common::BlockNumber::GENESIS),
            class_hashes: Some(vec![class_hash_bytes!(b"class 2 hash (sierra)"); 100]),
            contract_addresses: Some(vec![contract_address_bytes!(b"contract 2 (sierra)")]),
            contracts_storage_keys: Some(vec![ContractStorageKeys {
                contract_address: contract_address_bytes!(b"contract 1"),
                storage_keys: vec![storage_address_bytes!(b"storage addr 0")],
            }]),
        };

        let output = get_storage_proof(context, input).await;

        assert!(matches!(output, Err(Error::ProofLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn success() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Number(pathfinder_common::BlockNumber::GENESIS + 2),
            class_hashes: Some(vec![class_hash_bytes!(b"class 2 hash (sierra)"); 5]),
            contract_addresses: Some(vec![contract_address_bytes!(b"contract 2 (sierra)"); 5]),
            contracts_storage_keys: Some(vec![ContractStorageKeys {
                contract_address: contract_address_bytes!(b"contract 1"),
                storage_keys: vec![storage_address_bytes!(b"storage addr 0"); 5],
            }]),
        };

        let output = get_storage_proof(context, input).await;

        assert!(output.is_ok());
    }

    #[tokio::test]
    async fn pending_block() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Pending,
            class_hashes: None,
            contract_addresses: None,
            contracts_storage_keys: None,
        };

        let output = get_storage_proof(context, input).await;

        assert!(matches!(output, Err(Error::ProofMissing)));
    }

    #[tokio::test]
    async fn block_not_found() {
        let context = RpcContext::for_tests();
        let input = Input {
            block_id: BlockId::Number(pathfinder_common::BlockNumber::MAX),
            class_hashes: None,
            contract_addresses: None,
            contracts_storage_keys: None,
        };

        let output = get_storage_proof(context, input).await;

        assert!(matches!(output, Err(Error::BlockNotFound)));
    }
}
