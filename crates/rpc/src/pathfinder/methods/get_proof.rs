use anyhow::{anyhow, Context};
use pathfinder_common::prelude::*;
use pathfinder_common::trie::TrieNode;
use pathfinder_common::BlockId;
use pathfinder_crypto::Felt;
use pathfinder_merkle_tree::{
    tree,
    ClassCommitmentTree,
    ContractsStorageTree,
    StorageCommitmentTree,
};

use crate::context::RpcContext;

#[derive(Debug, PartialEq, Eq)]
pub struct GetProofInput {
    pub block_id: BlockId,
    pub contract_address: ContractAddress,
    pub keys: Vec<StorageAddress>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GetClassProofInput {
    pub block_id: BlockId,
    pub class_hash: ClassHash,
}

impl crate::dto::DeserializeForVersion for GetProofInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                contract_address: ContractAddress(value.deserialize("contract_address")?),
                keys: value
                    .deserialize_array("keys", |value| Ok(StorageAddress(value.deserialize()?)))?,
            })
        })
    }
}

impl crate::dto::DeserializeForVersion for GetClassProofInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                block_id: value.deserialize("block_id")?,
                class_hash: ClassHash(value.deserialize("class_hash")?),
            })
        })
    }
}

// FIXME: allow `generate_rpc_error_subset!` to work with enum struct variants.
// This may not actually be possible though.
#[derive(Debug)]
pub enum GetProofError {
    Internal(anyhow::Error),
    BlockNotFound,
    ProofLimitExceeded { limit: u32, requested: u32 },
    ProofMissing,
}

impl From<anyhow::Error> for GetProofError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<tree::GetProofError> for GetProofError {
    fn from(e: tree::GetProofError) -> Self {
        match e {
            tree::GetProofError::Internal(e) => Self::Internal(e),
            tree::GetProofError::StorageNodeMissing(index) => {
                tracing::warn!("Storage node missing: {}", index);
                Self::ProofMissing
            }
        }
    }
}

impl From<GetProofError> for crate::error::ApplicationError {
    fn from(x: GetProofError) -> Self {
        match x {
            GetProofError::ProofLimitExceeded { limit, requested } => {
                Self::ProofLimitExceeded { limit, requested }
            }
            GetProofError::BlockNotFound => Self::BlockNotFound,
            GetProofError::Internal(internal) => Self::Internal(internal),
            GetProofError::ProofMissing => Self::ProofMissing,
        }
    }
}

/// Utility struct used for serializing.
#[derive(Debug)]
struct PathWrapper {
    value: Felt,
    len: usize,
}

impl crate::dto::SerializeForVersion for PathWrapper {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut obj = serializer.serialize_struct()?;
        obj.serialize_field("value", &self.value)?;
        obj.serialize_field("len", &self.len)?;
        obj.end()
    }
}

/// Wrapper around [`Vec<TrieNode>`] as we don't control [TrieNode] in this
/// crate.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofNodes(Vec<TrieNode>);

impl crate::dto::SerializeForVersion for ProofNodes {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_iter(
            self.0.len(),
            &mut self.0.iter().map(|node| {
                struct SerProofNode<'a>(&'a TrieNode);

                impl crate::dto::SerializeForVersion for SerProofNode<'_> {
                    fn serialize(
                        &self,
                        serializer: crate::dto::Serializer,
                    ) -> Result<crate::dto::Ok, crate::dto::Error> {
                        let mut s = serializer.serialize_struct()?;
                        match self.0 {
                            TrieNode::Binary { left, right } => {
                                let mut inner = serializer.serialize_struct()?;
                                inner.serialize_field("left", left)?;
                                inner.serialize_field("right", right)?;
                                let inner = inner.end()?;

                                s.serialize_field("binary", &inner)?;
                            }
                            TrieNode::Edge { child, path } => {
                                let value = Felt::from_bits(path).unwrap();
                                let path = PathWrapper {
                                    value,
                                    len: path.len(),
                                };

                                let mut inner = serializer.serialize_struct()?;
                                inner.serialize_field("path", &path)?;
                                inner.serialize_field("child", child)?;
                                let inner = inner.end()?;

                                s.serialize_field("edge", &inner)?;
                            }
                        }
                        s.end()
                    }
                }

                SerProofNode(node)
            }),
        )
    }
}

/// Holds the data and proofs for a specific contract.
#[derive(Clone, Debug)]
pub struct ContractData {
    /// Required to verify the contract state hash to contract root calculation.
    class_hash: ClassHash,
    /// Required to verify the contract state hash to contract root calculation.
    nonce: ContractNonce,

    /// Root of the Contract state tree
    root: ContractRoot,

    /// This is currently just a constant = 0, however it might change in the
    /// future.
    contract_state_hash_version: Felt,

    /// The proofs associated with the queried storage values
    storage_proofs: Vec<ProofNodes>,
}

impl crate::dto::SerializeForVersion for ContractData {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut obj = serializer.serialize_struct()?;
        obj.serialize_field("class_hash", &self.class_hash)?;
        obj.serialize_field("nonce", &self.nonce)?;
        obj.serialize_field("root", &self.root)?;
        obj.serialize_field(
            "contract_state_hash_version",
            &self.contract_state_hash_version,
        )?;
        obj.serialize_iter(
            "storage_proofs",
            self.storage_proofs.len(),
            &mut self.storage_proofs.iter().cloned(),
        )?;
        obj.end()
    }
}

/// Holds the membership/non-membership of a contract and its associated
/// contract contract if the contract exists.
#[derive(Debug)]
pub struct GetProofOutput {
    /// The global state commitment for Starknet 0.11.0 blocks onwards, if
    /// absent the hash of the first node in the
    /// [contract_proof](GetProofOutput#contract_proof) is the global state
    /// commitment.
    state_commitment: Option<StateCommitment>,
    /// Required to verify that the hash of the class commitment and the root of
    /// the [contract_proof](GetProofOutput::contract_proof) matches the
    /// [state_commitment](Self#state_commitment). Present only for Starknet
    /// blocks 0.11.0 onwards.
    class_commitment: Option<ClassCommitment>,

    /// Membership / Non-membership proof for the queried contract
    contract_proof: ProofNodes,

    /// Additional contract data if it exists.
    contract_data: Option<ContractData>,
}

impl crate::dto::SerializeForVersion for GetProofOutput {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_optional_with_null("state_commitment", self.state_commitment)?;
        serializer.serialize_optional_with_null("class_commitment", self.class_commitment)?;
        serializer.serialize_field("contract_proof", &self.contract_proof)?;
        serializer.serialize_optional("contract_data", self.contract_data.clone())?;
        serializer.end()
    }
}

#[derive(Debug, PartialEq)]
pub struct GetClassProofOutput {
    /// Required to verify that the hash of the class commitment and the root of
    /// the [contract_proof](GetProofOutput::contract_proof) matches the
    /// [state_commitment](Self#state_commitment). Present only for Starknet
    /// blocks 0.11.0 onwards.
    class_commitment: Option<ClassCommitment>,
    /// Membership / Non-membership proof for the queried contract classes
    class_proof: ProofNodes,
}

impl crate::dto::SerializeForVersion for GetClassProofOutput {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_optional_with_null("class_commitment", self.class_commitment)?;
        serializer.serialize_field("class_proof", &self.class_proof)?;
        serializer.end()
    }
}

/// Returns all the necessary data to trustlessly verify storage slots for a
/// particular contract.
pub async fn get_proof(
    context: RpcContext,
    input: GetProofInput,
) -> Result<GetProofOutput, GetProofError> {
    const MAX_KEYS: usize = 100;
    if input.keys.len() > MAX_KEYS {
        return Err(GetProofError::ProofLimitExceeded {
            limit: MAX_KEYS as u32,
            requested: input.keys.len() as u32,
        });
    }

    let block_id = match input.block_id {
        BlockId::Pending => {
            return Err(GetProofError::Internal(anyhow!(
                "'pending' is not currently supported by this method!"
            )))
        }
        other => other.try_into().expect("Only pending cast should fail"),
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        // Use internal error to indicate that the process of querying for a particular
        // block failed, which is not the same as being sure that the block is
        // not in the db.
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .ok_or(GetProofError::BlockNotFound)?;

        let state_commitment = match header.state_commitment {
            StateCommitment::ZERO => None,
            other => Some(other),
        };

        let storage_root_idx = tx
            .storage_root_index(header.number)
            .context("Querying storage root index")?;
        let class_commitment = tx
            .class_root(header.number)
            .context("Querying class commitment")?;

        let Some(storage_root_idx) = storage_root_idx else {
            if tx.trie_pruning_enabled() {
                return Err(GetProofError::ProofMissing);
            } else {
                // Either:
                // - the chain is empty (no contract updates) up to and including this block
                // - or all leaves were removed resulting in an empty trie
                // An empty proof is then a proof of non-membership in an empty block.
                return Ok(GetProofOutput {
                    state_commitment,
                    class_commitment,
                    contract_proof: ProofNodes(vec![]),
                    contract_data: None,
                });
            }
        };

        // Generate a proof for this contract. If the contract does not exist, this will
        // be a "non membership" proof.
        let contract_proof = StorageCommitmentTree::get_proof(
            &tx,
            header.number,
            &input.contract_address,
            storage_root_idx,
        )?
        .into_iter()
        .map(|(node, _)| node)
        .collect();

        let contract_proof = ProofNodes(contract_proof);

        let contract_state_hash = tx
            .contract_state_hash(header.number, input.contract_address)
            .context("Fetching contract's state hash")?;

        if contract_state_hash.is_none() {
            return Ok(GetProofOutput {
                state_commitment,
                class_commitment,
                contract_proof,
                contract_data: None,
            });
        };

        let contract_root = tx
            .contract_root(header.number, input.contract_address)
            .context("Querying contract's root")?
            .unwrap_or_default();

        let class_hash = tx
            .contract_class_hash(header.number.into(), input.contract_address)
            .context("Querying contract's class hash")?
            .unwrap_or_default();

        let nonce = tx
            .contract_nonce(input.contract_address, header.number.into())
            .context("Querying contract's nonce")?
            .unwrap_or_default();

        let root = tx
            .contract_root_index(header.number, input.contract_address)
            .context("Querying contract root index")?;

        let mut storage_proofs = Vec::new();
        for k in &input.keys {
            if let Some(root) = root {
                let proof = ContractsStorageTree::get_proof(
                    &tx,
                    input.contract_address,
                    header.number,
                    k.view_bits(),
                    root,
                )?
                .into_iter()
                .map(|(node, _)| node)
                .collect();

                storage_proofs.push(ProofNodes(proof));
            } else {
                storage_proofs.push(ProofNodes(vec![]));
            }
        }

        let contract_data = ContractData {
            class_hash,
            nonce,
            root: contract_root,
            contract_state_hash_version: Felt::ZERO, /* Currently, this is defined as 0. Might
                                                      * change in the future. */
            storage_proofs,
        };

        Ok(GetProofOutput {
            state_commitment,
            class_commitment,
            contract_proof,
            contract_data: Some(contract_data),
        })
    });

    jh.await.context("Database read panic or shutting down")?
}

/// Returns all the necessary data to trustlessly verify class changes for a
/// particular contract.
pub async fn get_class_proof(
    context: RpcContext,
    input: GetClassProofInput,
) -> Result<GetClassProofOutput, GetProofError> {
    let block_id = match input.block_id {
        BlockId::Pending => {
            return Err(GetProofError::Internal(anyhow!(
                "'pending' is not currently supported by this method!"
            )))
        }
        other => other.try_into().expect("Only pending cast should fail"),
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        // Use internal error to indicate that the process of querying for a particular
        // block failed, which is not the same as being sure that the block is
        // not in the db.
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .ok_or(GetProofError::BlockNotFound)?;

        let class_root_idx = tx
            .class_root_index(header.number)
            .context("Querying class root index")?;

        let Some(class_root_idx) = class_root_idx else {
            if tx.trie_pruning_enabled() {
                return Err(GetProofError::ProofMissing);
            } else {
                // Either:
                // - the chain is empty (no declared classes) up to and including this block
                // - or all leaves were removed resulting in an empty trie
                // An empty proof is then a proof of non-membership in an empty block.
                return Ok(GetClassProofOutput {
                    class_commitment: None,
                    class_proof: ProofNodes(vec![]),
                });
            }
        };

        let class_commitment = tx
            .class_trie_node_hash(class_root_idx)
            .context("Querying class trie root")?
            .map(ClassCommitment);

        // Generate a proof for this class. If the class does not exist, this will
        // be a "non membership" proof.
        let class_proof =
            ClassCommitmentTree::get_proof(&tx, header.number, input.class_hash, class_root_idx)?
                .into_iter()
                .map(|(node, _)| node)
                .collect();

        let class_proof = ProofNodes(class_proof);

        Ok(GetClassProofOutput {
            class_commitment,
            class_proof,
        })
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_merkle_tree::starknet_state::update_starknet_state;

    use super::*;

    mod serialization {
        use bitvec::prelude::*;

        use super::*;
        use crate::dto::SerializeForVersion;

        #[test]
        fn serialize_proof_nodes() {
            let nodes = ProofNodes(vec![
                TrieNode::Binary {
                    left: Felt::from_u64(0),
                    right: Felt::from_u64(1),
                },
                TrieNode::Edge {
                    child: Felt::from_u64(2),
                    path: bitvec::bitvec![u8, Msb0; 1, 1],
                },
            ]);
            let actual = nodes
                .serialize(crate::dto::Serializer {
                    version: crate::RpcVersion::default(),
                })
                .unwrap();
            let expected = serde_json::json!(
                [
                    {
                        "binary": {
                            "left": "0x0",
                            "right": "0x1",
                        }
                    },
                    {
                        "edge": {
                            "path": {
                                "value": "0x3",
                                "len": 2,
                            },
                            "child": "0x2",
                        }
                    },
                ]
            );
            assert_eq!(actual, expected);
        }
    }

    mod get_proof {
        use super::*;

        #[tokio::test]
        async fn success() {
            let context = RpcContext::for_tests();

            let input = GetProofInput {
                block_id: BlockId::Number(pathfinder_common::BlockNumber::GENESIS + 2),
                contract_address: contract_address_bytes!(b"contract 2 (sierra)"),
                keys: vec![storage_address_bytes!(b"storage addr 0")],
            };

            get_proof(context, input).await.unwrap();
        }

        #[tokio::test]
        async fn limit_exceeded() {
            let context = RpcContext::for_tests();
            let input = GetProofInput {
                block_id: BlockId::Latest,
                contract_address: contract_address!("0xdeadbeef"),
                keys: (0..10_000)
                    .map(|idx| StorageAddress::new_or_panic(Felt::from_u64(idx)))
                    .collect(),
            };

            let err = get_proof(context, input).await.unwrap_err();
            assert_matches::assert_matches!(err, GetProofError::ProofLimitExceeded { .. });
        }

        #[tokio::test]
        async fn proof_pruned() {
            let context =
                RpcContext::for_tests_with_trie_pruning(pathfinder_storage::TriePruneMode::Prune {
                    num_blocks_kept: 0,
                });
            let mut conn = context.storage.connection().unwrap();
            let tx = conn.transaction().unwrap();

            // Ensure that all storage tries are pruned, hence the node does not store
            // historic proofs.
            tx.insert_storage_trie(
                &pathfinder_storage::TrieUpdate {
                    nodes_added: vec![(Felt::from_u64(0), pathfinder_storage::Node::LeafBinary)],
                    nodes_removed: (0..100).map(pathfinder_storage::TrieStorageIndex).collect(),
                    root_commitment: Felt::ZERO,
                },
                BlockNumber::GENESIS + 3,
            )
            .unwrap();
            tx.commit().unwrap();
            let tx = conn.transaction().unwrap();
            tx.insert_storage_trie(
                &pathfinder_storage::TrieUpdate {
                    nodes_added: vec![(Felt::from_u64(1), pathfinder_storage::Node::LeafBinary)],
                    nodes_removed: vec![],
                    root_commitment: Felt::ZERO,
                },
                BlockNumber::GENESIS + 4,
            )
            .unwrap();
            tx.commit().unwrap();
            drop(conn);

            let input = GetProofInput {
                block_id: BlockId::Latest,
                contract_address: contract_address_bytes!(b"contract 1"),
                keys: vec![storage_address_bytes!(b"storage addr 0")],
            };
            let err = get_proof(context, input).await.unwrap_err();
            assert_matches::assert_matches!(err, GetProofError::ProofMissing);
        }

        #[tokio::test]
        async fn chain_without_contract_updates() {
            let storage =
                pathfinder_storage::StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
                    pathfinder_storage::TriePruneMode::Archive,
                    NonZeroU32::new(5).unwrap(),
                )
                .unwrap();
            let blocks = pathfinder_storage::fake::generate::with_config(
                1,
                pathfinder_storage::fake::Config {
                    occurrence: pathfinder_storage::fake::OccurrencePerBlock {
                        nonce: 0..=0,
                        storage: 0..=0,
                        system_storage: 0..=0,
                        ..Default::default()
                    },
                    update_tries: Box::new(update_starknet_state),
                    ..Default::default()
                },
            );

            pathfinder_storage::fake::fill(
                &storage,
                &blocks,
                Some(Box::new(update_starknet_state)),
            );

            let context = RpcContext::for_tests().with_storage(storage);

            let input = GetProofInput {
                block_id: BlockId::Latest,
                contract_address: contract_address!("0xabcd"),
                keys: vec![storage_address!("0x1234")],
            };

            let output = get_proof(context, input).await.unwrap();
            assert!(output.contract_proof.0.is_empty());
            assert!(output.contract_data.is_none());
        }
    }

    mod get_class_proof {
        use pathfinder_storage::fake::{Config, OccurrencePerBlock};
        use pathfinder_storage::{StorageBuilder, TriePruneMode};

        use super::*;

        #[tokio::test]
        async fn success() {
            let context = RpcContext::for_tests();

            let input = GetClassProofInput {
                block_id: BlockId::Number(pathfinder_common::BlockNumber::GENESIS + 2),
                class_hash: class_hash_bytes!(b"class 2 hash (sierra)"),
            };

            get_class_proof(context, input).await.unwrap();
        }

        #[tokio::test]
        async fn proof_pruned() {
            let storage = StorageBuilder::in_memory_with_trie_pruning(TriePruneMode::Prune {
                num_blocks_kept: 0,
            })
            .unwrap();

            let blocks = pathfinder_storage::fake::generate::with_config(
                1,
                Config {
                    occurrence: OccurrencePerBlock {
                        sierra: 1..=10,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pathfinder_storage::fake::fill(
                &storage, &blocks, /* Simulates pruned tries */ None,
            );

            let context = RpcContext::for_tests().with_storage(storage);
            let class_hash = ClassHash(blocks.first().unwrap().sierra_defs.first().unwrap().0 .0);

            let input = GetClassProofInput {
                block_id: BlockId::Latest,
                // Declared in the block but the tries are missing
                class_hash,
            };

            let err = get_class_proof(context, input).await.unwrap_err();
            assert_matches::assert_matches!(err, GetProofError::ProofMissing);
        }

        #[tokio::test]
        async fn chain_without_class_declarations() {
            let storage =
                pathfinder_storage::StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
                    pathfinder_storage::TriePruneMode::Archive,
                    NonZeroU32::new(5).unwrap(),
                )
                .unwrap();
            let blocks = pathfinder_storage::fake::generate::with_config(
                1,
                pathfinder_storage::fake::Config {
                    occurrence: pathfinder_storage::fake::OccurrencePerBlock {
                        cairo: 0..=0,
                        sierra: 0..=0,
                        ..Default::default()
                    },
                    update_tries: Box::new(update_starknet_state),
                    ..Default::default()
                },
            );

            pathfinder_storage::fake::fill(
                &storage,
                &blocks,
                Some(Box::new(update_starknet_state)),
            );

            let context = RpcContext::for_tests().with_storage(storage);

            let input = GetClassProofInput {
                block_id: BlockId::Latest,
                class_hash: class_hash!("0xabcd"),
            };

            let output = get_class_proof(context, input).await.unwrap();
            assert_eq!(
                output,
                GetClassProofOutput {
                    class_commitment: None,
                    class_proof: ProofNodes(vec![])
                }
            );
        }
    }
}
