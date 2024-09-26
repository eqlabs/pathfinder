use anyhow::{anyhow, Context};
use pathfinder_common::prelude::*;
use pathfinder_common::trie::TrieNode;
use pathfinder_common::BlockId;
use pathfinder_crypto::Felt;
use pathfinder_merkle_tree::{ClassCommitmentTree, ContractsStorageTree, StorageCommitmentTree};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::context::RpcContext;

#[derive(Debug, PartialEq, Eq)]
pub struct GetProofInput {
    pub block_id: BlockId,
    pub contract_address: ContractAddress,
    pub keys: Vec<StorageAddress>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
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
#[derive(Debug, Serialize)]
struct PathWrapper {
    value: Felt,
    len: usize,
}

/// Wrapper around [`Vec<TrieNode>`] as we don't control [TrieNode] in this
/// crate.
#[derive(Debug)]
pub struct ProofNodes(Vec<TrieNode>);

impl Serialize for ProofNodes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeSeq, SerializeStructVariant};
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;

        for node in &self.0 {
            struct SerProofNode<'a>(&'a TrieNode);

            impl Serialize for SerProofNode<'_> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    match self.0 {
                        TrieNode::Binary { left, right } => {
                            let mut state = serializer.serialize_struct_variant(
                                "proof_node",
                                0,
                                "binary",
                                2,
                            )?;
                            state.serialize_field("left", &left)?;
                            state.serialize_field("right", &right)?;
                            state.end()
                        }
                        TrieNode::Edge { child, path } => {
                            let value = Felt::from_bits(path).unwrap();
                            let path = PathWrapper {
                                value,
                                len: path.len(),
                            };

                            let mut state =
                                serializer.serialize_struct_variant("proof_node", 1, "edge", 2)?;
                            state.serialize_field("path", &path)?;
                            state.serialize_field("child", &child)?;
                            state.end()
                        }
                    }
                }
            }

            sequence.serialize_element(&SerProofNode(node))?;
        }

        sequence.end()
    }
}

/// Holds the data and proofs for a specific contract.
#[derive(Debug, Serialize)]
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

/// Holds the membership/non-membership of a contract and its associated
/// contract contract if the contract exists.
#[derive(Debug, Serialize)]
#[skip_serializing_none]
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

#[derive(Debug, Serialize)]
#[skip_serializing_none]
pub struct GetClassProofOutput {
    /// Required to verify that the hash of the class commitment and the root of
    /// the [contract_proof](GetProofOutput::contract_proof) matches the
    /// [state_commitment](Self#state_commitment). Present only for Starknet
    /// blocks 0.11.0 onwards.
    class_commitment: Option<ClassCommitment>,
    /// Membership / Non-membership proof for the queried contract classes
    class_proof: ProofNodes,
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

    let jh = tokio::task::spawn_blocking(move || {
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
        let class_commitment = match header.class_commitment {
            ClassCommitment::ZERO => None,
            other => Some(other),
        };

        // Generate a proof for this contract. If the contract does not exist, this will
        // be a "non membership" proof.
        let contract_proof =
            StorageCommitmentTree::get_proof(&tx, header.number, &input.contract_address)
                .context("Creating contract proof")?
                .ok_or(GetProofError::ProofMissing)?;
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

        let mut storage_proofs = Vec::new();
        for k in &input.keys {
            let proof = ContractsStorageTree::get_proof(
                &tx,
                input.contract_address,
                header.number,
                k.view_bits(),
            )
            .context("Get proof from contract state tree")?
            .ok_or_else(|| {
                let e = anyhow!(
                    "Storage proof missing for key {:?}, but should be present",
                    k
                );
                tracing::warn!("{e}");
                e
            })?;
            storage_proofs.push(ProofNodes(proof));
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
pub async fn get_proof_class(
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

    let jh = tokio::task::spawn_blocking(move || {
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

        let class_commitment = match header.class_commitment {
            ClassCommitment::ZERO => None,
            other => Some(other),
        };

        // Generate a proof for this class. If the class does not exist, this will
        // be a "non membership" proof.
        let class_proof = ClassCommitmentTree::get_proof(&tx, header.number, input.class_hash)
            .context("Creating class proof")?
            .ok_or(GetProofError::ProofMissing)?;
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
    use pathfinder_common::macro_prelude::*;

    use super::*;

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
                nodes_removed: (0..100).collect(),
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

        let input = GetProofInput {
            block_id: BlockId::Latest,
            contract_address: contract_address!("0xdeadbeef"),
            keys: vec![storage_address_bytes!(b"storage addr 0")],
        };
        let err = get_proof(context, input).await.unwrap_err();
        assert_matches::assert_matches!(err, GetProofError::ProofMissing);
    }
}
