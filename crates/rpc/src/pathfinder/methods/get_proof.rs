use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::context::RpcContext;
use pathfinder_common::{
    BlockId, ClassCommitment, ClassHash, ContractAddress, ContractNonce, ContractRoot,
    StateCommitment, StorageAddress,
};
use pathfinder_merkle_tree::merkle_tree::ProofNode;
use pathfinder_merkle_tree::state_tree::{ContractsStateTree, StorageCommitmentTree};
use pathfinder_storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};
use stark_hash::Felt;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct GetProofInput {
    pub block_id: BlockId,
    pub contract_address: ContractAddress,
    pub keys: Vec<StorageAddress>,
}

// FIXME: allow `generate_rpc_error_subset!` to work with enum struct variants. This may not actually be possible though.
#[derive(Debug)]
pub enum GetProofError {
    Internal(anyhow::Error),
    BlockNotFound,
    ProofLimitExceeded { limit: u32, requested: u32 },
}
impl From<anyhow::Error> for GetProofError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}
impl From<GetProofError> for crate::error::RpcError {
    fn from(x: GetProofError) -> Self {
        match x {
            GetProofError::ProofLimitExceeded { limit, requested } => {
                Self::ProofLimitExceeded { limit, requested }
            }
            GetProofError::BlockNotFound => Self::BlockNotFound,
            GetProofError::Internal(internal) => Self::Internal(internal),
        }
    }
}

/// Utility struct used for serializing.
#[derive(Debug, Serialize)]
struct PathWrapper {
    value: Felt,
    len: usize,
}

/// Wrapper around [`Vec<ProofNode>`] as we don't control [ProofNode] in this crate.
#[derive(Debug)]
pub struct Proof(Vec<ProofNode>);

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeSeq, SerializeStructVariant};
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;

        for node in &self.0 {
            struct SerProofNode<'a>(&'a ProofNode);

            impl Serialize for SerProofNode<'_> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    match self.0 {
                        ProofNode::Binary(bin) => {
                            let mut state = serializer.serialize_struct_variant(
                                "proof_node",
                                0,
                                "binary",
                                2,
                            )?;
                            state.serialize_field("left", &bin.left_hash)?;
                            state.serialize_field("right", &bin.right_hash)?;
                            state.end()
                        }
                        ProofNode::Edge(edge) => {
                            let value = Felt::from_bits(edge.path.as_bitslice()).unwrap();
                            let path_wrapper = PathWrapper {
                                value,
                                len: edge.path.len(),
                            };

                            let mut state =
                                serializer.serialize_struct_variant("proof_node", 1, "edge", 2)?;
                            state.serialize_field("path", &path_wrapper)?;
                            state.serialize_field("child", &edge.child_hash)?;
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

    /// This is currently just a constant = 0, however it might change in the future.
    contract_state_hash_version: Felt,

    /// The proofs associated with the queried storage values
    storage_proofs: Vec<Proof>,
}

/// Holds the membership/non-membership of a contract and its associated contract contract if the contract exists.
#[derive(Debug, Serialize)]
#[skip_serializing_none]
pub struct GetProofOutput {
    /// The global state commitment for StarkNet 0.11.0 blocks onwards, if absent the hash
    /// of the first node in the [contract_proof](GetProofOutput#contract_proof) is the global state commitment.
    state_commitment: Option<StateCommitment>,
    /// Required to verify that the hash of the class commitment and the root of the [contract_proof](GetProofOutput::contract_proof)
    /// matches the [state_commitment](Self#state_commitment). Present only for StarkNet blocks 0.11.0 onwards.
    class_commitment: Option<ClassCommitment>,

    /// Membership / Non-membership proof for the queried contract
    contract_proof: Proof,

    /// Additional contract data if it exists.
    contract_data: Option<ContractData>,
}

/// Returns all the necessary data to trustlessly verify storage slots for a particular contract.
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
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            return Err(GetProofError::Internal(anyhow!(
                "'pending' is not currently supported by this method!"
            )))
        }
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let tx = db.transaction().context("Creating database transaction")?;

        // Use internal error to indicate that the process of querying for a particular block failed,
        // which is not the same as being sure that the block is not in the db.
        let (storage_commitment, class_commitment) =
            StarknetBlocksTable::get_state_commitment(&tx, block_id)
                .context("Get state commitment for block")?
                // Since the db query succeeded in execution, we can now report if the block hash was indeed not found
                // by using a dedicated error code from the RPC API spec
                .ok_or(GetProofError::BlockNotFound)?;

        let (state_commitment, class_commitment) = if class_commitment == ClassCommitment::ZERO {
            (None, None)
        } else {
            (
                Some(StateCommitment::calculate(
                    storage_commitment,
                    class_commitment,
                )),
                Some(class_commitment),
            )
        };

        let storage_commitment_tree = StorageCommitmentTree::load(&tx, storage_commitment)
            .context("Storage commitment tree")?;

        // Generate a proof for this contract. If the contract does not exist, this will
        // be a "non membership" proof.
        let contract_proof = storage_commitment_tree.get_proof(&input.contract_address)?;
        let contract_proof = Proof(contract_proof);

        let contract_state_hash = match storage_commitment_tree.get(input.contract_address)? {
            Some(contract_state_hash) => contract_state_hash,
            None => {
                // Contract not found: return the proof of non membership that we generated earlier.
                return Ok(GetProofOutput {
                    state_commitment,
                    class_commitment,
                    contract_proof,
                    contract_data: None,
                });
            }
        };

        let (contract_state_root, class_hash, nonce) =
            ContractsStateTable::get_root_class_hash_and_nonce(&tx, contract_state_hash)
                .context("Get contract state root and nonce")?
                // Root and nonce should not be None at this stage since we have a valid block and non-zero contract state_hash.
                .ok_or_else(|| -> GetProofError {
                    anyhow::anyhow!(
                        "Root or nonce missing for state_hash={}",
                        contract_state_hash
                    )
                    .into()
                })?;

        let contract_state_tree = ContractsStateTree::load(&tx, contract_state_root)
            .context("Load contract state tree")?;

        let storage_proofs = input
            .keys
            .iter()
            .map(|k| contract_state_tree.get_proof(k.view_bits()).map(Proof))
            .collect::<anyhow::Result<Vec<_>>>()
            .context("Get proof from contract state treee")?;

        let contract_data = ContractData {
            class_hash,
            nonce,
            root: contract_state_root,
            contract_state_hash_version: Felt::ZERO, // Currently, this is defined as 0. Might change in the future.
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

#[cfg(test)]
mod tests {
    use pathfinder_common::{felt, ContractAddress};

    use super::*;

    #[tokio::test]
    async fn limit_exceeded() {
        let context = RpcContext::for_tests();
        let input = GetProofInput {
            block_id: BlockId::Latest,
            contract_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
            keys: (0..10_000)
                .map(|idx| StorageAddress::new_or_panic(Felt::from_u64(idx)))
                .collect(),
        };

        let err = get_proof(context, input).await.unwrap_err();
        assert_matches::assert_matches!(err, GetProofError::ProofLimitExceeded { .. });
    }
}
