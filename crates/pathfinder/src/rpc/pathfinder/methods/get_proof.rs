use anyhow::{anyhow, Context};
use serde::ser::SerializeStructVariant;
use serde::{Deserialize, Serialize};

use crate::rpc::v02::RpcContext;
use crate::state::merkle_tree::ProofNode;
use crate::state::state_tree::{ContractsStateTree, GlobalStateTree};
use pathfinder_common::{
    BlockId, ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
    StorageAddress,
};
use pathfinder_storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};
use stark_hash::StarkHash;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct GetProofInput {
    pub contract_address: ContractAddress,
    pub keys: Vec<StorageAddress>,
    pub block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetProofError: BlockNotFound);

/// Utility struct used for serializing.
#[derive(Debug, Serialize)]
struct PathWrapper {
    value: StarkHash,
    len: usize,
}

impl Serialize for ProofNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self {
            ProofNode::Binary(bin) => {
                let mut state = serializer.serialize_struct_variant("ProofNode", 0, "Binary", 2)?;
                state.serialize_field("left", &bin.left_hash)?;
                state.serialize_field("right", &bin.right_hash)?;
                state.end()
            }
            ProofNode::Edge(edge) => {
                let value = StarkHash::from_bits(edge.path.as_bitslice()).unwrap();
                let path_wrapper = PathWrapper {
                    value,
                    len: edge.path.len(),
                };

                let mut state = serializer.serialize_struct_variant("ProofNode", 1, "Edge", 2)?;
                state.serialize_field("path", &path_wrapper)?;
                state.serialize_field("child", &edge.child_hash)?;
                state.end()
            }
        }
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
    contract_state_hash_version: StarkHash,

    /// The proofs associated with the queried storage values
    storage_proofs: Vec<Vec<ProofNode>>,
}

/// Holds the membership/non-membership of a contract and its associated contract contract if the contract exists.
#[derive(Debug, Serialize)]
pub struct GetProofOutput {
    /// Membership / Non-membership proof for the queried contract
    contract_proof: Vec<ProofNode>,

    /// Additional contract data if it exists.
    contract_data: Option<ContractData>,
}

/// Returns all the necessary data to trustlessly verify storage slots for a particular contract.
pub async fn get_proof(
    context: RpcContext,
    input: GetProofInput,
) -> Result<GetProofOutput, GetProofError> {
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
        let global_root = StarknetBlocksTable::get_root(&tx, block_id)
            .context("Get global root for block")?
            // Since the db query succeeded in execution, we can now report if the block hash was indeed not found
            // by using a dedicated error code from the RPC API spec
            .ok_or(GetProofError::BlockNotFound)?;

        let global_state_tree =
            GlobalStateTree::load(&tx, global_root).context("Global state tree")?;

        // Generate a proof for this contract. If the contract does not exist, this will
        // be a "non membership" proof.
        let contract_proof = global_state_tree.get_proof(&input.contract_address)?;

        let contract_state_hash = match global_state_tree.get(input.contract_address)? {
            Some(contract_state_hash) => contract_state_hash,
            None => {
                // Contract not found: return the proof of non membership that we generated earlier.
                return Ok(GetProofOutput {
                    contract_proof,
                    contract_data: None,
                });
            }
        };

        let (contract_state_root, nonce) =
            ContractsStateTable::get_root_and_nonce(&tx, contract_state_hash)
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

        let class_hash = read_class_hash(&tx, contract_state_hash)
            .context("Reading class hash from state table")?
            // Class hash should not be None at this stage since we have a valid block and non-zero contract state_hash.
            .ok_or_else(|| -> GetProofError {
                tracing::error!(%contract_state_hash, "Class hash is missing in `contract_states` table");
                anyhow::anyhow!("State table missing row for state_hash={}", contract_state_hash).into()
            })?;

        let storage_proofs = input
            .keys
            .iter()
            .map(|k| contract_state_tree.get_proof(k.view_bits()))
            .collect::<anyhow::Result<Vec<Vec<ProofNode>>>>()
            .context("Get proof from contract state treee")?;

        let contract_data = ContractData {
            class_hash,
            nonce,
            root: contract_state_root,
            contract_state_hash_version: StarkHash::ZERO, // Currently, this is defined as 0. Might change in the future.
            storage_proofs,
        };

        Ok(GetProofOutput {
            contract_proof,
            contract_data: Some(contract_data),
        })
    });

    jh.await.context("Database read panic or shutting down")?
}

/// Returns the [ClassHash] for the given [ContractStateHash] from the database.
// Copied from `get_class_hash_at.rs`
fn read_class_hash(
    tx: &rusqlite::Transaction<'_>,
    state_hash: ContractStateHash,
) -> anyhow::Result<Option<ClassHash>> {
    use rusqlite::OptionalExtension;

    tx.query_row(
        "SELECT hash FROM contract_states WHERE state_hash=?",
        [state_hash],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| e.into())
}
