use anyhow::{anyhow, Context};
use serde::Deserialize;

use crate::rpc::v02::RpcContext;
use crate::state::merkle_tree::ProofNode;
use crate::state::state_tree::{ContractsStateTree, GlobalStateTree};
use crate::storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};
use bitvec::{prelude::Msb0, slice::BitSlice};
use pathfinder_common::{
    BlockId, ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
    StorageAddress,
};
use serde::Serialize;
use stark_hash::StarkHash;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct GetStorageProofInput {
    pub contract_address: ContractAddress,
    pub keys: Vec<StorageAddress>,
    pub block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetStorageProofError: BlockNotFound);

/// Holds the data and proofs for a specific contract.
#[derive(Debug, Serialize)]
pub struct ContractData {
    // Required to verify the contract state hash to contract root calculation.
    class_hash: ClassHash,
    // Required to verify the contract state hash to contract root calculation.
    nonce: ContractNonce,

    // Root of the Contract state tree
    root: ContractRoot,

    // This is currently just a constant = 0, however it might change in the future.
    contract_state_hash_version: StarkHash,

    // The proofs associated with the queried storage values
    storage_proofs: Vec<Vec<ProofNode>>,
}

/// Holds the membership/non-membership of a contract and its associated contract contract if the contract exists.
#[derive(Debug, Serialize)]
pub struct GetStorageProofOutput {
    // Membership / Non-membership proof for the queried contract
    contract_proof: Vec<ProofNode>,

    // Additional contract data if it exists.
    contract_data: Option<ContractData>,
}

/// Returns all the necessary data to trustlessly verify storage slots for a particular contract.
pub async fn get_storage_proofs(
    context: RpcContext,
    input: GetStorageProofInput,
) -> Result<GetStorageProofOutput, GetStorageProofError> {
    let block_id = match input.block_id {
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            match context
                .pending_data
                .ok_or_else(|| anyhow!("Pending data not supported in this configuration"))?
                .state_update()
                .await
            {
                Some(_) => {
                    // TODO: add support for pending blocks
                    return Err(GetStorageProofError::Internal(anyhow!(
                        "'pending' is not currently supported by this method!"
                    )));
                }
                None => StarknetBlocksBlockId::Latest,
            }
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
            .ok_or(GetStorageProofError::BlockNotFound)?;

        let global_state_tree =
            GlobalStateTree::load(&tx, global_root).context("Global state tree")?;

        // Generate a proof for this contract. If the contract does not exist, this will
        // be a "non membership" proof.
        let contract_proof = global_state_tree.get_proof(&input.contract_address)?;

        let contract_state_hash = match global_state_tree.get(input.contract_address)? {
            Some(contract_state_hash) => contract_state_hash,
            None => {
                // Contract not found: return the proof of non membership that we generated earlier.
                return Ok(GetStorageProofOutput {
                    contract_proof,
                    contract_data: None,
                });
            }
        };

        let (contract_state_root, nonce) =
            ContractsStateTable::get_root_and_nonce(&tx, contract_state_hash)
                .context("Get contract state root and nonce")?
                // Root and nonce should not be None at this stage since we have a valid block and non-zero contract state_hash.
                .ok_or_else(|| -> GetStorageProofError {
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
            .ok_or_else(|| -> GetStorageProofError {
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

        Ok(GetStorageProofOutput {
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pathfinder_common::{starkhash_bytes, ContractAddress, StarknetBlockHash, StorageAddress};

    type TestCaseHandler = Box<dyn Fn(usize, &Result<GetStorageProofOutput, GetStorageProofError>)>;

    /// Execute a single test case and check its outcome for `get_storage_at`
    async fn check(
        test_case_idx: usize,
        test_case: &(
            RpcContext,
            ContractAddress,
            StorageAddress,
            BlockId,
            TestCaseHandler,
        ),
    ) {
        let (context, contract_address, key, block_id, f) = test_case;
        let result = get_storage_proofs(
            context.clone(),
            GetStorageProofInput {
                contract_address: *contract_address,
                keys: vec![*key],
                block_id: *block_id,
            },
        )
        .await;
        f(test_case_idx, &result);
    }

    impl PartialEq for GetStorageProofError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    /// Common assertion type for most of the error paths
    // fn assert_error(expected: GetStorageProofError) -> TestCaseHandler {
    //     Box::new(move |i: usize, result| {
    //         assert_matches!(result, Err(error) => assert_eq!(*error, expected, "test case {i}"), "test case {i}");
    //     })
    // }

    /// Common assertion type for most of the happy paths
    fn assert_value(expected: &'static [&'static [ProofNode]]) -> TestCaseHandler {
        Box::new(|_: usize, result| {
            assert_matches!(result, Ok(values) => {
            let storage_proofs = &values.contract_data.as_ref().unwrap().storage_proofs;
            storage_proofs.iter().zip(expected.iter()).for_each(|(proofs, expected_proofs)| {
                proofs.iter().zip(expected_proofs.iter()).for_each(|(val, exp)| {
                    assert_eq!(val, exp);
                })
            }
            )});
        })
    }

    // #[tokio::test]
    // async fn scott() {
    //     let ctx = RpcContext::for_tests_with_pending().await;
    //     let ctx_with_pending_empty =
    //         RpcContext::for_tests().with_pending_data(crate::state::PendingData::default());
    //     let ctx_with_pending_disabled = RpcContext::for_tests();

    //     let pending_contract0 =
    //         ContractAddress::new_or_panic(starkhash_bytes!(b"pending contract 1 address"));
    //     let pending_key0 = StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 0"));
    //     let contract1 = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
    //     let key0 = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0"));
    //     let deployment_block = BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"block 1")));
    //     let non_existent_key = StorageAddress::new_or_panic(starkhash_bytes!(b"non-existent"));

    //     let non_existent_contract =
    //         ContractAddress::new_or_panic(starkhash_bytes!(b"non-existent"));
    //     let pre_deploy_block = BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"genesis")));
    //     let non_existent_block =
    //         BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"non-existent")));

    //     let cases: &[(
    //         RpcContext,
    //         ContractAddress,
    //         StorageAddress,
    //         BlockId,
    //         TestCaseHandler,
    //     )] = &[
    //         // Pending - happy paths
    //         (
    //             ctx.clone(),
    //             pending_contract0,
    //             pending_key0,
    //             BlockId::Pending,
    //             assert_value(&[&[]]),
    //         ),
    //         (
    //             ctx_with_pending_empty,
    //             contract1,
    //             key0,
    //             BlockId::Pending,
    //             // Pending data is absent, fallback to the latest block
    //             assert_value(&[&[]]),
    //         ),
    //         // Other block ids - happy paths
    //         (
    //             ctx.clone(),
    //             contract1,
    //             key0,
    //             deployment_block,
    //             assert_value(&[&[]]),
    //         ),
    //         (
    //             ctx.clone(),
    //             contract1,
    //             key0,
    //             BlockId::Latest,
    //             assert_value(&[&[]]),
    //         ),
    //         (
    //             ctx.clone(),
    //             contract1,
    //             non_existent_key,
    //             BlockId::Latest,
    //             assert_value(&[&[]]),
    //         ),
    // Errors
    // (
    //     ctx.clone(),
    //     non_existent_contract,
    //     key0,
    //     BlockId::Latest,
    //     assert_error(GetStorageProofError::ContractNotFound),
    // ),
    // (
    //     ctx.clone(),
    //     contract1,
    //     key0,
    //     non_existent_block,
    //     assert_error(GetStorageProofError::BlockNotFound),
    // ),
    // (
    //     ctx.clone(),
    //     contract1,
    //     key0,
    //     pre_deploy_block,
    //     assert_error(GetStorageProofError::ContractNotFound),
    // ),
    // (
    //     ctx_with_pending_disabled,
    //     pending_contract0,
    //     pending_key0,
    //     BlockId::Pending,
    //     assert_error(GetStorageProofError::Internal(anyhow!(
    //         "Pending data not supported in this configuration"
    //     ))),
    // ),
    // ];

    // for (i, test_case) in cases.iter().enumerate() {
    //     check(i, test_case).await;
    // }
    // }
}
