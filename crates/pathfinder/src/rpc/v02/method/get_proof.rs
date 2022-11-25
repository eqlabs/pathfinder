use anyhow::{anyhow, Context};
use serde::Deserialize;

use crate::core::{
    BlockId, ClassHash, ContractAddress, ContractNonce, ContractRoot, ContractStateHash,
    StorageAddress,
};
use crate::rpc::v02::RpcContext;
use crate::state::merkle_tree::ProofNode;
use crate::state::state_tree::{ContractsStateTree, GlobalStateTree};
use crate::storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};
use serde::Serialize;
use stark_hash::StarkHash;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct GetStorageProofInput {
    pub contract_address: ContractAddress,
    pub key: StorageAddress,
    pub block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(
    GetStorageProofError: ContractNotFound,
    BlockNotFound
);

#[derive(Debug, Serialize)]
pub struct ContractStorage {
    // Required by the verifier to verify the contract state hash to contract root calculation.
    class_hash: ClassHash,
    nonce: ContractNonce,

    // Root of the Contract state tree
    root: ContractRoot,

    // This is currently just a constant = 0, however we should include it so the caller
    // doesn't have to worry about this.
    contract_state_hash_version: StarkHash,

    // Assuming we allow multiple queries in one. Contract root -> storage key proofs
    storage_proofs: Vec<ProofNode>, // SCOTT change to vec<vec<>>
}

/// TODO fix comments
#[derive(Debug, Serialize)]
pub struct GetStorageProofOutput {
    // This is the global root -> contract state hash proof
    contract_proof: Vec<ProofNode>,

    contract_storage: Option<ContractStorage>,
}

/// TODO: description
pub async fn get_proof(
    context: RpcContext,
    input: GetStorageProofInput,
) -> Result<GetStorageProofOutput, GetStorageProofError> {
    let block_id = match input.block_id {
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            // TODO: what to do with pending blockId?
            match context
                .pending_data
                .ok_or_else(|| anyhow!("Pending data not supported in this configuration"))?
                .state_update()
                .await
            {
                Some(_) => {
                    return Err(GetStorageProofError::Internal(anyhow!(
                        "'pending' is not currently supported by this method!"
                    )))
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

        let contract_proof = global_state_tree.get_proof(&input.contract_address)?;

        let contract_state_hash = match global_state_tree.get(input.contract_address)? {
            Some(contract_state_hash) => contract_state_hash,
            None => {
                return Ok(GetStorageProofOutput {
                    contract_proof,
                    contract_storage: None,
                })
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

        let storage_proofs = contract_state_tree
            .get_proof(input.key.view_bits())
            .context("Get proof from contract state treee")?;

        let contract_storage = ContractStorage {
            class_hash,
            nonce,
            root: contract_state_root,
            contract_state_hash_version: StarkHash::ZERO,
            storage_proofs,
        };

        Ok(GetStorageProofOutput {
            contract_proof,
            contract_storage: Some(contract_storage),
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
    use crate::core::{ContractAddress, StarknetBlockHash, StorageAddress};
    use crate::starkhash_bytes;
    use assert_matches::assert_matches;

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
        let result = get_proof(
            context.clone(),
            GetStorageProofInput {
                contract_address: *contract_address,
                key: *key,
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
    fn assert_value(expected: &'static [ProofNode]) -> TestCaseHandler {
        Box::new(|i: usize, result| {
            assert_matches!(result, Ok(values) => {
                println!("values {:?}", values.contract_storage.as_ref().unwrap().storage_proofs); // SCOTT temp
                values.contract_storage.as_ref().unwrap().storage_proofs.iter().zip(expected.iter()).for_each(|(val, exp)| assert_eq!(val, exp))});
        })
    }

    #[tokio::test]
    async fn scott() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let ctx_with_pending_empty =
            RpcContext::for_tests().with_pending_data(crate::state::PendingData::default());
        let ctx_with_pending_disabled = RpcContext::for_tests();

        let pending_contract0 =
            ContractAddress::new_or_panic(starkhash_bytes!(b"pending contract 1 address"));
        let pending_key0 = StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 0"));
        let contract1 = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
        let key0 = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0"));
        let deployment_block = BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"block 1")));
        let non_existent_key = StorageAddress::new_or_panic(starkhash_bytes!(b"non-existent"));

        let non_existent_contract =
            ContractAddress::new_or_panic(starkhash_bytes!(b"non-existent"));
        let pre_deploy_block = BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"genesis")));
        let non_existent_block =
            BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"non-existent")));

        let cases: &[(
            RpcContext,
            ContractAddress,
            StorageAddress,
            BlockId,
            TestCaseHandler,
        )] = &[
            // Pending - happy paths
            (
                ctx.clone(),
                pending_contract0,
                pending_key0,
                BlockId::Pending,
                assert_value(&[]),
            ),
            (
                ctx_with_pending_empty,
                contract1,
                key0,
                BlockId::Pending,
                // Pending data is absent, fallback to the latest block
                assert_value(&[]),
            ),
            // Other block ids - happy paths
            (
                ctx.clone(),
                contract1,
                key0,
                deployment_block,
                assert_value(&[]),
            ),
            (
                ctx.clone(),
                contract1,
                key0,
                BlockId::Latest,
                assert_value(&[]),
            ),
            (
                ctx.clone(),
                contract1,
                non_existent_key,
                BlockId::Latest,
                assert_value(&[]),
            ),
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
        ];

        for (i, test_case) in cases.iter().enumerate() {
            check(i, test_case).await;
        }
    }
}
