use anyhow::{anyhow, Context};
use serde::Deserialize;
use stark_hash::StarkHash;

use crate::core::{BlockId, ContractAddress, StorageAddress, StorageValue};
use crate::rpc::v02::RpcContext;
use crate::state::state_tree::{ContractsStateTree, GlobalStateTree};
use crate::storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable};

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct GetStorageAtInput {
    contract_address: ContractAddress,
    key: StorageAddress,
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetStorageAtError: ContractNotFound, BlockNotFound);

/// Get the value of the storage at the given address and key.
pub async fn get_storage_at(
    context: RpcContext,
    input: GetStorageAtInput,
) -> Result<StorageValue, GetStorageAtError> {
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
                Some(update) => {
                    let pending_value = update
                        .state_diff
                        .storage_diffs
                        .get(&input.contract_address)
                        .and_then(|storage| {
                            storage.iter().find_map(|update| {
                                (update.key == input.key).then_some(update.value)
                            })
                        });

                    match pending_value {
                        Some(value) => return Ok(value),
                        None => StarknetBlocksBlockId::Latest,
                    }
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

        // Use internal_server_error to indicate that the process of querying for a particular block failed,
        // which is not the same as being sure that the block is not in the db.
        let global_root = StarknetBlocksTable::get_root(&tx, block_id)?
            // Since the db query succeeded in execution, we can now report if the block hash was indeed not found
            // by using a dedicated error code from the RPC API spec
            .ok_or_else(|| GetStorageAtError::BlockNotFound)?;

        let global_state_tree =
            GlobalStateTree::load(&tx, global_root).context("Global state tree")?;

        let contract_state_hash = global_state_tree
            .get(input.contract_address)
            .context("Get contract state hash from global state tree")?
            .ok_or_else(|| GetStorageAtError::ContractNotFound)?;

        let contract_state_root = ContractsStateTable::get_root(&tx, contract_state_hash)
            .context("Get contract state root")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Contract state root not found for contract state hash {}",
                    contract_state_hash.0
                )
            })?;

        let contract_state_tree = ContractsStateTree::load(&tx, contract_state_root)
            .context("Load contract state tree")?;

        let storage_val = contract_state_tree
            .get(input.key)
            .context("Get value from contract state tree")?
            .unwrap_or(StorageValue(StarkHash::ZERO));

        Ok(storage_val)
    });

    jh.await.context("Database read panic or shutting down")?
}
