use crate::jsonrpc::RpcResult;
use crate::module::Module;

pub mod method;

use crate::v02::method as v02_method;
use method as v03_method;

/// Registers all methods for the v0.3 RPC API
pub fn register_methods(module: Module) -> anyhow::Result<Module> {
    let module = module
        // Reused from v0.2
        .register_method(
            "v0.3_starknet_addDeclareTransaction",
            v02_method::add_declare_transaction,
        )?
        .register_method(
            "v0.3_starknet_addDeployAccountTransaction",
            v02_method::add_deploy_account_transaction,
        )?
        .register_method(
            "v0.3_starknet_addInvokeTransaction",
            v02_method::add_invoke_transaction,
        )?
        .register_method_with_no_input(
            "v0.3_starknet_blockHashAndNumber",
            v02_method::block_hash_and_number,
        )?
        .register_method_with_no_input("v0.3_starknet_blockNumber", v02_method::block_number)?
        .register_method("v0.3_starknet_call", v02_method::call)?
        .register_method_with_no_input("v0.3_starknet_chainId", v02_method::chain_id)?
        .register_method("v0.3_starknet_estimateFee", v03_method::estimate_fee)?
        .register_method(
            "v0.3_starknet_getBlockWithTxHashes",
            v02_method::get_block_with_tx_hashes,
        )?
        .register_method(
            "v0.3_starknet_getBlockWithTxs",
            v02_method::get_block_with_txs,
        )?
        .register_method(
            "v0.3_starknet_getBlockTransactionCount",
            v02_method::get_block_transaction_count,
        )?
        .register_method("v0.3_starknet_getClass", v02_method::get_class)?
        .register_method("v0.3_starknet_getClassAt", v02_method::get_class_at)?
        .register_method(
            "v0.3_starknet_getClassHashAt",
            v02_method::get_class_hash_at,
        )?
        .register_method("v0.3_starknet_getNonce", v02_method::get_nonce)?
        .register_method("v0.3_starknet_getStorageAt", v02_method::get_storage_at)?
        .register_method(
            "v0.3_starknet_getTransactionByBlockIdAndIndex",
            v02_method::get_transaction_by_block_id_and_index,
        )?
        .register_method(
            "v0.3_starknet_getTransactionByHash",
            v02_method::get_transaction_by_hash,
        )?
        .register_method(
            "v0.3_starknet_getTransactionReceipt",
            v02_method::get_transaction_receipt,
        )?
        .register_method_with_no_input(
            "v0.3_starknet_pendingTransactions",
            v02_method::pending_transactions,
        )?
        .register_method_with_no_input("v0.3_starknet_syncing", v02_method::syncing)?
        // Specific implementations for v0.3
        .register_method("v0.3_starknet_getEvents", v03_method::get_events)?
        .register_method("v0.3_starknet_getStateUpdate", v03_method::get_state_update)?
        .register_method(
            "v0.3_starknet_simulateTransaction",
            v03_method::simulate_transaction,
        )?
        .register_method(
            "v0.3_starknet_estimateMessageFee",
            v03_method::estimate_message_fee,
        )?
        .register_method(
            "v0.3_pathfinder_getProof",
            crate::pathfinder::methods::get_proof,
        )?
        .register_method(
            "v0.3_pathfinder_getTransactionStatus",
            crate::pathfinder::methods::get_transaction_status,
        )?;

    Ok(module)
}

pub struct RpcHandlerV03;

#[axum::async_trait]
impl crate::jsonrpc::RpcMethodHandler for RpcHandlerV03 {
    async fn call_method(
        method: &str,
        ctx: crate::context::RpcContext,
        params: serde_json::Value,
    ) -> RpcResult {
        use crate::jsonrpc::RpcMethod;

        #[rustfmt::skip]
        let output = match method {
            "starknet_addDeclareTransaction"           => v02_method::add_declare_transaction.invoke("starknet_addDeclareTransaction", "v0.3", ctx, params).await,
            "starknet_addDeployAccountTransaction"     => v02_method::add_deploy_account_transaction.invoke("starknet_addDeployAccountTransaction", "v0.3", ctx, params).await,
            "starknet_addInvokeTransaction"            => v02_method::add_invoke_transaction.invoke("starknet_addInvokeTransaction", "v0.3", ctx, params).await,
            "starknet_blockHashAndNumber"              => v02_method::block_hash_and_number.invoke("starknet_blockHashAndNumber", "v0.3", ctx, params).await,
            "starknet_blockNumber"                     => v02_method::block_number.invoke("starknet_blockNumber", "v0.3", ctx, params).await,
            "starknet_call"                            => v02_method::call.invoke("starknet_call", "v0.3", ctx, params).await,
            "starknet_chainId"                         => v02_method::chain_id.invoke("starknet_chainId", "v0.3", ctx, params).await,
            "starknet_getBlockWithTxHashes"            => v02_method::get_block_with_tx_hashes.invoke("starknet_getBlockWithTxHashes", "v0.3", ctx, params).await,
            "starknet_getBlockWithTxs"                 => v02_method::get_block_with_txs.invoke("starknet_getBlockWithTxs", "v0.3", ctx, params).await,
            "starknet_getBlockTransactionCount"        => v02_method::get_block_transaction_count.invoke("starknet_getBlockTransactionCount", "v0.3", ctx, params).await,
            "starknet_getClass"                        => v02_method::get_class.invoke("starknet_getClass", "v0.3", ctx, params).await,
            "starknet_getClassAt"                      => v02_method::get_class_at.invoke("starknet_getClassAt", "v0.3", ctx, params).await,
            "starknet_getClassHashAt"                  => v02_method::get_class_hash_at.invoke("starknet_getClassHashAt", "v0.3", ctx, params).await,
            "starknet_getNonce"                        => v02_method::get_nonce.invoke("starknet_getNonce", "v0.3", ctx, params).await,
            "starknet_getStorageAt"                    => v02_method::get_storage_at.invoke("starknet_getStorageAt", "v0.3", ctx, params).await,
            "starknet_getTransactionByBlockIdAndIndex" => v02_method::get_transaction_by_block_id_and_index.invoke("starknet_getTransactionByBlockIdAndIndex", "v0.3", ctx, params).await,
            "starknet_getTransactionByHash"            => v02_method::get_transaction_by_hash.invoke("starknet_getTransactionByHash", "v0.3", ctx, params).await,
            "starknet_getTransactionReceipt"           => v02_method::get_transaction_receipt.invoke("starknet_getTransactionReceipt", "v0.3", ctx, params).await,
            "starknet_pendingTransactions"             => v02_method::pending_transactions.invoke("starknet_pendingTransactions", "v0.3", ctx, params).await,
            "starknet_syncing"                         => v02_method::syncing.invoke("starknet_syncing", "v0.3", ctx, params).await,

            "starknet_estimateFee"                     => v03_method::estimate_fee.invoke("starknet_estimateFee", "v0.3", ctx, params).await,
            "starknet_getEvents"                       => v03_method::get_events.invoke("starknet_getEvents", "v0.3", ctx, params).await,
            "starknet_getStateUpdate"                  => v03_method::get_state_update.invoke("starknet_getStateUpdate", "v0.3", ctx, params).await,
            "starknet_simulateTransaction"             => v03_method::simulate_transaction.invoke("starknet_simulateTransaction", "v0.3", ctx, params).await,
            "starknet_estimateMessageFee"              => v03_method::estimate_message_fee.invoke("starknet_estimateMessageFee", "v0.3", ctx, params).await,

            "pathfinder_getProof"                      => crate::pathfinder::methods::get_proof.invoke("pathfinder_getProof", "v0.3", ctx, params).await,
            "pathfinder_getTransactionStatus"          => crate::pathfinder::methods::get_transaction_status.invoke("pathfinder_getTransactionStatus", "v0.3", ctx, params).await,
            unknown => Err(crate::jsonrpc::RpcError::MethodNotFound {
                method: unknown.to_owned(),
            }),
        };

        output
    }
}
