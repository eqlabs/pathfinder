use crate::jsonrpc::RpcRouter;
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

#[rustfmt::skip]
pub fn rpc_router() -> RpcRouter {
    RpcRouter::builder("v0.3")
        .register("starknet_addDeclareTransaction"           ,v02_method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction"     ,v02_method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction"            ,v02_method::add_invoke_transaction)
        .register("starknet_blockHashAndNumber"              ,v02_method::block_hash_and_number)
        .register("starknet_blockNumber"                     ,v02_method::block_number)
        .register("starknet_call"                            ,v02_method::call)
        .register("starknet_chainId"                         ,v02_method::chain_id)
        .register("starknet_getBlockWithTxHashes"            ,v02_method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs"                 ,v02_method::get_block_with_txs)
        .register("starknet_getBlockTransactionCount"        ,v02_method::get_block_transaction_count)
        .register("starknet_getClass"                        ,v02_method::get_class)
        .register("starknet_getClassAt"                      ,v02_method::get_class_at)
        .register("starknet_getClassHashAt"                  ,v02_method::get_class_hash_at)
        .register("starknet_getNonce"                        ,v02_method::get_nonce)
        .register("starknet_getStorageAt"                    ,v02_method::get_storage_at)
        .register("starknet_getTransactionByBlockIdAndIndex" ,v02_method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash"            ,v02_method::get_transaction_by_hash)
        .register("starknet_getTransactionReceipt"           ,v02_method::get_transaction_receipt)
        .register("starknet_pendingTransactions"             ,v02_method::pending_transactions)
        .register("starknet_syncing"                         ,v02_method::syncing)

        .register("starknet_estimateFee"                     ,v03_method::estimate_fee)
        .register("starknet_getEvents"                       ,v03_method::get_events)
        .register("starknet_getStateUpdate"                  ,v03_method::get_state_update)
        .register("starknet_simulateTransaction"             ,v03_method::simulate_transaction)
        .register("starknet_estimateMessageFee"              ,v03_method::estimate_message_fee)

        .register("pathfinder_getProof"                      ,crate::pathfinder::methods::get_proof)
        .register("pathfinder_getTransactionStatus"          ,crate::pathfinder::methods::get_transaction_status)
        .build()
}
