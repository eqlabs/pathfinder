use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;

pub mod method;

use crate::v02::method as v02_method;

/// Registers all methods for the v0.3 RPC API
pub fn register_methods(context: RpcContext) -> anyhow::Result<Methods> {
    let methods = crate::module::Module::new(context)
        // Reused from v0.2
        .register_method(
            "starknet_addDeclareTransaction",
            v02_method::add_declare_transaction,
        )?
        .register_method(
            "starknet_addDeployAccountTransaction",
            v02_method::add_deploy_account_transaction,
        )?
        .register_method(
            "starknet_addInvokeTransaction",
            v02_method::add_invoke_transaction,
        )?
        .register_method_with_no_input(
            "starknet_blockHashAndNumber",
            v02_method::block_hash_and_number,
        )?
        .register_method_with_no_input("starknet_blockNumber", v02_method::block_number)?
        .register_method_with_no_input("starknet_chainId", v02_method::chain_id)?
        .register_method(
            "starknet_getBlockWithTxHashes",
            v02_method::get_block_with_tx_hashes,
        )?
        .register_method("starknet_getBlockWithTxs", v02_method::get_block_with_txs)?
        .register_method(
            "starknet_getBlockTransactionCount",
            v02_method::get_block_transaction_count,
        )?
        .register_method("starknet_getClass", v02_method::get_class)?
        .register_method("starknet_getClassAt", v02_method::get_class_at)?
        .register_method("starknet_getClassHashAt", v02_method::get_class_hash_at)?
        .register_method("starknet_getNonce", v02_method::get_nonce)?
        .register_method("starknet_getStorageAt", v02_method::get_storage_at)?
        .register_method(
            "starknet_getTransactionByBlockIdAndIndex",
            v02_method::get_transaction_by_block_id_and_index,
        )?
        .register_method(
            "starknet_getTransactionByHash",
            v02_method::get_transaction_by_hash,
        )?
        .register_method(
            "starknet_getTransactionReceipt",
            v02_method::get_transaction_receipt,
        )?
        .register_method_with_no_input(
            "starknet_pendingTransactions",
            v02_method::pending_transactions,
        )?
        .register_method_with_no_input("starknet_syncing", v02_method::syncing)?
        // Specific implementations for v0.3
        .register_method("starknet_getEvents", method::get_events)?
        .register_method("starknet_getStateUpdate", method::get_state_update)?
        .build();

    Ok(methods)
}
