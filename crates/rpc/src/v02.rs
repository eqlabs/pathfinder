use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;

mod common;
pub mod method;
pub mod types;

/// Registers all methods for the v0.2 RPC API
pub fn register_methods(context: RpcContext) -> anyhow::Result<Methods> {
    let methods = crate::module::Module::new(context)
        .register_method("starknet_call", method::call)?
        .register_method_with_no_input("starknet_chainId", method::chain_id)?
        .register_method(
            "starknet_getBlockWithTxHashes",
            method::get_block_with_tx_hashes,
        )?
        .register_method("starknet_getBlockWithTxs", method::get_block_with_txs)?
        .register_method("starknet_getClass", method::get_class)?
        .register_method("starknet_getClassAt", method::get_class_at)?
        .register_method("starknet_getClassHashAt", method::get_class_hash_at)?
        .register_method("starknet_getEvents", method::get_events)?
        .register_method("starknet_estimateFee", method::estimate_fee)?
        .register_method("starknet_getNonce", method::get_nonce)?
        .register_method_with_no_input(
            "starknet_pendingTransactions",
            method::pending_transactions,
        )?
        .register_method("starknet_getStateUpdate", method::get_state_update)?
        .register_method("starknet_getStorageAt", method::get_storage_at)?
        .register_method(
            "starknet_getTransactionByHash",
            method::get_transaction_by_hash,
        )?
        .register_method(
            "starknet_getTransactionByBlockIdAndIndex",
            method::get_transaction_by_block_id_and_index,
        )?
        .register_method(
            "starknet_getTransactionReceipt",
            method::get_transaction_receipt,
        )?
        .register_method_with_no_input("starknet_syncing", method::syncing)?
        .register_method(
            "starknet_getBlockTransactionCount",
            method::get_block_transaction_count,
        )?
        .register_method_with_no_input(
            "starknet_blockHashAndNumber",
            method::block_hash_and_number,
        )?
        .register_method_with_no_input("starknet_blockNumber", method::block_number)?
        .register_method(
            "starknet_addInvokeTransaction",
            method::add_invoke_transaction,
        )?
        .register_method(
            "starknet_addDeclareTransaction",
            method::add_declare_transaction,
        )?
        .register_method(
            "starknet_addDeployAccountTransaction",
            method::add_deploy_account_transaction,
        )?
        .register_method(
            "pathfinder_getProof",
            crate::pathfinder::methods::get_proof::get_proof,
        )?
        .build();

    Ok(methods)
}
