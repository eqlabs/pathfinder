use crate::module::Module;

pub mod common;
pub mod method;
pub mod types;

/// Registers all methods for the v0.2 RPC API
pub fn register_methods(module: Module) -> anyhow::Result<Module> {
    let module = module
        .register_method("v0.2_starknet_call", method::call)?
        .register_method_with_no_input("v0.2_starknet_chainId", method::chain_id)?
        .register_method(
            "v0.2_starknet_getBlockWithTxHashes",
            method::get_block_with_tx_hashes,
        )?
        .register_method("v0.2_starknet_getBlockWithTxs", method::get_block_with_txs)?
        .register_method("v0.2_starknet_getClass", method::get_class)?
        .register_method("v0.2_starknet_getClassAt", method::get_class_at)?
        .register_method("v0.2_starknet_getClassHashAt", method::get_class_hash_at)?
        .register_method("v0.2_starknet_getEvents", method::get_events)?
        .register_method("v0.2_starknet_estimateFee", method::estimate_fee)?
        .register_method("v0.2_starknet_getNonce", method::get_nonce)?
        .register_method_with_no_input(
            "v0.2_starknet_pendingTransactions",
            method::pending_transactions,
        )?
        .register_method("v0.2_starknet_getStateUpdate", method::get_state_update)?
        .register_method("v0.2_starknet_getStorageAt", method::get_storage_at)?
        .register_method(
            "v0.2_starknet_getTransactionByHash",
            method::get_transaction_by_hash,
        )?
        .register_method(
            "v0.2_starknet_getTransactionByBlockIdAndIndex",
            method::get_transaction_by_block_id_and_index,
        )?
        .register_method(
            "v0.2_starknet_getTransactionReceipt",
            method::get_transaction_receipt,
        )?
        .register_method_with_no_input("v0.2_starknet_syncing", method::syncing)?
        .register_method(
            "v0.2_starknet_getBlockTransactionCount",
            method::get_block_transaction_count,
        )?
        .register_method_with_no_input(
            "v0.2_starknet_blockHashAndNumber",
            method::block_hash_and_number,
        )?
        .register_method_with_no_input("v0.2_starknet_blockNumber", method::block_number)?
        .register_method(
            "v0.2_starknet_addInvokeTransaction",
            method::add_invoke_transaction,
        )?
        .register_method(
            "v0.2_starknet_addDeclareTransaction",
            method::add_declare_transaction,
        )?
        .register_method(
            "v0.2_starknet_addDeployAccountTransaction",
            method::add_deploy_account_transaction,
        )?
        .register_method(
            "v0.2_pathfinder_getProof",
            crate::pathfinder::methods::get_proof,
        )?
        .register_method(
            "v0.2_pathfinder_getTransactionStatus",
            crate::pathfinder::methods::get_transaction_status,
        )?;

    Ok(module)
}
