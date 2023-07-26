use crate::module::Module;

mod method;

use crate::v02::method as v02_method;
use crate::v03::method as v03_method;
use crate::v04::method as v04_method;

/// Registers all methods for the v0.3 RPC API
pub fn register_methods(module: Module) -> anyhow::Result<Module> {
    let module = module
        // Reused from v0.2
        .register_method(
            "v0.4_starknet_addDeclareTransaction",
            v04_method::add_declare_transaction,
        )?
        .register_method(
            "v0.4_starknet_addDeployAccountTransaction",
            v04_method::add_deploy_account_transaction,
        )?
        .register_method(
            "v0.4_starknet_addInvokeTransaction",
            v04_method::add_invoke_transaction,
        )?
        .register_method_with_no_input(
            "v0.4_starknet_blockHashAndNumber",
            v02_method::block_hash_and_number,
        )?
        .register_method_with_no_input("v0.4_starknet_blockNumber", v02_method::block_number)?
        .register_method("v0.4_starknet_call", v02_method::call)?
        .register_method_with_no_input("v0.4_starknet_chainId", v02_method::chain_id)?
        .register_method("v0.4_starknet_estimateFee", v03_method::estimate_fee)?
        .register_method(
            "v0.4_starknet_getBlockWithTxHashes",
            v02_method::get_block_with_tx_hashes,
        )?
        .register_method(
            "v0.4_starknet_getBlockWithTxs",
            v02_method::get_block_with_txs,
        )?
        .register_method(
            "v0.4_starknet_getBlockTransactionCount",
            v02_method::get_block_transaction_count,
        )?
        .register_method("v0.4_starknet_getClass", v02_method::get_class)?
        .register_method("v0.4_starknet_getClassAt", v02_method::get_class_at)?
        .register_method(
            "v0.4_starknet_getClassHashAt",
            v02_method::get_class_hash_at,
        )?
        .register_method("v0.4_starknet_getNonce", v02_method::get_nonce)?
        .register_method("v0.4_starknet_getStorageAt", v02_method::get_storage_at)?
        .register_method(
            "v0.4_starknet_getTransactionByBlockIdAndIndex",
            v02_method::get_transaction_by_block_id_and_index,
        )?
        .register_method(
            "v0.4_starknet_getTransactionByHash",
            v02_method::get_transaction_by_hash,
        )?
        .register_method(
            "v0.4_starknet_getTransactionReceipt",
            v04_method::get_transaction_receipt,
        )?
        .register_method_with_no_input(
            "v0.4_starknet_pendingTransactions",
            v02_method::pending_transactions,
        )?
        .register_method_with_no_input("v0.4_starknet_syncing", v04_method::syncing)?
        // Specific implementations for v0.3
        .register_method("v0.4_starknet_getEvents", v03_method::get_events)?
        .register_method("v0.4_starknet_getStateUpdate", v03_method::get_state_update)?
        .register_method(
            "v0.4_starknet_simulateTransactions",
            v04_method::simulate_transactions,
        )?
        .register_method(
            "v0.4_pathfinder_getProof",
            crate::pathfinder::methods::get_proof,
        )?
        .register_method(
            "v0.4_pathfinder_getTransactionStatus",
            crate::pathfinder::methods::get_transaction_status,
        )?
        // Specific v0.4 implementations
        .register_method(
            "v0.4_starknet_estimateMessageFee",
            v04_method::estimate_message_fee,
        )?;

    Ok(module)
}
