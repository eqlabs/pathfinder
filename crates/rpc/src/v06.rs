use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V06)
        .register("starknet_addDeclareTransaction",               crate::method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction",         crate::method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction",                crate::method::add_invoke_transaction)
        .register("starknet_blockNumber",                         crate::method::block_number)
        .register("starknet_blockHashAndNumber",                  crate::method::block_hash_and_number)
        .register("starknet_call",                                crate::method::call)
        .register("starknet_chainId",                             crate::method::chain_id)
        .register("starknet_getClass",                            crate::method::get_class)
        .register("starknet_getClassAt",                          crate::method::get_class_at)
        .register("starknet_getBlockTransactionCount",            crate::method::get_block_transaction_count)
        .register("starknet_getBlockWithTxHashes",                crate::method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs",                     crate::method::get_block_with_txs)
        .register("starknet_getClassHashAt",                      crate::method::get_class_hash_at)
        .register("starknet_getNonce",                            crate::method::get_nonce)
        .register("starknet_getStorageAt",                        crate::method::get_storage_at)
        .register("starknet_getTransactionByHash",                crate::method::get_transaction_by_hash)
        .register("starknet_getTransactionByBlockIdAndIndex",     crate::method::get_transaction_by_block_id_and_index)
        .register("starknet_specVersion",                         || "0.6.0")
        .register("starknet_syncing",                             crate::method::syncing)
        .register("pathfinder_getProof",                          crate::pathfinder::methods::get_proof)
}
