use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V06)
        .register("starknet_blockNumber",                         crate::method::block_number)
        .register("starknet_chainId",                             crate::method::chain_id)
        .register("starknet_getBlockTransactionCount",            crate::method::get_block_transaction_count)
        .register("starknet_getNonce",                            crate::method::get_nonce)
        .register("starknet_getStorageAt",                        crate::method::get_storage_at)
        .register("starknet_getTransactionByHash",                crate::method::get_transaction_by_hash)
        .register("starknet_getTransactionByBlockIdAndIndex",     crate::method::get_transaction_by_block_id_and_index)
}
