pub mod dto;

use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V07)
        .register("starknet_blockHashAndNumber",                  crate::method::block_hash_and_number)
        .register("starknet_blockNumber",                         crate::method::block_number)
        .register("starknet_chainId",                             crate::method::chain_id)
        .register("starknet_getBlockTransactionCount",            crate::method::get_block_transaction_count)
        .register("starknet_getClass",                            crate::method::get_class)
        .register("starknet_getClassAt",                          crate::method::get_class_at)
        .register("starknet_getClassHashAt",                      crate::method::get_class_hash_at)
        .register("starknet_getEvents",                           crate::method::get_events)
        .register("starknet_getNonce",                            crate::method::get_nonce)
        .register("starknet_getStateUpdate",                      crate::method::get_state_update)
        .register("starknet_getStorageAt",                        crate::method::get_storage_at)
        .register("starknet_syncing",                             crate::method::syncing)
        .register("starknet_getTransactionReceipt",               crate::method::get_transaction_receipt)
        .register("starknet_getTransactionStatus",                crate::method::get_transaction_status)
        .register("starknet_call",                                crate::method::call)
        .register("starknet_addDeclareTransaction",               crate::method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction",         crate::method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction",                crate::method::add_invoke_transaction)
        .register("starknet_getTransactionByBlockIdAndIndex",     crate::method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash",                crate::method::get_transaction_by_hash)
        .register("starknet_estimateFee",                         crate::method::estimate_fee)
        .register("starknet_estimateMessageFee",                  crate::method::estimate_message_fee)
        .register("starknet_getBlockWithTxHashes",                crate::method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs",                     crate::method::get_block_with_txs)
        .register("starknet_simulateTransactions",                crate::method::simulate_transactions)
        .register("starknet_traceBlockTransactions",              crate::method::trace_block_transactions)
        .register("starknet_traceTransaction",                    crate::method::trace_transaction)
        .register("starknet_getBlockWithReceipts",                crate::method::get_block_with_receipts)
        .register("pathfinder_getProof",                          crate::pathfinder::methods::get_proof)
        .register("starknet_specVersion",                         || "0.7.1")
}
