pub mod dto;
pub mod method;

use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::v02::method as v02_method;
use crate::v03::method as v03_method;
use crate::v05::method as v05_method;
use crate::v06::method as v06_method;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V07)
        .register("starknet_blockHashAndNumber",                  crate::method::block_hash_and_number)
        .register("starknet_blockNumber",                         crate::method::block_number)
        .register("starknet_chainId",                             crate::method::chain_id)
        .register("starknet_getBlockTransactionCount",            crate::method::get_block_transaction_count)
        .register("starknet_getClass",                            crate::method::get_class)
        .register("starknet_getClassAt",                          v02_method::get_class_at)
        .register("starknet_getClassHashAt",                      crate::method::get_class_hash_at)
        .register("starknet_getNonce",                            crate::method::get_nonce)
        .register("starknet_getStorageAt",                        crate::method::get_storage_at)
        
        .register("starknet_getEvents",                           v03_method::get_events)
        .register("starknet_getStateUpdate",                      v03_method::get_state_update)

        .register("starknet_syncing",                             crate::method::syncing)

        .register("starknet_call",                                v05_method::call)
        .register("starknet_getTransactionStatus",                crate::method::get_transaction_status)

        .register("starknet_addDeclareTransaction",               v06_method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction",         v06_method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction",                v06_method::add_invoke_transaction)
        .register("starknet_getTransactionByBlockIdAndIndex",     v06_method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash",                v06_method::get_transaction_by_hash)

        .register("starknet_estimateFee",                         method::estimate_fee)
        .register("starknet_estimateMessageFee",                  method::estimate_message_fee)
        .register("starknet_getBlockWithTxHashes",                method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs",                     method::get_block_with_txs)
        .register("starknet_getTransactionReceipt",               method::get_transaction_receipt)
        .register("starknet_simulateTransactions",                method::simulate_transactions)
        .register("starknet_specVersion",                         || "0.7.1")
        .register("starknet_traceBlockTransactions",              method::trace_block_transactions)
        .register("starknet_traceTransaction",                    method::trace_transaction)
        .register("starknet_getBlockWithReceipts",                method::get_block_with_receipts)

        .register("pathfinder_getProof",                          crate::pathfinder::methods::get_proof)
}
