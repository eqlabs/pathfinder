use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

pub(crate) mod method;
pub(crate) mod types;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V06)
        .register("starknet_blockHashAndNumber"              , crate::method::block_hash_and_number)
        .register("starknet_blockNumber"                     , crate::method::block_number)
        .register("starknet_chainId"                         , crate::method::chain_id)
        .register("starknet_getBlockTransactionCount"        , crate::method::get_block_transaction_count)
        .register("starknet_getClass"                        , crate::method::get_class)
        .register("starknet_getClassAt"                      , crate::method::get_class_at)
        .register("starknet_getClassHashAt"                  , crate::method::get_class_hash_at)
        .register("starknet_getNonce"                        , crate::method::get_nonce)
        .register("starknet_getStorageAt"                    , crate::method::get_storage_at)

        .register("starknet_getEvents"                       , crate::method::get_events)
        .register("starknet_getStateUpdate"                  , crate::method::get_state_update)

        .register("starknet_syncing"                         , method::syncing)
        .register("starknet_getTransactionStatus"            , method::get_transaction_status)
        .register("starknet_call"                            , method::call)
        .register("starknet_addDeclareTransaction"           , method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction"     , method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction"            , method::add_invoke_transaction)
        .register("starknet_estimateFee"                     , method::estimate_fee)
        .register("starknet_estimateMessageFee"              , method::estimate_message_fee)
        .register("starknet_getBlockWithTxHashes"            , method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs"                 , method::get_block_with_txs)
        .register("starknet_getTransactionByBlockIdAndIndex" , method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash"            , crate::method::get_transaction_by_hash)
        .register("starknet_getTransactionReceipt"           , method::get_transaction_receipt)
        .register("starknet_simulateTransactions"            , method::simulate_transactions)
        .register("starknet_specVersion"                     , || "0.6.0")
        .register("starknet_traceBlockTransactions"          , method::trace_block_transactions)
        .register("starknet_traceTransaction"                , method::trace_transaction)

        .register("pathfinder_getProof"                      , crate::pathfinder::methods::get_proof)
}
