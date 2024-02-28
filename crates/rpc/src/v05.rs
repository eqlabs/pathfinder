use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

pub(crate) mod method;
pub(crate) mod types;

use crate::v02::method as v02_method;
use crate::v03::method as v03_method;
use crate::v04::method as v04_method;

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::V05)
        .register("starknet_blockHashAndNumber"              , v02_method::block_hash_and_number)
        .register("starknet_blockNumber"                     , v02_method::block_number)
        .register("starknet_chainId"                         , v02_method::chain_id)
        .register("starknet_getBlockTransactionCount"        , v02_method::get_block_transaction_count)
        .register("starknet_getClass"                        , v02_method::get_class)
        .register("starknet_getClassAt"                      , v02_method::get_class_at)
        .register("starknet_getClassHashAt"                  , v02_method::get_class_hash_at)
        .register("starknet_getNonce"                        , v02_method::get_nonce)
        .register("starknet_getStorageAt"                    , v02_method::get_storage_at)
        
        .register("starknet_getEvents"                       , v03_method::get_events)
        .register("starknet_getStateUpdate"                  , v03_method::get_state_update)

        .register("starknet_addDeclareTransaction"           , v04_method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction"     , v04_method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction"            , v04_method::add_invoke_transaction)
        .register("starknet_getTransactionByBlockIdAndIndex" , v04_method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash"            , v04_method::get_transaction_by_hash)
        .register("starknet_getTransactionReceipt"           , method::get_transaction_receipt)
        .register("starknet_syncing"                         , v04_method::syncing)

        .register("starknet_call"                            , method::call)
        .register("starknet_estimateFee"                     , method::estimate_fee)
        .register("starknet_estimateMessageFee"              , method::estimate_message_fee)
        .register("starknet_getBlockWithTxHashes"            , method::get_block_with_tx_hashes)
        .register("starknet_getBlockWithTxs"                 , method::get_block_with_txs)
        .register("starknet_getTransactionStatus"            , method::get_transaction_status)
        .register("starknet_simulateTransactions"            , method::simulate_transactions)
        .register("starknet_specVersion"                     , || "0.5.1")
        .register("starknet_traceBlockTransactions"          , method::trace_block_transactions)
        .register("starknet_traceTransaction"                , method::trace_transaction)

        .register("pathfinder_getProof"                      , crate::pathfinder::methods::get_proof)
        .register("pathfinder_getTransactionStatus"          , crate::pathfinder::methods::get_transaction_status)
}
