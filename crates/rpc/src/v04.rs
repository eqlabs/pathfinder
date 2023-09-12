use crate::jsonrpc::RpcRouter;

mod method;
mod types;

use crate::v02::method as v02_method;
use crate::v03::method as v03_method;
use crate::v04::method as v04_method;

#[rustfmt::skip]
pub fn rpc_router() -> RpcRouter {
    RpcRouter::builder("v0.4")
        .register("starknet_blockHashAndNumber"              , v02_method::block_hash_and_number)
        .register("starknet_blockNumber"                     , v02_method::block_number)
        .register("starknet_call"                            , v02_method::call)
        .register("starknet_chainId"                         , v02_method::chain_id)
        .register("starknet_getBlockWithTxHashes"            , v02_method::get_block_with_tx_hashes)
        .register("starknet_getBlockTransactionCount"        , v02_method::get_block_transaction_count)
        .register("starknet_getClass"                        , v02_method::get_class)
        .register("starknet_getClassAt"                      , v02_method::get_class_at)
        .register("starknet_getClassHashAt"                  , v02_method::get_class_hash_at)
        .register("starknet_getNonce"                        , v02_method::get_nonce)
        .register("starknet_getStorageAt"                    , v02_method::get_storage_at)

        .register("starknet_estimateFee"                     , v03_method::estimate_fee)
        .register("starknet_getEvents"                       , v03_method::get_events)
        .register("starknet_getStateUpdate"                  , v03_method::get_state_update)

        .register("starknet_addDeclareTransaction"           , v04_method::add_declare_transaction)
        .register("starknet_addDeployAccountTransaction"     , v04_method::add_deploy_account_transaction)
        .register("starknet_addInvokeTransaction"            , v04_method::add_invoke_transaction)
        .register("starknet_getBlockWithTxs"                 , v04_method::get_block_with_txs)
        .register("starknet_getTransactionReceipt"           , v04_method::get_transaction_receipt)
        .register("starknet_syncing"                         , v04_method::syncing)
        .register("starknet_simulateTransactions"            , v04_method::simulate_transactions)
        .register("starknet_estimateMessageFee"              , v04_method::estimate_message_fee)
        .register("starknet_getTransactionByBlockIdAndIndex" , v04_method::get_transaction_by_block_id_and_index)
        .register("starknet_getTransactionByHash"            , v04_method::get_transaction_by_hash)
        .register("starknet_pendingTransactions"             , v04_method::pending_transactions)
        .register("starknet_traceTransaction"                , v04_method::trace_transaction)
        .register("starknet_traceBlockTransactions"          , v04_method::trace_block_transactions)

        .register("pathfinder_getProof"                      , crate::pathfinder::methods::get_proof)
        .register("pathfinder_getTransactionStatus"          , crate::pathfinder::methods::get_transaction_status)
        .build()
}
