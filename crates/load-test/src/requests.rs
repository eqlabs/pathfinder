use goose::prelude::*;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;

use pathfinder_lib::core::{
    BlockId, ContractAddress, StarknetBlockHash, StarknetBlockNumber, StarknetTransactionHash,
    StarknetTransactionIndex, StorageAddress, StorageValue,
};
use pathfinder_lib::rpc::v01::types::{
    reply::{
        Block, GetEventsResult, Transaction as StarknetTransaction,
        TransactionReceipt as StarknetTransactionReceipt,
    },
    request::EventFilter,
};

type GooseTransactionError = goose::goose::TransactionError;
type MethodResult<T> = Result<T, GooseTransactionError>;

pub async fn get_block_by_number(
    user: &mut GooseUser,
    block_number: StarknetBlockNumber,
) -> MethodResult<Block> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockWithTxHashes",
        json!({ "block_id": { "block_number": block_number } }),
    )
    .await
}

pub async fn get_block_by_hash(
    user: &mut GooseUser,
    block_hash: StarknetBlockHash,
) -> MethodResult<Block> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockWithTxHashes",
        json!({ "block_id": { "block_hash": block_hash } }),
    )
    .await
}

pub async fn get_transaction_by_hash(
    user: &mut GooseUser,
    hash: StarknetTransactionHash,
) -> MethodResult<StarknetTransaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByHash",
        json!({ "transaction_hash": hash }),
    )
    .await
}

pub async fn get_transaction_by_block_hash_and_index(
    user: &mut GooseUser,
    block_hash: StarknetBlockHash,
    index: StarknetTransactionIndex,
) -> MethodResult<StarknetTransaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByBlockIdAndIndex",
        json!({ "block_id": {"block_hash": block_hash}, "index": index }),
    )
    .await
}

pub async fn get_transaction_by_block_number_and_index(
    user: &mut GooseUser,
    block_number: StarknetBlockNumber,
    index: StarknetTransactionIndex,
) -> MethodResult<StarknetTransaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByBlockIdAndIndex",
        json!({ "block_id": {"block_number": block_number}, "index": index }),
    )
    .await
}

pub async fn get_transaction_receipt_by_hash(
    user: &mut GooseUser,
    hash: StarknetTransactionHash,
) -> MethodResult<StarknetTransactionReceipt> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionReceipt",
        json!({ "transaction_hash": hash }),
    )
    .await
}

pub async fn get_block_transaction_count_by_hash(
    user: &mut GooseUser,
    hash: StarknetBlockHash,
) -> MethodResult<u64> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockTransactionCount",
        json!({ "block_id": { "block_hash": hash } }),
    )
    .await
}

pub async fn get_block_transaction_count_by_number(
    user: &mut GooseUser,
    number: StarknetBlockNumber,
) -> MethodResult<u64> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockTransactionCount",
        json!({ "block_id": { "block_number": number } }),
    )
    .await
}

pub async fn block_number(user: &mut GooseUser) -> MethodResult<u64> {
    post_jsonrpc_request(user, "starknet_blockNumber", json!({})).await
}

pub async fn syncing(user: &mut GooseUser) -> MethodResult<serde_json::Value> {
    post_jsonrpc_request(user, "starknet_syncing", json!({})).await
}

pub async fn chain_id(user: &mut GooseUser) -> MethodResult<String> {
    post_jsonrpc_request(user, "starknet_chainId", json!({})).await
}

pub async fn get_events(
    user: &mut GooseUser,
    filter: EventFilter,
) -> MethodResult<GetEventsResult> {
    post_jsonrpc_request(user, "starknet_getEvents", json!({ "filter": filter })).await
}

pub async fn get_storage_at(
    user: &mut GooseUser,
    contract_address: ContractAddress,
    key: StorageAddress,
    block_id: BlockId,
) -> MethodResult<StorageValue> {
    post_jsonrpc_request(
        user,
        "starknet_getStorageAt",
        json!({ "contract_address": contract_address, "key": key, "block_id": block_id }),
    )
    .await
}

pub async fn call(
    user: &mut GooseUser,
    contract_address: ContractAddress,
    call_data: &[&str],
    entry_point_selector: &str,
    at_block: BlockId,
) -> MethodResult<Vec<String>> {
    post_jsonrpc_request(
        user,
        "starknet_call",
        json!({
            "request": {
                "contract_address": contract_address,
                "calldata": call_data,
                "entry_point_selector": entry_point_selector,
            },
            "block_id": at_block,
        }),
    )
    .await
}

async fn post_jsonrpc_request<T: DeserializeOwned>(
    user: &mut GooseUser,
    method: &str,
    params: serde_json::Value,
) -> MethodResult<T> {
    let request = jsonrpc_request(method, params);
    let response = user.post_json("", &request).await?.response?;
    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }
    let response: TransactionReceiptResponse<T> = response.json().await?;

    Ok(response.result)
}

fn jsonrpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    })
}
