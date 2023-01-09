use goose::prelude::*;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;

use stark_hash::Felt;

use crate::types::{
    Block, ContractClass, FeeEstimate, StateUpdate, Transaction, TransactionReceipt,
};

type MethodResult<T> = Result<T, Box<goose::goose::TransactionError>>;

pub async fn get_block_by_number(user: &mut GooseUser, block_number: u64) -> MethodResult<Block> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockWithTxHashes",
        json!({ "block_id": { "block_number": block_number } }),
    )
    .await
}

pub async fn get_block_by_hash(user: &mut GooseUser, block_hash: Felt) -> MethodResult<Block> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockWithTxHashes",
        json!({ "block_id": { "block_hash": block_hash } }),
    )
    .await
}

pub async fn get_state_update(user: &mut GooseUser, block_hash: Felt) -> MethodResult<StateUpdate> {
    post_jsonrpc_request(
        user,
        "starknet_getStateUpdate",
        json!({ "block_id": { "block_hash": block_hash }}),
    )
    .await
}

pub async fn get_transaction_by_hash(
    user: &mut GooseUser,
    hash: Felt,
) -> MethodResult<Transaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByHash",
        json!({ "transaction_hash": hash }),
    )
    .await
}

pub async fn get_transaction_by_block_hash_and_index(
    user: &mut GooseUser,
    block_hash: Felt,
    index: usize,
) -> MethodResult<Transaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByBlockIdAndIndex",
        json!({ "block_id": {"block_hash": block_hash}, "index": index }),
    )
    .await
}

pub async fn get_transaction_by_block_number_and_index(
    user: &mut GooseUser,
    block_number: u64,
    index: usize,
) -> MethodResult<Transaction> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionByBlockIdAndIndex",
        json!({ "block_id": {"block_number": block_number}, "index": index }),
    )
    .await
}

pub async fn get_transaction_receipt_by_hash(
    user: &mut GooseUser,
    hash: Felt,
) -> MethodResult<TransactionReceipt> {
    post_jsonrpc_request(
        user,
        "starknet_getTransactionReceipt",
        json!({ "transaction_hash": hash }),
    )
    .await
}

pub async fn get_block_transaction_count_by_hash(
    user: &mut GooseUser,
    hash: Felt,
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
    number: u64,
) -> MethodResult<u64> {
    post_jsonrpc_request(
        user,
        "starknet_getBlockTransactionCount",
        json!({ "block_id": { "block_number": number } }),
    )
    .await
}

pub async fn get_class(
    user: &mut GooseUser,
    block_hash: Felt,
    class_hash: Felt,
) -> MethodResult<ContractClass> {
    post_jsonrpc_request(
        user,
        "starknet_getClass",
        json!({ "block_id": { "block_hash": block_hash }, "class_hash": class_hash }),
    )
    .await
}

pub async fn get_class_hash_at(
    user: &mut GooseUser,
    block_hash: Felt,
    contract_address: Felt,
) -> MethodResult<Felt> {
    post_jsonrpc_request(
        user,
        "starknet_getClassHashAt",
        json!({ "block_id": { "block_hash": block_hash }, "contract_address": contract_address }),
    )
    .await
}

pub async fn get_class_at(
    user: &mut GooseUser,
    block_hash: Felt,
    contract_address: Felt,
) -> MethodResult<ContractClass> {
    post_jsonrpc_request(
        user,
        "starknet_getClassAt",
        json!({ "block_id": { "block_hash": block_hash }, "contract_address": contract_address }),
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
    let from_block = block_number_to_block_id(filter.from_block);
    let to_block = block_number_to_block_id(filter.to_block);
    post_jsonrpc_request(
        user,
        "starknet_getEvents",
        json!({ "filter": {
            "from_block": from_block,
            "to_block": to_block,
            "address": filter.address,
            "keys": filter.keys,
            "chunk_size": 1000,
        }}),
    )
    .await
}

pub struct EventFilter {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub address: Option<Felt>,
    pub keys: Vec<Felt>,
    pub page_size: u64,
    pub page_number: u64,
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
pub struct GetEventsResult {
    pub events: Vec<serde_json::Value>,
    pub continuation_token: Option<String>,
}

fn block_number_to_block_id(number: Option<u64>) -> serde_json::Value {
    match number {
        Some(number) => json!({ "block_number": number }),
        None => serde_json::Value::Null,
    }
}

pub async fn get_storage_at(
    user: &mut GooseUser,
    contract_address: Felt,
    key: Felt,
    block_hash: Felt,
) -> MethodResult<Felt> {
    post_jsonrpc_request(
        user,
        "starknet_getStorageAt",
        json!({ "contract_address": contract_address, "key": key, "block_id": {"block_hash": block_hash} }),
    )
    .await
}

pub async fn call(
    user: &mut GooseUser,
    contract_address: Felt,
    call_data: &[&str],
    entry_point_selector: &str,
    at_block: Felt,
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
            "block_id": {"block_hash": at_block},
        }),
    )
    .await
}

pub async fn estimate_fee_for_invoke(
    user: &mut GooseUser,
    contract_address: Felt,
    call_data: &[Felt],
    entry_point_selector: Felt,
    max_fee: Felt,
    at_block: Felt,
) -> MethodResult<FeeEstimate> {
    post_jsonrpc_request(
        user,
        "starknet_estimateFee",
        json!({
            "request": {
                "type": "INVOKE",
                "version": "0x0",
                "max_fee": max_fee,
                "signature": [],
                "contract_address": contract_address,
                "calldata": call_data,
                "entry_point_selector": entry_point_selector,
            },
            "block_id": {"block_hash": at_block}
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
    let response = user
        .post_json("/rpc/v0.2", &request)
        .await?
        .response
        .map_err(|e| Box::new(e.into()))?;
    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }
    let response: TransactionReceiptResponse<T> =
        response.json().await.map_err(|e| Box::new(e.into()))?;

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
