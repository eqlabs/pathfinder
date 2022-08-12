#![deny(rust_2018_idioms)]

//! Load test for pathfinder JSON-RPC endpoints.
//!
//! This program expects a mainnet pathfinder node synced until block 1800,
//! since it contains references to transactions and contract addresses on mainnet.
//!
//! Running the load test:
//! ```
//! cargo run --release -p load-test -- -H http://127.0.0.1:9545 --report-file /tmp/report.html -u 30 -r 5 -t 60 --no-gzip
//! ```
use goose::prelude::*;
use rand::{Rng, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use stark_hash::StarkHash;

use pathfinder_lib::{
    core::{
        BlockId, ContractAddress, StarknetBlockHash, StarknetBlockNumber, StarknetTransactionHash,
        StarknetTransactionIndex, StorageAddress, StorageValue,
    },
    rpc::types::{
        reply::{
            Block, GetEventsResult, Transaction as StarknetTransaction,
            TransactionReceipt as StarknetTransactionReceipt, Transactions as StarknetTransactions,
        },
        request::EventFilter,
    },
};

//
// Tasks
//

/// Fetch a random block, then fetch all individual transactions and receipts in the block.
async fn block_explorer(user: &mut GooseUser) -> TransactionResult {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let block_number: u64 = rng.gen_range(1..1800);

    let block = get_block_by_number(
        user,
        StarknetBlockNumber::new(block_number).expect("block_number out of range"),
    )
    .await?;
    let block_by_hash = get_block_by_hash(user, block.block_hash.unwrap()).await?;
    assert_eq!(block, block_by_hash);

    if let StarknetTransactions::HashesOnly(hashes) = block.transactions {
        for (idx, hash) in hashes.iter().enumerate() {
            let transaction = get_transaction_by_hash(user, *hash).await?;

            let transaction_by_hash_and_index = get_transaction_by_block_hash_and_index(
                user,
                block.block_hash.unwrap(),
                StarknetTransactionIndex::new_or_panic(idx as u64),
            )
            .await?;
            assert_eq!(transaction, transaction_by_hash_and_index);

            let transaction_by_number_and_index = get_transaction_by_block_number_and_index(
                user,
                block.block_number.unwrap(),
                StarknetTransactionIndex::new_or_panic(idx as u64),
            )
            .await?;
            assert_eq!(transaction, transaction_by_number_and_index);

            let _receipt = get_transaction_receipt_by_hash(user, *hash).await?;
        }
    }

    Ok(())
}

async fn task_block_by_number(user: &mut GooseUser) -> TransactionResult {
    get_block_by_number(user, StarknetBlockNumber::new_or_panic(1000)).await?;
    Ok(())
}

async fn task_block_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_block_by_hash(
        user,
        StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a",
            )
            .unwrap(),
        ),
    )
    .await?;
    Ok(())
}

async fn task_block_transaction_count_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_block_transaction_count_by_hash(
        user,
        StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a",
            )
            .unwrap(),
        ),
    )
    .await?;
    Ok(())
}

async fn task_block_transaction_count_by_number(user: &mut GooseUser) -> TransactionResult {
    get_block_transaction_count_by_number(user, StarknetBlockNumber::new_or_panic(1000)).await?;
    Ok(())
}

async fn task_transaction_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_hash(
        user,
        StarknetTransactionHash(
            StarkHash::from_hex_str(
                "0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60",
            )
            .unwrap(),
        ),
    )
    .await?;
    Ok(())
}

async fn task_transaction_by_block_number_and_index(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_block_number_and_index(
        user,
        StarknetBlockNumber::new_or_panic(1000),
        StarknetTransactionIndex::new_or_panic(3),
    )
    .await?;
    Ok(())
}

async fn task_transaction_by_block_hash_and_index(user: &mut GooseUser) -> TransactionResult {
    get_transaction_by_block_hash_and_index(
        user,
        StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a",
            )
            .unwrap(),
        ),
        StarknetTransactionIndex::new_or_panic(3),
    )
    .await?;
    Ok(())
}

async fn task_transaction_receipt_by_hash(user: &mut GooseUser) -> TransactionResult {
    get_transaction_receipt_by_hash(
        user,
        StarknetTransactionHash(
            StarkHash::from_hex_str(
                "0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60",
            )
            .unwrap(),
        ),
    )
    .await?;
    Ok(())
}

async fn task_block_number(user: &mut GooseUser) -> TransactionResult {
    block_number(user).await?;
    Ok(())
}

async fn task_syncing(user: &mut GooseUser) -> TransactionResult {
    syncing(user).await?;
    Ok(())
}

async fn task_call(user: &mut GooseUser) -> TransactionResult {
    // call a test contract deployed in block 0
    // https://voyager.online/contract/0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae
    call(
        user,
        ContractAddress::new_or_panic(
            StarkHash::from_hex_str(
                "0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae",
            )
            .unwrap(),
        ),
        &[
            // address
            "0x01e2cd4b3588e8f6f9c4e89fb0e293bf92018c96d7a93ee367d29a284223b6ff",
            // value
            "0x071d1e9d188c784a0bde95c1d508877a0d93e9102b37213d1e13f3ebc54a7751",
        ],
        // "set_value" entry point
        "0x3d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3",
        // hash of mainnet block 0
        BlockId::Hash(StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x47c3637b57c2b079b93c61539950c17e868a28f46cdef28f88521067f21e943",
            )
            .unwrap(),
        )),
    )
    .await?;
    Ok(())
}

async fn task_chain_id(user: &mut GooseUser) -> TransactionResult {
    chain_id(user).await?;
    Ok(())
}

async fn task_get_events(user: &mut GooseUser) -> TransactionResult {
    // This returns a single event.
    let events = get_events(
        user,
        EventFilter {
            from_block: Some(StarknetBlockNumber::new_or_panic(1000).into()),
            to_block: Some(StarknetBlockNumber::new_or_panic(1100).into()),
            address: Some(ContractAddress::new_or_panic(
                StarkHash::from_hex_str(
                    "0x103114c4c5ac233a360d39a9217b9067be6979f3d08e1cf971fd22baf8f8713",
                )
                .unwrap(),
            )),
            keys: vec![],
            page_size: 1024,
            page_number: 0,
        },
    )
    .await?;

    assert_eq!(events.events.len(), 1);

    Ok(())
}

async fn task_get_storage_at(user: &mut GooseUser) -> TransactionResult {
    // Taken from:
    // https://alpha-mainnet.starknet.io/feeder_gateway/get_state_update?blockNumber=1700
    //
    // "block_hash": "0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87"
    //
    // "storage_diffs": {"0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056":
    // [{"key": "0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1",
    // "value": "0x44054cde571399c485119e55cf0b9fc7dcc151fb3486f70020d3ee4d7b20f8d"}]
    get_storage_at(
        user,
        ContractAddress::new_or_panic(
            StarkHash::from_hex_str(
                "0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056",
            )
            .unwrap(),
        ),
        StorageAddress::new_or_panic(
            StarkHash::from_hex_str(
                "0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1",
            )
            .unwrap(),
        ),
        BlockId::Hash(StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87",
            )
            .unwrap(),
        )),
    )
    .await?;
    Ok(())
}

//
// Requests
//
type GooseTransactionError = goose::goose::TransactionError;
type MethodResult<T> = Result<T, GooseTransactionError>;

async fn get_block_by_number(
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

async fn get_block_by_hash(
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

async fn get_transaction_by_hash(
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

async fn get_transaction_by_block_hash_and_index(
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

async fn get_transaction_by_block_number_and_index(
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

async fn get_transaction_receipt_by_hash(
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

async fn get_block_transaction_count_by_hash(
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

async fn get_block_transaction_count_by_number(
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

async fn block_number(user: &mut GooseUser) -> MethodResult<u64> {
    post_jsonrpc_request(user, "starknet_blockNumber", json!({})).await
}

async fn syncing(user: &mut GooseUser) -> MethodResult<serde_json::Value> {
    post_jsonrpc_request(user, "starknet_syncing", json!({})).await
}

async fn chain_id(user: &mut GooseUser) -> MethodResult<String> {
    post_jsonrpc_request(user, "starknet_chainId", json!({})).await
}

async fn get_events(user: &mut GooseUser, filter: EventFilter) -> MethodResult<GetEventsResult> {
    post_jsonrpc_request(user, "starknet_getEvents", json!({ "filter": filter })).await
}

async fn get_storage_at(
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

async fn call(
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

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    use pathfinder_lib::core::EntryPoint;
    dbg!(EntryPoint::hashed("set_value".as_bytes()));

    GooseAttack::initialize()?
        // primitive operations using the database
        .register_scenario(
            scenario!("block_by_number").register_transaction(transaction!(task_block_by_number)),
        )
        .register_scenario(
            scenario!("block_by_hash").register_transaction(transaction!(task_block_by_hash)),
        )
        .register_scenario(
            scenario!("block_transaction_count_by_hash")
                .register_transaction(transaction!(task_block_transaction_count_by_hash)),
        )
        .register_scenario(
            scenario!("block_transaction_count_by_number")
                .register_transaction(transaction!(task_block_transaction_count_by_number)),
        )
        .register_scenario(
            scenario!("transaction_by_hash")
                .register_transaction(transaction!(task_transaction_by_hash)),
        )
        .register_scenario(
            scenario!("transaction_by_block_number_and_index")
                .register_transaction(transaction!(task_transaction_by_block_number_and_index)),
        )
        .register_scenario(
            scenario!("transaction_by_block_hash_and_index")
                .register_transaction(transaction!(task_transaction_by_block_hash_and_index)),
        )
        .register_scenario(
            scenario!("transaction_receipt_by_hash")
                .register_transaction(transaction!(task_transaction_receipt_by_hash)),
        )
        .register_scenario(
            scenario!("block_number").register_transaction(transaction!(task_block_number)),
        )
        .register_scenario(
            scenario!("get_events").register_transaction(transaction!(task_get_events)),
        )
        .register_scenario(
            scenario!("get_storage_at").register_transaction(transaction!(task_get_storage_at)),
        )
        // primitive operations that don't use the database
        .register_scenario(scenario!("syncing").register_transaction(transaction!(task_syncing)))
        .register_scenario(scenario!("chain_id").register_transaction(transaction!(task_chain_id)))
        // primitive operation utilizing the Cairo Python subprocesses
        .register_scenario(scenario!("call").register_transaction(transaction!(task_call)))
        // composite scenario
        .register_scenario(
            scenario!("block_explorer").register_transaction(transaction!(block_explorer)),
        )
        .execute()
        .await?;

    Ok(())
}
