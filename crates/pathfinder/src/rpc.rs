//! StarkNet node JSON-RPC related modules.
pub mod api;
pub mod serde;
pub mod types;

use crate::{
    core::{ContractAddress, StarknetTransactionHash, StarknetTransactionIndex, StorageAddress},
    rpc::{
        api::RpcApi,
        types::{
            request::{BlockResponseScope, Call},
            BlockHashOrTag, BlockNumberOrTag,
        },
    },
    sequencer,
    storage::Storage,
};
use ::serde::Deserialize;
use jsonrpsee::{
    http_server::{HttpServerBuilder, HttpServerHandle, RpcModule},
    types::Error,
};
use std::{net::SocketAddr, result::Result};

/// Starts the HTTP-RPC server.
pub fn run_server(
    addr: SocketAddr,
    storage: Storage,
    sequencer: sequencer::Client,
) -> Result<(HttpServerHandle, SocketAddr), Error> {
    let server = HttpServerBuilder::default().build(addr)?;
    let local_addr = server.local_addr()?;
    let api = RpcApi::new(storage, sequencer);
    let mut module = RpcModule::new(api);
    module.register_async_method("starknet_getBlockByHash", |params, context| async move {
        #[derive(Debug, Deserialize)]
        pub struct NamedArgs {
            pub block_hash: BlockHashOrTag,
            #[serde(default)]
            pub requested_scope: Option<BlockResponseScope>,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_block_by_hash(params.block_hash, params.requested_scope)
            .await
    })?;
    module.register_async_method("starknet_getBlockByNumber", |params, context| async move {
        #[derive(Debug, Deserialize)]
        pub struct NamedArgs {
            pub block_number: BlockNumberOrTag,
            #[serde(default)]
            pub requested_scope: Option<BlockResponseScope>,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_block_by_number(params.block_number, params.requested_scope)
            .await
    })?;
    module.register_async_method(
        "starknet_getStateUpdateByHash",
        |params, context| async move {
            let hash = if params.is_object() {
                #[derive(Debug, Deserialize)]
                pub struct NamedArgs {
                    pub block_hash: BlockHashOrTag,
                }
                params.parse::<NamedArgs>()?.block_hash
            } else {
                params.one::<BlockHashOrTag>()?
            };
            context.get_state_update_by_hash(hash).await
        },
    )?;
    module.register_async_method("starknet_getStorageAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        pub struct NamedArgs {
            pub contract_address: ContractAddress,
            pub key: StorageAddress,
            pub block_hash: BlockHashOrTag,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_storage_at(params.contract_address, params.key, params.block_hash)
            .await
    })?;
    module.register_async_method(
        "starknet_getTransactionByHash",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_by_hash(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionByBlockHashAndIndex",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub block_hash: BlockHashOrTag,
                pub index: StarknetTransactionIndex,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_transaction_by_block_hash_and_index(params.block_hash, params.index)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionByBlockNumberAndIndex",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub block_number: BlockNumberOrTag,
                pub index: StarknetTransactionIndex,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_transaction_by_block_number_and_index(params.block_number, params.index)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionReceipt",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_receipt(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method("starknet_getCode", |params, context| async move {
        #[derive(Debug, Deserialize)]
        pub struct NamedArgs {
            pub contract_address: ContractAddress,
        }
        context
            .get_code(params.parse::<NamedArgs>()?.contract_address)
            .await
    })?;
    module.register_async_method(
        "starknet_getBlockTransactionCountByHash",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub block_hash: BlockHashOrTag,
            }
            context
                .get_block_transaction_count_by_hash(params.parse::<NamedArgs>()?.block_hash)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getBlockTransactionCountByNumber",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            pub struct NamedArgs {
                pub block_number: BlockNumberOrTag,
            }
            context
                .get_block_transaction_count_by_number(params.parse::<NamedArgs>()?.block_number)
                .await
        },
    )?;
    module.register_async_method("starknet_call", |params, context| async move {
        #[derive(Debug, Deserialize)]
        pub struct NamedArgs {
            pub request: Call,
            pub block_hash: BlockHashOrTag,
        }
        let params = params.parse::<NamedArgs>()?;
        context.call(params.request, params.block_hash).await
    })?;
    module.register_async_method("starknet_blockNumber", |_, context| async move {
        context.block_number().await
    })?;
    module.register_async_method("starknet_chainId", |_, context| async move {
        context.chain_id().await
    })?;
    module.register_async_method("starknet_pendingTransactions", |_, context| async move {
        context.pending_transactions().await
    })?;
    module.register_async_method("starknet_protocolVersion", |_, context| async move {
        context.protocol_version().await
    })?;
    module.register_async_method("starknet_syncing", |_, context| async move {
        context.chain_id().await
    })?;
    server.start(module).map(|handle| (handle, local_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{StarknetChainId, StarknetProtocolVersion},
        rpc::run_server,
        sequencer::test_utils::*,
    };
    use assert_matches::assert_matches;
    use jsonrpsee::{
        http_client::{HttpClient, HttpClientBuilder},
        rpc_params,
        types::{traits::Client, v2::ParamsSer, DeserializeOwned},
    };
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    /// Helper wrapper to allow retrying the test if rate limiting kicks in on the sequencer API side.
    ///
    /// Necessary until we move to mocking whatever the RPC api will call when the first release is ready.
    async fn client_request<'a, Out>(
        method: &str,
        params: Option<ParamsSer<'a>>,
    ) -> Result<Out, jsonrpsee::types::Error>
    where
        Out: Clone + DeserializeOwned,
    {
        let mut sleep_time_ms = 8000;
        const MAX_SLEEP_TIME_MS: u64 = 128000;

        loop {
            // Restart the server each time (and implicitly the sequencer client, which actually does the job)
            let storage = Storage::in_memory().unwrap();
            let sequencer = sequencer::Client::goerli().unwrap();
            let (__handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
            match client(addr).request::<Out>(method, params.clone()).await {
                Ok(r) => return Ok(r),
                Err(e) => match &e {
                    jsonrpsee::types::Error::Request(s)
                        if s.contains("(429 Too Many Requests)") =>
                    {
                        if sleep_time_ms > MAX_SLEEP_TIME_MS {
                            return Err(e);
                        }
                        // Give the sequencer api some slack and then retry
                        eprintln!(
                            "Got HTTP 429, retrying after {} seconds...",
                            sleep_time_ms / 1000
                        );
                        tokio::time::sleep(Duration::from_millis(sleep_time_ms)).await;
                        sleep_time_ms *= 2;
                    }
                    _ => return Err(e),
                },
            }
        }
    }

    /// Helper function: produces named rpc method args map.
    fn by_name<const N: usize>(params: [(&'_ str, serde_json::Value); N]) -> Option<ParamsSer<'_>> {
        Some(BTreeMap::from(params).into())
    }

    /// Helper rpc client
    fn client(addr: SocketAddr) -> HttpClient {
        HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(120))
            .build(format!("http://{}", addr))
            .expect("Failed to create HTTP-RPC client")
    }

    lazy_static::lazy_static! {
        static ref LOCALHOST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    }

    mod error {
        lazy_static::lazy_static! {
            pub static ref CONTRACT_NOT_FOUND: (i64, String) = (20, "Contract not found".to_owned());
            pub static ref INVALID_SELECTOR: (i64, String) = (21, "Invalid message selector".to_owned());
            pub static ref INVALID_CALL_DATA: (i64, String) = (22, "Invalid call data".to_owned());
            pub static ref INVALID_KEY: (i64, String) = (23, "Invalid storage key".to_owned());
            pub static ref INVALID_BLOCK_HASH: (i64, String) = (24, "Invalid block hash".to_owned());
            pub static ref INVALID_TX_HASH: (i64, String) = (25, "Invalid transaction hash".to_owned());
            pub static ref INVALID_BLOCK_NUMBER: (i64, String) = (26, "Invalid block number".to_owned());
        }
    }

    fn get_err(json_str: &str) -> (i64, String) {
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        (
            v["error"]["code"].as_i64().unwrap(),
            v["error"]["message"].as_str().unwrap().to_owned(),
        )
    }

    mod get_block_by_hash {
        use super::*;
        use crate::rpc::types::{reply::Block, request::BlockResponseScope, BlockHashOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_HASH);
            client_request::<Block>("starknet_getBlockByHash", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            mod positional_args {
                use super::*;

                #[tokio::test]
                async fn all() {
                    let params = rpc_params!(
                        BlockHashOrTag::Tag(Tag::Latest),
                        BlockResponseScope::TransactionHashes
                    );
                    client_request::<Block>("starknet_getBlockByHash", params)
                        .await
                        .unwrap();
                }

                #[tokio::test]
                async fn only_mandatory() {
                    let params = rpc_params!(BlockHashOrTag::Tag(Tag::Latest));
                    client_request::<Block>("starknet_getBlockByHash", params)
                        .await
                        .unwrap();
                }
            }

            mod named_args {
                use super::*;

                #[tokio::test]
                async fn all() {
                    use serde_json::json;
                    let params = by_name([
                        ("block_hash", json!("latest")),
                        ("requested_scope", json!("FULL_TXN_AND_RECEIPTS")),
                    ]);
                    client_request::<Block>("starknet_getBlockByHash", params)
                        .await
                        .unwrap();
                }

                #[tokio::test]
                async fn only_mandatory() {
                    use serde_json::json;
                    let params = by_name([("block_hash", json!("latest"))]);
                    client_request::<Block>("starknet_getBlockByHash", params)
                        .await
                        .unwrap();
                }
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(
                BlockHashOrTag::Tag(Tag::Pending),
                BlockResponseScope::FullTransactions
            );
            client_request::<Block>("starknet_getBlockByHash", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let params = rpc_params!(*INVALID_BLOCK_HASH);
            let error = client_request::<Block>("starknet_getBlockByHash", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }
    }

    mod get_block_by_number {
        use super::*;
        use crate::rpc::types::{reply::Block, request::BlockResponseScope, BlockNumberOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_NUMBER);
            client_request::<Block>("starknet_getBlockByNumber", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            mod positional_args {
                use super::*;

                #[tokio::test]
                async fn all() {
                    let params = rpc_params!(
                        BlockNumberOrTag::Tag(Tag::Latest),
                        BlockResponseScope::TransactionHashes
                    );
                    client_request::<Block>("starknet_getBlockByNumber", params)
                        .await
                        .unwrap();
                }

                #[tokio::test]
                async fn only_mandatory() {
                    let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Latest));
                    client_request::<Block>("starknet_getBlockByNumber", params)
                        .await
                        .unwrap();
                }
            }

            mod named_args {
                use super::*;

                #[tokio::test]
                async fn all() {
                    use serde_json::json;
                    let params = by_name([
                        ("block_number", json!("latest")),
                        ("requested_scope", json!("FULL_TXN_AND_RECEIPTS")),
                    ]);
                    client_request::<Block>("starknet_getBlockByNumber", params)
                        .await
                        .unwrap();
                }

                #[tokio::test]
                async fn only_mandatory() {
                    use serde_json::json;
                    let params = by_name([("block_number", json!("latest"))]);
                    client_request::<Block>("starknet_getBlockByNumber", params)
                        .await
                        .unwrap();
                }
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(
                BlockNumberOrTag::Tag(Tag::Pending),
                BlockResponseScope::FullTransactions
            );
            client_request::<Block>("starknet_getBlockByNumber", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_number() {
            let params = rpc_params!(*INVALID_BLOCK_NUMBER);
            let error = client_request::<Block>("starknet_getBlockByNumber", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_NUMBER)
            );
        }
    }

    mod get_state_update_by_hash {
        use super::*;
        use crate::rpc::types::{reply::StateUpdate, BlockHashOrTag, Tag};

        #[tokio::test]
        #[should_panic]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_HASH);
            client_request::<StateUpdate>("starknet_getStateUpdateByHash", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn latest() {
            let params = rpc_params!(BlockHashOrTag::Tag(Tag::Latest));
            client_request::<StateUpdate>("starknet_getStateUpdateByHash", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn pending() {
            let params = rpc_params!(BlockHashOrTag::Tag(Tag::Pending));
            client_request::<StateUpdate>("starknet_getStateUpdateByHash", params)
                .await
                .unwrap();
        }
    }

    mod get_storage_at {
        use super::*;
        use crate::{
            core::StorageValue,
            rpc::types::{BlockHashOrTag, Tag},
        };

        #[tokio::test]
        async fn invalid_contract() {
            let params = rpc_params!(
                *INVALID_CONTRACT_ADDR,
                *VALID_KEY,
                BlockHashOrTag::Tag(Tag::Latest)
            );
            client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_key() {
            let params = rpc_params!(
                *VALID_CONTRACT_ADDR,
                *INVALID_KEY,
                BlockHashOrTag::Tag(Tag::Latest)
            );
            client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_key_is_zero() {
            // Invalid key of value zero results with storage value of zero
            let params = rpc_params!(
                *VALID_CONTRACT_ADDR,
                *ZERO_KEY,
                BlockHashOrTag::Tag(Tag::Latest)
            );
            client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let params = rpc_params!(*VALID_CONTRACT_ADDR, *VALID_KEY, *INVALID_BLOCK_HASH);
            let error = client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }

        #[tokio::test]
        async fn latest_invoke_block() {
            let params = rpc_params!(
                *VALID_CONTRACT_ADDR,
                *VALID_KEY,
                *INVOKE_CONTRACT_BLOCK_HASH
            );
            client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
        }

        mod latest_block {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest)
                );
                client_request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([
                    ("contract_address", json!(*VALID_CONTRACT_ADDR)),
                    ("key", json!(*VALID_KEY)),
                    ("block_hash", json!("latest")),
                ]);
                client_request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn pending_block() {
            let params = rpc_params!(
                *VALID_CONTRACT_ADDR,
                *VALID_KEY,
                BlockHashOrTag::Tag(Tag::Pending)
            );
            client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_hash {
        use super::*;
        use crate::rpc::types::reply::Transaction;

        mod accepted {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(*VALID_TX_HASH);
                client_request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("transaction_hash", json!(*VALID_TX_HASH))]);
                client_request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn invalid_hash() {
            let params = rpc_params!(*INVALID_TX_HASH);
            let error = client_request::<Transaction>("starknet_getTransactionByHash", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_TX_HASH)
            );
        }
    }

    mod get_transaction_by_block_hash_and_index {
        use super::*;
        use crate::rpc::types::{reply::Transaction, BlockHashOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_HASH, *VALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(BlockHashOrTag::Tag(Tag::Latest), *VALID_TX_INDEX);
                client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([
                    ("block_hash", json!("latest")),
                    ("index", json!(*VALID_TX_INDEX)),
                ]);
                client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(BlockHashOrTag::Tag(Tag::Pending), *VALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block() {
            let params = rpc_params!(*INVALID_BLOCK_HASH, *VALID_TX_INDEX);
            let error =
                client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                    .await
                    .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }

        #[tokio::test]
        async fn invalid_transaction_index() {
            let params = rpc_params!(*DEPLOY_CONTRACT_BLOCK_HASH, *INVALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockHashAndIndex", params)
                .await
                .unwrap_err();
        }
    }

    mod get_transaction_by_block_number_and_index {
        use super::*;
        use crate::rpc::types::{reply::Transaction, BlockNumberOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_NUMBER, *VALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockNumberAndIndex", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Latest), *VALID_TX_INDEX);
                client_request::<Transaction>(
                    "starknet_getTransactionByBlockNumberAndIndex",
                    params,
                )
                .await
                .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([
                    ("block_number", json!("latest")),
                    ("index", json!(*VALID_TX_INDEX)),
                ]);
                client_request::<Transaction>(
                    "starknet_getTransactionByBlockNumberAndIndex",
                    params,
                )
                .await
                .unwrap();
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Pending), *VALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockNumberAndIndex", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block() {
            let params = rpc_params!(*INVALID_BLOCK_NUMBER, *VALID_TX_INDEX);
            let error = client_request::<Transaction>(
                "starknet_getTransactionByBlockNumberAndIndex",
                params,
            )
            .await
            .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_NUMBER)
            );
        }

        #[tokio::test]
        async fn invalid_transaction_index() {
            let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Latest), *INVALID_TX_INDEX);
            client_request::<Transaction>("starknet_getTransactionByBlockNumberAndIndex", params)
                .await
                .unwrap_err();
        }
    }

    mod get_transaction_receipt {
        use super::*;
        use crate::rpc::types::reply::TransactionReceipt;

        mod accepted {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(*VALID_TX_HASH);
                client_request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("transaction_hash", json!(*VALID_TX_HASH))]);
                client_request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn invalid() {
            let params = rpc_params!(*INVALID_TX_HASH);
            let error =
                client_request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_TX_HASH)
            );
        }
    }

    mod get_code {
        use super::*;
        use crate::sequencer::reply::Code;

        #[tokio::test]
        async fn invalid_contract_address() {
            // At the moment an invalid address causes an empty but valid reply
            let params = rpc_params!(*INVALID_CONTRACT_ADDR);
            client_request::<Code>("starknet_getCode", params)
                .await
                .unwrap();
        }

        mod success {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(*VALID_CONTRACT_ADDR);
                client_request::<Code>("starknet_getCode", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("contract_address", json!(*VALID_CONTRACT_ADDR))]);
                client_request::<Code>("starknet_getCode", params)
                    .await
                    .unwrap();
            }
        }
    }

    mod get_block_transaction_count_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_HASH);
            client_request::<u64>("starknet_getBlockTransactionCountByHash", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(BlockHashOrTag::Tag(Tag::Latest));
                client_request::<u64>("starknet_getBlockTransactionCountByHash", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("block_hash", json!("latest"))]);
                client_request::<u64>("starknet_getBlockTransactionCountByHash", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(BlockHashOrTag::Tag(Tag::Pending));
            client_request::<u64>("starknet_getBlockTransactionCountByHash", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let params = rpc_params!(*INVALID_BLOCK_HASH);
            let error = client_request::<u64>("starknet_getBlockTransactionCountByHash", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }
    }

    mod get_block_transaction_count_by_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};

        #[tokio::test]
        #[ignore = "Currently gives 502/503"]
        async fn genesis() {
            let params = rpc_params!(*GENESIS_BLOCK_NUMBER);
            client_request::<u64>("starknet_getBlockTransactionCountByNumber", params)
                .await
                .unwrap();
        }

        mod latest {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Latest));
                client_request::<u64>("starknet_getBlockTransactionCountByNumber", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([("block_number", json!("latest"))]);
                client_request::<u64>("starknet_getBlockTransactionCountByNumber", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn pending() {
            let params = rpc_params!(BlockNumberOrTag::Tag(Tag::Pending));
            client_request::<u64>("starknet_getBlockTransactionCountByNumber", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let params = rpc_params!(*INVALID_BLOCK_NUMBER);
            let error = client_request::<u64>("starknet_getBlockTransactionCountByNumber", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_NUMBER)
            );
        }
    }

    mod call {
        use super::*;
        use crate::{
            core::{CallParam, CallResultValue},
            rpc::types::{request::Call, BlockHashOrTag, Tag},
        };

        lazy_static::lazy_static! {
            static ref CALL_DATA: Vec<CallParam> = vec![CallParam::from_hex_str("1234").unwrap()];
        }

        #[tokio::test]
        async fn latest_invoked_block() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                *INVOKE_CONTRACT_BLOCK_HASH
            );
            client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap();
        }

        mod latest_block {
            use super::*;

            #[tokio::test]
            async fn positional_args() {
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.clone(),
                        contract_address: *VALID_CONTRACT_ADDR,
                        entry_point_selector: *VALID_ENTRY_POINT,
                    },
                    BlockHashOrTag::Tag(Tag::Latest)
                );
                client_request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn named_args() {
                let params = by_name([
                    (
                        "request",
                        json!({
                            "calldata": CALL_DATA.clone(),
                            "contract_address": *VALID_CONTRACT_ADDR,
                            "entry_point_selector": *VALID_ENTRY_POINT,
                        }),
                    ),
                    ("block_hash", json!("latest")),
                ]);
                client_request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn pending_block() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                BlockHashOrTag::Tag(Tag::Pending)
            );
            client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_entry_point() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *INVALID_ENTRY_POINT,
                },
                BlockHashOrTag::Tag(Tag::Latest)
            );
            let error = client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_SELECTOR)
            );
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *INVALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                BlockHashOrTag::Tag(Tag::Latest)
            );
            let error = client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::CONTRACT_NOT_FOUND)
            );
        }

        #[tokio::test]
        async fn invalid_call_data() {
            let params = rpc_params!(
                Call {
                    calldata: vec![],
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                BlockHashOrTag::Tag(Tag::Latest)
            );
            let error = client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_CALL_DATA)
            );
        }

        #[tokio::test]
        async fn uninitialized_contract() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                *PRE_DEPLOY_CONTRACT_BLOCK_HASH
            );
            let error = client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::CONTRACT_NOT_FOUND)
            );
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let params = rpc_params!(
                Call {
                    calldata: CALL_DATA.clone(),
                    contract_address: *VALID_CONTRACT_ADDR,
                    entry_point_selector: *VALID_ENTRY_POINT,
                },
                *INVALID_BLOCK_HASH
            );
            let error = client_request::<Vec<CallResultValue>>("starknet_call", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }
    }

    #[tokio::test]
    async fn block_number() {
        let storage = Storage::in_memory().unwrap();
        let sequencer = sequencer::Client::goerli().unwrap();
        let (_handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
        let params = rpc_params!();
        client(addr)
            .request::<u64>("starknet_blockNumber", params)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn chain_id() {
        let storage = Storage::in_memory().unwrap();
        let sequencer = sequencer::Client::goerli().unwrap();
        let (_handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
        let params = rpc_params!();
        client(addr)
            .request::<StarknetChainId>("starknet_chainId", params)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn pending_transactions() {
        let storage = Storage::in_memory().unwrap();
        let sequencer = sequencer::Client::goerli().unwrap();
        let (_handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
        let params = rpc_params!();
        client(addr)
            .request::<()>("starknet_pendingTransactions", params)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn protocol_version() {
        let storage = Storage::in_memory().unwrap();
        let sequencer = sequencer::Client::goerli().unwrap();
        let (_handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
        let params = rpc_params!();
        client(addr)
            .request::<StarknetProtocolVersion>("starknet_protocolVersion", params)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn syncing() {
        let storage = Storage::in_memory().unwrap();
        let sequencer = sequencer::Client::goerli().unwrap();
        let (_handle, addr) = run_server(*LOCALHOST, storage, sequencer).unwrap();
        let params = rpc_params!();
        use crate::rpc::types::reply::Syncing;
        client(addr)
            .request::<Syncing>("starknet_syncing", params)
            .await
            .unwrap();
    }
}
