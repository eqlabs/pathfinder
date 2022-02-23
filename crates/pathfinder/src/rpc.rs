//! StarkNet node JSON-RPC related modules.
pub mod api;
pub mod serde;
pub mod types;

use crate::{
    core::{ContractAddress, StarknetTransactionHash, StarknetTransactionIndex},
    rpc::{
        api::RpcApi,
        types::{
            request::OverflowingStorageAddress,
            request::{BlockResponseScope, Call},
            BlockHashOrTag, BlockNumberOrTag,
        },
    },
};
use ::serde::Deserialize;
use jsonrpsee::{
    http_server::{HttpServerBuilder, HttpServerHandle, RpcModule},
    types::Error,
};
use std::{net::SocketAddr, result::Result};

/// Helper wrapper for attaching spans to rpc method implementations
struct RpcModuleWrapper<Context>(jsonrpsee::RpcModule<Context>);

impl<Context: Send + Sync + 'static> RpcModuleWrapper<Context> {
    /// This wrapper helper adds a tracing span around all rpc methods with name = method_name.
    ///
    /// It could do more, for example trace the outputs, durations.
    ///
    /// This is the only one method provided at the moment, because it's the only one used. If you
    /// need to use some other `register_*` method from [`jsonrpsee::RpcModule`], just add it to
    /// this wrapper.
    fn register_async_method<R, Fun, Fut>(
        &mut self,
        method_name: &'static str,
        callback: Fun,
    ) -> Result<jsonrpsee::utils::server::rpc_module::MethodResourcesBuilder, jsonrpsee::types::Error>
    where
        R: ::serde::Serialize + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<R, Error>> + Send,
        Fun: (Fn(jsonrpsee::types::v2::Params<'static>, std::sync::Arc<Context>) -> Fut)
            + Copy
            + Send
            + Sync
            + 'static,
    {
        use tracing::Instrument;

        self.0.register_async_method(method_name, move |p, c| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            callback(p, c).instrument(span)
        })
    }

    fn into_inner(self) -> jsonrpsee::RpcModule<Context> {
        self.0
    }
}

/// Starts the HTTP-RPC server.
pub fn run_server(addr: SocketAddr, api: RpcApi) -> Result<(HttpServerHandle, SocketAddr), Error> {
    let server = HttpServerBuilder::default().build(addr)?;
    let local_addr = server.local_addr()?;
    let mut module = RpcModuleWrapper(RpcModule::new(api));
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
            // Accept overflowing type here to report INVALID_STORAGE_KEY properly
            pub key: OverflowingStorageAddress,
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
    let module = module.into_inner();
    server.start(module).map(|handle| (handle, local_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::StarknetProtocolVersion, ethereum::Chain, rpc::run_server, sequencer,
        sequencer::test_utils::*, storage::Storage,
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
            let sequencer = sequencer::Client::new(Chain::Goerli).unwrap();
            let api = RpcApi::new(storage, sequencer, Chain::Goerli);
            let (__handle, addr) = run_server(*LOCALHOST, api).unwrap();
            match client(addr).request::<Out>(method, params.clone()).await {
                Ok(r) => return Ok(r),
                Err(e) => match &e {
                    jsonrpsee::types::Error::Request(s)
                        if s.contains("(429 Too Many Requests)") =>
                    {
                        if sleep_time_ms > MAX_SLEEP_TIME_MS {
                            return Err(e);
                        }
                        let d = Duration::from_millis(sleep_time_ms);
                        // Give the sequencer api some slack and then retry
                        eprintln!("Got HTTP 429, retrying after {:?} ...", d);
                        tokio::time::sleep(d).await;
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
        async fn overflowing_key() {
            use std::str::FromStr;

            let params = rpc_params!(
                *VALID_CONTRACT_ADDR,
                web3::types::H256::from_str(
                    "0x0800000000000000000000000000000000000000000000000000000000000000"
                )
                .unwrap(),
                BlockHashOrTag::Tag(Tag::Latest)
            );
            let error = client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_KEY)
            );
        }

        #[tokio::test]
        #[ignore = "Until the test is actually implemented."]
        async fn non_existent_contract_address() {
            todo!("Add the test once state mocking is easy");
        }

        #[tokio::test]
        #[ignore = "Until the test is actually implemented."]
        async fn pre_deploy_block_hash() {
            todo!("Add the test once state mocking is easy");
        }

        #[tokio::test]
        async fn non_existent_block_hash() {
            let params = rpc_params!(*VALID_CONTRACT_ADDR, *VALID_KEY, *INVALID_BLOCK_HASH);
            let error = client_request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_matches!(
                error,
                Error::Request(s) => assert_eq!(get_err(&s), *error::INVALID_BLOCK_HASH)
            );
        }

        mod latest_block {
            use super::*;

            #[tokio::test]
            #[ignore = "This is a manual test and will be removed once state mocking facilities are ready."]
            async fn real_data() {
                let storage = Storage::migrate("desync.sqlite".into()).unwrap();
                let sequencer = sequencer::Client::new(Chain::Goerli).unwrap();
                let api = RpcApi::new(storage, sequencer, Chain::Goerli);
                let (__handle, addr) = run_server(*LOCALHOST, api).unwrap();
                let params = rpc_params!(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest)
                );
                let value = client(addr)
                    .request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
                assert_eq!(value, StorageValue::from_hex_str("0x1E240").unwrap());
            }

            #[tokio::test]
            #[ignore = "Until the test is actually implemented."]
            async fn positional_args() {
                todo!("Add the test once state mocking is easy");
            }

            #[tokio::test]
            #[ignore = "Until the test is actually implemented."]
            async fn named_args() {
                todo!("Add the test once state mocking is easy");
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
        use crate::core::ContractCode;
        use crate::rpc::types::reply::ErrorCode;

        #[tokio::test]
        async fn invalid_contract_address() {
            let params = rpc_params!(*INVALID_CONTRACT_ADDR);
            let e = client_request::<ContractCode>("starknet_getCode", params)
                .await
                .unwrap_err();

            assert_eq!(ErrorCode::ContractNotFound, e);
        }

        #[tokio::test]
        async fn returns_not_found_if_we_dont_know_about_the_contract() {
            let storage = Storage::in_memory().unwrap();
            let sequencer = sequencer::Client::new(Chain::Goerli).unwrap();
            let api = RpcApi::new(storage, sequencer, Chain::Goerli);
            let (__handle, addr) = run_server(*LOCALHOST, api).unwrap();

            let not_found = client(addr)
                .request::<ContractCode>(
                    "starknet_getCode",
                    rpc_params!(
                        "0x4ae0618c330c59559a59a27d143dd1c07cd74cf4e5e5a7cd85d53c6bf0e89dc"
                    ),
                )
                .await
                .unwrap_err();

            assert_eq!(ErrorCode::ContractNotFound, not_found);
        }

        #[tokio::test]
        async fn returns_abi_and_code_for_known() {
            use crate::core::ContractCode;
            use anyhow::Context;
            use bytes::Bytes;
            use futures::stream::TryStreamExt;
            use pedersen::StarkHash;

            let storage = Storage::in_memory().unwrap();

            let contract_definition = include_bytes!("../fixtures/contract_definition.json.zst");
            let buffer = zstd::decode_all(std::io::Cursor::new(contract_definition)).unwrap();
            let contract_definition = Bytes::from(buffer);

            {
                let mut conn = storage.connection().unwrap();
                let tx = conn.transaction().unwrap();

                let address = StarkHash::from_hex_str(
                    "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                )
                .unwrap();
                let expected_hash = StarkHash::from_hex_str(
                    "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b",
                )
                .unwrap();

                let (abi, bytecode, hash) =
                    crate::state::contract_hash::extract_abi_code_hash(&*contract_definition)
                        .unwrap();

                assert_eq!(hash, expected_hash);

                crate::storage::ContractCodeTable::insert(
                    &tx,
                    crate::core::ContractHash(hash),
                    &abi,
                    &bytecode,
                    &contract_definition,
                )
                .context("Deploy testing contract")
                .unwrap();

                crate::storage::ContractsTable::insert(
                    &tx,
                    crate::core::ContractAddress(address),
                    crate::core::ContractHash(hash),
                )
                .unwrap();

                tx.commit().unwrap();
            }

            let sequencer = sequencer::Client::new(Chain::Goerli).unwrap();
            let api = RpcApi::new(storage, sequencer, Chain::Goerli);
            let (__handle, addr) = run_server(*LOCALHOST, api).unwrap();

            let client = client(addr);

            // both parameters, these used to be separate tests
            let rets = [
                rpc_params!("0x057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"),
                by_name([(
                    "contract_address",
                    json!("0x057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"),
                )]),
            ]
            .into_iter()
            .map(|arg| client.request::<ContractCode>("starknet_getCode", arg))
            .collect::<futures::stream::FuturesOrdered<_>>()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

            assert_eq!(rets.len(), 2);

            assert_eq!(rets[0], rets[1]);
            let abi = rets[0].abi.to_string();
            assert_eq!(
                abi,
                // this should not have the quotes because that'd be in json:
                // `"abi":"\"[{....}]\""`
                r#"[{"inputs":[{"name":"address","type":"felt"},{"name":"value","type":"felt"}],"name":"increase_value","outputs":[],"type":"function"},{"inputs":[{"name":"contract_address","type":"felt"},{"name":"address","type":"felt"},{"name":"value","type":"felt"}],"name":"call_increase_value","outputs":[],"type":"function"},{"inputs":[{"name":"address","type":"felt"}],"name":"get_value","outputs":[{"name":"res","type":"felt"}],"type":"function"}]"#
            );
            assert_eq!(rets[0].bytecode.len(), 132);
        }
    }

    mod get_block_transaction_count_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
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
        client_request::<u64>("starknet_blockNumber", rpc_params!())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn chain_id() {
        use futures::stream::StreamExt;

        assert_eq!(
            [Chain::Goerli, Chain::Mainnet]
                .iter()
                .map(|set_chain| async {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = sequencer::Client::new(*set_chain).unwrap();
                    let api = RpcApi::new(storage, sequencer, *set_chain);
                    let (__handle, addr) = run_server(*LOCALHOST, api).unwrap();
                    let params = rpc_params!();
                    client(addr)
                        .request::<String>("starknet_chainId", params)
                        .await
                        .unwrap()
                })
                .collect::<futures::stream::FuturesOrdered<_>>()
                .collect::<Vec<_>>()
                .await,
            vec![
                format!("0x{}", hex::encode("SN_GOERLI")),
                format!("0x{}", hex::encode("SN_MAIN")),
            ]
        );
    }

    #[tokio::test]
    #[should_panic]
    async fn pending_transactions() {
        client_request::<()>("starknet_pendingTransactions", rpc_params!())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn protocol_version() {
        client_request::<StarknetProtocolVersion>("starknet_protocolVersion", rpc_params!())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn syncing() {
        client_request::<types::reply::Syncing>("starknet_syncing", rpc_params!())
            .await
            .unwrap();
    }
}
