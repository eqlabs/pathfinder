use self::api::RpcApi;

pub mod api;
pub mod types;

/// Helper wrapper for attaching spans to rpc method implementations
pub struct RpcModuleWrapper<Context>(jsonrpsee::RpcModule<Context>);

impl<Context: Send + Sync + 'static> RpcModuleWrapper<Context> {
    pub fn new(context: jsonrpsee::RpcModule<Context>) -> Self {
        Self(context)
    }

    /// This wrapper helper adds a tracing span around all rpc methods with name = method_name.
    ///
    /// It could do more, for example trace the outputs, durations.
    ///
    /// This is the only one method provided at the moment, because it's the only one used. If you
    /// need to use some other `register_*` method from [`jsonrpsee::RpcModule`], just add it to
    /// this wrapper.
    pub fn register_async_method<R, Fun, Fut>(
        &mut self,
        method_name: &'static str,
        callback: Fun,
    ) -> Result<
        jsonrpsee::core::server::rpc_module::MethodResourcesBuilder<'_>,
        jsonrpsee::core::Error,
    >
    where
        R: ::serde::Serialize + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<R, jsonrpsee::core::Error>> + Send,
        Fun: (Fn(jsonrpsee::types::Params<'static>, std::sync::Arc<Context>) -> Fut)
            + Copy
            + Send
            + Sync
            + 'static,
    {
        use tracing::Instrument;

        metrics::register_counter!("rpc_method_calls_total", "method" => method_name);
        metrics::register_counter!("rpc_method_calls_failed_total", "method" => method_name);

        self.0.register_async_method(method_name, move |p, c| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            callback(p, c).instrument(span)
        })
    }

    pub fn into_inner(self) -> jsonrpsee::RpcModule<Context> {
        self.0
    }
}

// Registers all methods for the v0.1 API
pub fn register_all_methods(
    module: &mut RpcModuleWrapper<RpcApi>,
) -> Result<(), jsonrpsee::core::Error> {
    use crate::{
        core::{
            BlockId, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, Fee,
            StarknetTransactionHash, StarknetTransactionIndex, TransactionNonce,
            TransactionSignatureElem, TransactionVersion,
        },
        rpc::serde::{
            FeeAsHexStr, TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
        },
        sequencer::request::add_transaction::ContractDefinition,
    };
    use ::serde::Deserialize;
    use stark_hash::StarkHash;

    use api::BlockResponseScope;
    use types::request::{Call, ContractCall, EventFilter};

    module.register_async_method(
        "starknet_getBlockWithTxHashes",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_block(params.block_id, BlockResponseScope::TransactionHashes)
                .await
        },
    )?;
    module.register_async_method("starknet_getBlockWithTxs", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_block(params.block_id, BlockResponseScope::FullTransactions)
            .await
    })?;
    module.register_async_method("starknet_getStateUpdate", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.get_state_update(params.block_id).await
    })?;
    module.register_async_method("starknet_getStorageAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            contract_address: ContractAddress,
            key: crate::core::StorageAddress,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_storage_at(params.contract_address, params.key, params.block_id)
            .await
    })?;
    module.register_async_method(
        "starknet_getTransactionByHash",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_by_hash(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionByBlockIdAndIndex",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
                index: StarknetTransactionIndex,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .get_transaction_by_block_id_and_index(params.block_id, params.index)
                .await
        },
    )?;
    module.register_async_method(
        "starknet_getTransactionReceipt",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                transaction_hash: StarknetTransactionHash,
            }
            context
                .get_transaction_receipt(params.parse::<NamedArgs>()?.transaction_hash)
                .await
        },
    )?;
    module.register_async_method("starknet_getClass", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            class_hash: ClassHash,
        }
        context
            .get_class(params.parse::<NamedArgs>()?.class_hash)
            .await
    })?;
    module.register_async_method("starknet_getClassHashAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
            contract_address: ContractAddress,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_class_hash_at(params.block_id, params.contract_address)
            .await
    })?;
    module.register_async_method("starknet_getClassAt", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            block_id: BlockId,
            contract_address: ContractAddress,
        }
        let params = params.parse::<NamedArgs>()?;
        context
            .get_class_at(params.block_id, params.contract_address)
            .await
    })?;
    module.register_async_method(
        "starknet_getBlockTransactionCount",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                block_id: BlockId,
            }
            context
                .get_block_transaction_count(params.parse::<NamedArgs>()?.block_id)
                .await
        },
    )?;
    module.register_async_method("starknet_getNonce", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            contract_address: ContractAddress,
        }
        context
            .get_nonce(params.parse::<NamedArgs>()?.contract_address)
            .await
    })?;
    module.register_async_method("starknet_call", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            request: Call,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.call(params.request, params.block_id).await
    })?;
    module.register_async_method("starknet_estimateFee", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            request: Call,
            block_id: BlockId,
        }
        let params = params.parse::<NamedArgs>()?;
        context.estimate_fee(params.request, params.block_id).await
    })?;
    module.register_async_method("starknet_blockNumber", |_, context| async move {
        context.block_number().await
    })?;
    module.register_async_method("starknet_blockHashAndNumber", |_, context| async move {
        context.block_hash_and_number().await
    })?;
    module.register_async_method("starknet_chainId", |_, context| async move {
        context.chain_id().await
    })?;
    module.register_async_method("starknet_pendingTransactions", |_, context| async move {
        context.pending_transactions().await
    })?;
    module.register_async_method("starknet_syncing", |_, context| async move {
        context.syncing().await
    })?;
    module.register_async_method("starknet_getEvents", |params, context| async move {
        #[derive(Debug, Deserialize)]
        struct NamedArgs {
            filter: EventFilter,
        }
        let request = params.parse::<NamedArgs>()?.filter;
        context.get_events(request).await
    })?;
    module.register_async_method(
        "starknet_addInvokeTransaction",
        |params, context| async move {
            #[serde_with::serde_as]
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                function_invocation: ContractCall,
                #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
                signature: Vec<TransactionSignatureElem>,
                #[serde_as(as = "FeeAsHexStr")]
                max_fee: Fee,
                #[serde_as(as = "TransactionVersionAsHexStr")]
                version: TransactionVersion,
                #[serde(default)]
                nonce: Option<TransactionNonce>,
            }
            let params = params.parse::<NamedArgs>()?;
            context
                .add_invoke_transaction(
                    params.version,
                    params.max_fee,
                    params.signature,
                    params.nonce,
                    params.function_invocation,
                )
                .await
        },
    )?;
    module.register_async_method(
        "starknet_addDeclareTransaction",
        |params, context| async move {
            #[serde_with::serde_as]
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                contract_class: ContractDefinition,
                #[serde_as(as = "TransactionVersionAsHexStr")]
                version: TransactionVersion,
                // An undocumented parameter that we forward to the sequencer API
                // A deploy token is required to deploy contracts on Starknet mainnet only.
                #[serde(default)]
                token: Option<String>,
            }
            let params = params.parse::<NamedArgs>()?;

            // These are required on the sequencer-side but missing from the v0.1.0 RPC request
            const MAX_FEE: Fee = Fee(web3::types::H128::zero());
            const NONCE: TransactionNonce = TransactionNonce(StarkHash::ZERO);
            // actual address dumped from a `starknet declare` call
            const SENDER_ADDRESS: ContractAddress =
                ContractAddress::new_or_panic(crate::starkhash!("01"));

            context
                .add_declare_transaction(
                    params.version,
                    MAX_FEE,
                    vec![],
                    NONCE,
                    params.contract_class,
                    SENDER_ADDRESS,
                    params.token,
                )
                .await
        },
    )?;
    module.register_async_method(
        "starknet_addDeployTransaction",
        |params, context| async move {
            #[derive(Debug, Deserialize)]
            struct NamedArgs {
                contract_address_salt: ContractAddressSalt,
                constructor_calldata: Vec<ConstructorParam>,
                contract_definition: ContractDefinition,
                // An undocumented parameter that we forward to the sequencer API
                // A deploy token is required to deploy contracts on Starknet mainnet only.
                #[serde(default)]
                token: Option<String>,
            }
            let params = params.parse::<NamedArgs>()?;

            // Required on the sequencer-side but missing from the v0.1.0 RPC request
            const VERSION: TransactionVersion = TransactionVersion::ZERO;

            context
                .add_deploy_transaction(
                    VERSION,
                    params.contract_address_salt,
                    params.constructor_calldata,
                    params.contract_definition,
                    params.token,
                )
                .await
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::rpc::v01::types::reply::BlockHashAndNumber;
    use crate::rpc::RpcServer;
    use crate::sequencer::reply::PendingBlock;
    use crate::{
        core::BlockId,
        rpc::{
            test_client::client,
            tests::{create_pending_data, run_server, setup_storage, LOCALHOST},
            v01::{
                api::RpcApi,
                types::reply::{Block, Transactions},
            },
        },
    };
    use crate::{
        core::{
            Chain, ClassHash, ContractAddress, EventKey, GasPrice, SequencerAddress,
            StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
            StarknetTransactionHash, StorageAddress,
        },
        sequencer::{test_utils::*, Client},
        starkhash, starkhash_bytes,
        state::{state_tree::GlobalStateTree, PendingData, SyncState},
        storage::{StarknetBlock, StarknetBlocksTable, StarknetTransactionsTable, Storage},
    };
    use assert_matches::assert_matches;
    use jsonrpsee::core::params::ArrayParams;
    use jsonrpsee::core::traits::ToRpcParams;
    use jsonrpsee::core::RpcResult;
    use jsonrpsee::types::Params;
    use serde_json::json;
    use stark_hash::StarkHash;
    use std::sync::Arc;

    mod get_block {
        use super::*;

        async fn check_result_with_api<F: Fn(&RpcResult<Block>, Option<&PendingBlock>)>(
            api: RpcApi,
            params: serde_json::Value,
            check_fn: F,
        ) {
            let pending_data = api.pending_data.as_ref();
            let pending_block = match pending_data {
                Some(pending_data) => pending_data.block().await,
                None => None,
            };
            let pending_block = pending_block.as_ref().map(|x| x.as_ref());

            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let result = client(addr)
                .request::<Block>("starknet_getBlockWithTxHashes", params.clone())
                .await;
            check_fn(&result, pending_block);
            let _ = result.map(
                |block| assert_matches!(block.transactions, Transactions::HashesOnly(_) => {}),
            );

            let result = client(addr)
                .request::<Block>("starknet_getBlockWithTxs", params)
                .await;
            check_fn(&result, pending_block);
            let _ = result
                .map(|block| assert_matches!(block.transactions, Transactions::Full(_) => {}));
        }

        async fn check_result<F: Fn(&RpcResult<Block>, Option<&PendingBlock>)>(
            params: serde_json::Value,
            check_fn: F,
        ) {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                .with_pending_data(pending_data.clone());
            check_result_with_api(api, params, check_fn).await
        }

        #[tokio::test]
        async fn genesis_by_hash() {
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let params = json!([{ "block_hash": genesis_hash }]);

            check_result(params, move |result, _| {
                assert_matches!(result, Ok(block) => {
                    assert_eq!(block.block_number, Some(StarknetBlockNumber::GENESIS));
                    assert_eq!(block.block_hash, Some(genesis_hash));
                });
            })
            .await;
        }

        #[tokio::test]
        async fn genesis_by_number() {
            let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
            let params = json!([{"block_number": 0}]);

            check_result(params, move |result, _| {
                assert_matches!(result, Ok(block) => {
                    assert_eq!(block.block_number, Some(StarknetBlockNumber::GENESIS));
                    assert_eq!(block.block_hash, Some(genesis_hash));
                });
            })
            .await;
        }

        mod latest {
            use super::*;

            mod positional_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn all() {
                    let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
                    let params = json!(["latest"]);

                    check_result(params, move |result, _| {
                        assert_matches!(result, Ok(block) => {
                            assert_eq!(
                                block.block_number,
                                Some(StarknetBlockNumber::new_or_panic(2))
                            );
                            assert_eq!(block.block_hash, Some(latest_hash));
                        });
                    })
                    .await;
                }
            }

            mod named_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn all() {
                    let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
                    let params = json!({"block_id": "latest"});

                    check_result(params, move |result, _| {
                        assert_matches!(result, Ok(block) => {
                            assert_eq!(
                                block.block_number,
                                Some(StarknetBlockNumber::new_or_panic(2))
                            );
                            assert_eq!(block.block_hash, Some(latest_hash));
                        });
                    })
                    .await;
                }
            }
        }

        mod pending {
            use super::*;

            #[tokio::test]
            async fn available() {
                let params = json!({"block_id": "pending"});
                check_result(params, move |result, pending| {
                    assert_matches!(result, Ok(block) => {
                        assert_eq!(block.parent_hash, pending.unwrap().parent_hash);
                    });
                })
                .await;
            }

            #[tokio::test]
            async fn empty() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(PendingData::default());
                let params = json!({"block_id": "pending"});
                check_result_with_api(api, params, |result, _| {
                    assert_matches!(result, Ok(block) => {
                        assert_eq!(
                            block.block_hash,
                            Some(StarknetBlockHash(starkhash_bytes!(b"latest")))
                        );
                    });
                })
                .await;
            }

            #[tokio::test]
            async fn disabled() {
                use jsonrpsee::{core::error::Error, types::error::CallError};

                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let params = json!({"block_id": "pending"});
                check_result_with_api(api, params, |result, _| {
                    assert_matches!(result, Err(Error::Call(CallError::Custom(_))));
                })
                .await;
            }
        }

        #[tokio::test]
        async fn invalid_block_id() {
            let params = json!({"block_id": {"block_hash": "0x0"}});
            check_result(params, |result, _| {
                assert_matches!(result, Err(error) => assert_eq!(
                    &crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                    error
                ));
            })
            .await;
        }
    }

    mod get_state_update {
        use crate::rpc::test_setup::Test;
        use crate::rpc::v01::types::reply::ErrorCode;
        use crate::storage::fixtures::init::with_n_state_updates;
        use serde_json::json;

        #[tokio::test]
        async fn happy_path_and_starkware_errors() {
            Test::new("starknet_getStateUpdate", line!())
                .with_storage(|tx| with_n_state_updates(tx, 3))
                .with_params_json(json!([
                    [{"block_hash":"0x0"}],
                    [{"block_hash":"0x1"}],
                    [{"block_number":0}],
                    [{"block_number":1}],
                    ["latest"],
                    {"block_id": "latest"},
                    {"block_id": {"block_hash":"0xdead"}},
                    {"block_id": {"block_number":9999}}
                ]))
                .map_err_to_starkware_error_code()
                .map_expected(|in_storage| {
                    let in_storage = in_storage.collect::<Vec<_>>();
                    vec![
                        Ok(in_storage[0].clone()),
                        Ok(in_storage[1].clone()),
                        Ok(in_storage[0].clone()),
                        Ok(in_storage[1].clone()),
                        Ok(in_storage[2].clone()),
                        Ok(in_storage[2].clone()),
                        Err(ErrorCode::InvalidBlockId),
                        Err(ErrorCode::InvalidBlockId),
                    ]
                })
                .run()
                .await;
        }

        #[tokio::test]
        #[ignore = "implement after local pending is merged into master"]
        async fn pending() {
            todo!()
        }
    }

    mod get_storage_at {
        use super::*;
        use crate::core::StorageValue;
        use pretty_assertions::assert_eq;

        #[tokio::test]
        async fn key_is_field_modulus() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 0"),
                "0x0800000000000011000000000000000000000000000000000000000000000001",
                "latest"
            ]);
            client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn key_is_less_than_modulus_but_252_bits() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 0"),
                "0x0800000000000000000000000000000000000000000000000000000000000000",
                "latest"
            ]);
            client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn non_existent_contract_address() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"nonexistent"),
                starkhash_bytes!(b"storage addr 0"),
                "latest"
            ]);
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::v01::types::reply::ErrorCode::ContractNotFound,
                error
            );
        }

        #[tokio::test]
        async fn pre_deploy_block_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 1"),
                starkhash_bytes!(b"storage addr 0"),
                { "block_hash": starkhash_bytes!(b"genesis") }
            ]);
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::v01::types::reply::ErrorCode::ContractNotFound,
                error
            );
        }

        #[tokio::test]
        async fn non_existent_block_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 1"),
                starkhash_bytes!(b"storage addr 0"),
                { "block_hash": starkhash_bytes!(b"nonexistent") }
            ]);
            let error = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                error
            );
        }

        #[tokio::test]
        async fn non_existent_key_gives_zero_value() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 1"),
                starkhash_bytes!(b"nonexistent"),
                "latest"
            ]);
            let value = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
            assert_eq!(value.0, StarkHash::ZERO);
        }

        #[tokio::test]
        async fn deployment_block() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let params = json!([
                starkhash_bytes!(b"contract 1"),
                starkhash_bytes!(b"storage addr 0"),
                { "block_hash": starkhash_bytes!(b"block 1") }
            ]);
            let value = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
            assert_eq!(value.0, starkhash_bytes!(b"storage value 1"));
        }

        mod latest_block {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = json!([
                    starkhash_bytes!(b"contract 1"),
                    starkhash_bytes!(b"storage addr 0"),
                    "latest"
                ]);
                let value = client(addr)
                    .request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
                assert_eq!(value.0, starkhash_bytes!(b"storage value 2"));
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = json!({
                        "contract_address": starkhash_bytes!(b"contract 1"),
                        "key": starkhash_bytes!(b"storage addr 0"),
                        "block_id": "latest",
                });
                let value = client(addr)
                    .request::<StorageValue>("starknet_getStorageAt", params)
                    .await
                    .unwrap();
                assert_eq!(value.0, starkhash_bytes!(b"storage value 2"));
            }
        }

        #[tokio::test]
        async fn pending_block() {
            let storage = setup_storage();
            let pending_data = create_pending_data(storage.clone()).await;
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                .with_pending_data(pending_data.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            // Pick an arbitrary pending storage update to query.
            let state_update = pending_data.state_update().await.unwrap();
            let (contract, updates) = state_update.state_diff.storage_diffs.iter().next().unwrap();
            let storage_key = updates[0].key;
            let storage_val = updates[0].value;

            let params = json!([contract, storage_key, "pending"]);
            let result = client(addr)
                .request::<StorageValue>("starknet_getStorageAt", params)
                .await
                .unwrap();
            assert_eq!(result, storage_val);
        }
    }

    mod get_transaction_by_hash {
        use super::*;
        use crate::rpc::v01::types::reply::Transaction;
        use pretty_assertions::assert_eq;

        mod accepted {
            use crate::core::StarknetTransactionHash;

            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn positional_args() {
                let storage = setup_storage();
                let hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = json!([hash]);
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction.hash(), hash);
            }

            #[tokio::test]
            async fn named_args() {
                let storage = setup_storage();
                let hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = json!({ "transaction_hash": hash });
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction.hash(), hash);
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                // Select an arbitrary pending transaction to query.
                let expected = pending_data.block().await.unwrap();
                let expected: Transaction = expected.transactions.first().unwrap().into();

                let params = json!([expected.hash()]);
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByHash", params)
                    .await
                    .unwrap();
                assert_eq!(transaction, expected);
            }
        }

        #[tokio::test]
        async fn invalid_hash() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            let params = json!(["0x0"]);
            let error = client(addr)
                .request::<Transaction>("starknet_getTransactionByHash", params)
                .await
                .unwrap_err();
            assert_eq!(
                crate::rpc::v01::types::reply::ErrorCode::InvalidTransactionHash,
                error
            );
        }
    }

    #[cfg(fixme)]
    mod fixme {

        mod get_transaction_by_block_id_and_index {
            use super::*;
            use crate::{core::StarknetTransactionHash, rpc::v01::types::reply::Transaction};
            use pretty_assertions::assert_eq;

            async fn check_result<F: Fn(&Transaction)>(
                params: (), /*FIXME Option<ParamsSer<'_>>*/
                check_fn: F,
            ) {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let txn = client(addr)
                    .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                    .await
                    .unwrap();

                check_fn(&txn);
            }

            #[tokio::test]
            async fn genesis_by_hash() {
                let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
                let genesis_id = BlockId::Hash(genesis_hash);
                let params = rpc_params!(genesis_id, 0);
                check_result(params, move |txn| {
                    assert_eq!(
                        txn.hash(),
                        StarknetTransactionHash(starkhash_bytes!(b"txn 0"))
                    )
                })
                .await;
            }

            #[tokio::test]
            async fn genesis_by_number() {
                let genesis_id = BlockId::Number(StarknetBlockNumber::GENESIS);
                let params = rpc_params!(genesis_id, 0);
                check_result(params, move |txn| {
                    assert_eq!(
                        txn.hash(),
                        StarknetTransactionHash(starkhash_bytes!(b"txn 0"))
                    )
                })
                .await;
            }

            mod latest {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn positional_args() {
                    let params = rpc_params!(BlockId::Latest, 0);
                    check_result(params, move |txn| {
                        assert_eq!(
                            txn.hash(),
                            StarknetTransactionHash(starkhash_bytes!(b"txn 3"))
                        );
                    })
                    .await;
                }

                #[tokio::test]
                async fn named_args() {
                    let params = by_name([("block_id", json!("latest")), ("index", json!(0))]);
                    check_result(params, move |txn| {
                        assert_eq!(
                            txn.hash(),
                            StarknetTransactionHash(starkhash_bytes!(b"txn 3"))
                        );
                    })
                    .await;
                }
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                const TX_IDX: usize = 1;
                let expected = pending_data.block().await.unwrap();
                assert!(TX_IDX <= expected.transactions.len());
                let expected: Transaction = expected.transactions.get(TX_IDX).unwrap().into();

                let params = rpc_params!(BlockId::Pending, TX_IDX);
                let transaction = client(addr)
                    .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                    .await
                    .unwrap();

                assert_eq!(transaction, expected);
            }

            #[tokio::test]
            async fn invalid_block() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)), 0);
                let error = client(addr)
                    .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                    error
                );
            }

            #[tokio::test]
            async fn invalid_transaction_index() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
                let genesis_id = BlockId::Hash(genesis_hash);
                let params = rpc_params!(genesis_id, 123);
                let error = client(addr)
                    .request::<Transaction>("starknet_getTransactionByBlockIdAndIndex", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidTransactionIndex,
                    error
                );
            }
        }

        mod get_transaction_receipt {
            use super::*;
            use crate::rpc::v01::types::reply::TransactionReceipt;
            use pretty_assertions::assert_eq;

            mod accepted {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn positional_args() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                    let params = rpc_params!(txn_hash);
                    let receipt = client(addr)
                        .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                        .await
                        .unwrap();
                    assert_eq!(receipt.hash(), txn_hash);
                    assert_matches!(
                        receipt,
                        TransactionReceipt::Invoke(invoke) => assert_eq!(
                            invoke.events[0].keys[0],
                            EventKey(starkhash_bytes!(b"event 0 key"))
                        )
                    );
                }

                #[tokio::test]
                async fn named_args() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
                    let params = by_name([("transaction_hash", json!(txn_hash))]);
                    let receipt = client(addr)
                        .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                        .await
                        .unwrap();
                    assert_eq!(receipt.hash(), txn_hash);
                    assert_matches!(
                        receipt,
                        TransactionReceipt::Invoke(invoke) => assert_eq!(
                            invoke.events[0].keys[0],
                            EventKey(starkhash_bytes!(b"event 0 key"))
                        )
                    );
                }

                #[tokio::test]
                async fn pending() {
                    let storage = setup_storage();
                    let pending_data = create_pending_data(storage.clone()).await;
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                        .with_pending_data(pending_data.clone());
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    // Select an arbitrary pending transaction to query.
                    let expected = pending_data.block().await.unwrap();
                    let expected = expected.transaction_receipts.first().unwrap();

                    let params = rpc_params!(expected.transaction_hash);
                    let receipt = client(addr)
                        .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                        .await
                        .unwrap();
                    // Only asserting the hash because translating from Sequencer receipt to RPC receipt is pita.
                    assert_eq!(receipt.hash(), expected.transaction_hash);
                    assert_matches!(
                        receipt,
                        TransactionReceipt::PendingInvoke(invoke) => {
                            assert_eq!(invoke.common.actual_fee, crate::core::Fee(Default::default()));
                            assert_eq!(invoke.events.len(), 3);
                        }
                    );
                }
            }

            #[tokio::test]
            async fn invalid() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let txn_hash = StarknetTransactionHash(starkhash_bytes!(b"not found"));
                let params = rpc_params!(txn_hash);
                let error = client(addr)
                    .request::<TransactionReceipt>("starknet_getTransactionReceipt", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidTransactionHash,
                    error
                );
            }
        }

        mod get_class {
            use super::contract_setup::setup_class_and_contract;
            use super::*;
            use crate::core::ContractClass;
            use crate::rpc::v01::types::reply::ErrorCode;

            mod positional_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn returns_invalid_contract_class_hash_for_nonexistent_class() {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = rpc_params!(INVALID_CLASS_HASH);
                    let error = client(addr)
                        .request::<ContractClass>("starknet_getClass", params)
                        .await
                        .unwrap_err();
                    assert_eq!(ErrorCode::InvalidContractClassHash, error);
                }

                #[tokio::test]
                async fn returns_program_and_entry_points_for_known_class() {
                    let storage = setup_storage();

                    let mut conn = storage.connection().unwrap();
                    let transaction = conn.transaction().unwrap();
                    let (_contract_address, class_hash, program, entry_points) =
                        setup_class_and_contract(&transaction).unwrap();
                    transaction.commit().unwrap();

                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = rpc_params!(class_hash);
                    let class = client(addr)
                        .request::<ContractClass>("starknet_getClass", params)
                        .await
                        .unwrap();

                    assert_eq!(class.entry_points_by_type, entry_points);
                    assert_eq!(class.program, program);
                }
            }

            mod named_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn returns_program_and_entry_points_for_known_class() {
                    let storage = setup_storage();

                    let mut conn = storage.connection().unwrap();
                    let transaction = conn.transaction().unwrap();
                    let (_contract_address, class_hash, program, entry_points) =
                        setup_class_and_contract(&transaction).unwrap();
                    transaction.commit().unwrap();

                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = by_name([("class_hash", json!(class_hash))]);
                    let class = client(addr)
                        .request::<ContractClass>("starknet_getClass", params)
                        .await
                        .unwrap();

                    assert_eq!(class.entry_points_by_type, entry_points);
                    assert_eq!(class.program, program);
                }
            }
        }

        mod get_class_hash_at {
            use super::*;

            mod positional_args {
                use super::*;
                use crate::rpc::v01::types::reply::ErrorCode;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn returns_contract_not_found_for_nonexistent_contract() {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = rpc_params!(BlockId::Latest, INVALID_CONTRACT_ADDR);
                    let error = client(addr)
                        .request::<ClassHash>("starknet_getClassHashAt", params)
                        .await
                        .unwrap_err();
                    assert_eq!(ErrorCode::ContractNotFound, error);
                }

                #[tokio::test]
                async fn returns_class_hash_for_existing_contract() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let contract_address =
                        ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                    let params = rpc_params!(BlockId::Latest, contract_address);
                    let class_hash = client(addr)
                        .request::<ClassHash>("starknet_getClassHashAt", params)
                        .await
                        .unwrap();
                    let expected_class_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));
                    assert_eq!(class_hash, expected_class_hash);
                }

                #[tokio::test]
                async fn returns_not_found_for_existing_contract_that_is_not_yet_deployed() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let contract_address =
                        ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                    let params = rpc_params!(
                        BlockId::Number(StarknetBlockNumber::GENESIS),
                        contract_address
                    );
                    let error = client(addr)
                        .request::<ClassHash>("starknet_getClassHashAt", params)
                        .await
                        .unwrap_err();
                    assert_eq!(ErrorCode::ContractNotFound, error);
                }

                #[tokio::test]
                async fn pending() {
                    let storage = setup_storage();
                    let pending_data = create_pending_data(storage.clone()).await;
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                        .with_pending_data(pending_data.clone());
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let contract = pending_data.state_update().await.unwrap();
                    let contract = contract.state_diff.deployed_contracts.first().unwrap();

                    let params = rpc_params!(BlockId::Pending, contract.address);
                    let class_hash = client(addr)
                        .request::<ClassHash>("starknet_getClassHashAt", params)
                        .await
                        .unwrap();
                    assert_eq!(class_hash, contract.class_hash);
                }
            }

            mod named_args {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn returns_class_hash_for_existing_contract() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let contract_address =
                        ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));
                    let params = by_name([
                        ("block_id", json!("latest")),
                        ("contract_address", json!(contract_address)),
                    ]);
                    let class_hash = client(addr)
                        .request::<ClassHash>("starknet_getClassHashAt", params)
                        .await
                        .unwrap();
                    let expected_class_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));
                    assert_eq!(class_hash, expected_class_hash);
                }
            }
        }

        mod get_class_at {
            use super::contract_setup::setup_class_and_contract;
            use super::*;
            use crate::core::ContractClass;
            use crate::rpc::v01::types::reply::ErrorCode;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn invalid_contract_address() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Latest, INVALID_CONTRACT_ADDR);
                let error = client(addr)
                    .request::<ContractClass>("starknet_getClassAt", params)
                    .await
                    .unwrap_err();
                assert_eq!(ErrorCode::ContractNotFound, error);
            }

            #[tokio::test]
            async fn returns_not_found_if_we_dont_know_about_the_contract() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let not_found = client(addr)
                    .request::<ContractClass>(
                        "starknet_getClassAt",
                        rpc_params!(
                            BlockId::Latest,
                            "0x4ae0618c330c59559a59a27d143dd1c07cd74cf4e5e5a7cd85d53c6bf0e89dc"
                        ),
                    )
                    .await
                    .unwrap_err();

                assert_eq!(ErrorCode::ContractNotFound, not_found);
            }

            #[tokio::test]
            async fn returns_program_and_entry_points_for_known_class() {
                use crate::core::ContractClass;
                use futures::stream::TryStreamExt;

                let storage = setup_storage();
                let mut conn = storage.connection().unwrap();
                let transaction = conn.transaction().unwrap();
                let (contract_address, _class_hash, program, entry_points) =
                    setup_class_and_contract(&transaction).unwrap();
                transaction.commit().unwrap();

                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let client = client(addr);

                // both parameters, these used to be separate tests
                let rets = [
                    rpc_params!(BlockId::Latest, contract_address),
                    by_name([
                        ("block_id", json!("latest")),
                        ("contract_address", json!(contract_address)),
                    ]),
                ]
                .into_iter()
                .map(|arg| client.request::<ContractClass>("starknet_getClassAt", arg))
                .collect::<futures::stream::FuturesOrdered<_>>()
                .try_collect::<Vec<_>>()
                .await
                .unwrap();

                assert_eq!(rets.len(), 2);

                assert_eq!(rets[0], rets[1]);
                assert_eq!(rets[0].entry_points_by_type, entry_points);
                assert_eq!(rets[0].program, program);
            }

            #[tokio::test]
            async fn returns_not_found_for_existing_contract_that_is_not_yet_deployed() {
                use crate::core::ContractClass;

                let storage = setup_storage();
                let mut conn = storage.connection().unwrap();
                let transaction = conn.transaction().unwrap();
                let (contract_address, _class_hash, _program, _entry_points) =
                    setup_class_and_contract(&transaction).unwrap();
                transaction.commit().unwrap();

                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let not_found = client(addr)
                    .request::<ContractClass>(
                        "starknet_getClassAt",
                        rpc_params!(
                            BlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                            contract_address
                        ),
                    )
                    .await
                    .unwrap_err();

                assert_eq!(ErrorCode::ContractNotFound, not_found);
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let contract = pending_data.state_update().await.unwrap();
                let contract = contract.state_diff.deployed_contracts.first().unwrap();

                let params = rpc_params!(BlockId::Pending, contract.address);
                client(addr)
                    .request::<ContractClass>("starknet_getClassAt", params)
                    .await
                    .unwrap();
            }
        }

        mod contract_setup {
            use crate::{
                core::StorageValue, sequencer::reply::state_update::StorageDiff, starkhash,
                state::update_contract_state, storage::StarknetBlocksBlockId,
            };

            use super::*;
            use anyhow::Context;
            use bytes::Bytes;
            use flate2::{write::GzEncoder, Compression};
            use pretty_assertions::assert_eq;

            pub fn setup_class_and_contract(
                transaction: &rusqlite::Transaction<'_>,
            ) -> anyhow::Result<(ContractAddress, ClassHash, String, serde_json::Value)>
            {
                let contract_definition =
                    include_bytes!("../../fixtures/contract_definition.json.zst");
                let buffer = zstd::decode_all(std::io::Cursor::new(contract_definition))?;
                let contract_definition = Bytes::from(buffer);

                let contract_address = ContractAddress::new_or_panic(starkhash!(
                    "057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                ));
                let expected_hash =
                    starkhash!("050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b");

                let (abi, bytecode, hash) =
                    crate::state::class_hash::extract_abi_code_hash(&*contract_definition)?;

                assert_eq!(hash.0, expected_hash);

                let (program, entry_points) =
                    crate::state::class_hash::extract_program_and_entry_points_by_type(
                        &*contract_definition,
                    )?;

                crate::storage::ContractCodeTable::insert(
                    transaction,
                    hash,
                    &abi,
                    &bytecode,
                    &contract_definition,
                )
                .context("Deploy testing contract")?;

                crate::storage::ContractsTable::upsert(transaction, contract_address, hash)?;

                let mut compressor = GzEncoder::new(Vec::new(), Compression::fast());
                serde_json::to_writer(&mut compressor, &program)?;
                let program = compressor.finish()?;

                let program = base64::encode(program);

                // insert a new block whose state includes the contract
                let storage_addr = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr"));
                let storage_diff = vec![StorageDiff {
                    key: storage_addr,
                    value: StorageValue(starkhash_bytes!(b"storage_value")),
                }];
                let block2 = StarknetBlocksTable::get(
                    transaction,
                    StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(2)),
                )
                .unwrap()
                .unwrap();
                let mut global_tree = GlobalStateTree::load(transaction, block2.root).unwrap();
                let contract_state_hash = update_contract_state(
                    contract_address,
                    &storage_diff,
                    None,
                    &global_tree,
                    transaction,
                )
                .unwrap();
                global_tree
                    .set(contract_address, contract_state_hash)
                    .unwrap();

                let block3 = StarknetBlock {
                    number: StarknetBlockNumber::new_or_panic(3),
                    hash: StarknetBlockHash(starkhash_bytes!(b"block 3 hash")),
                    root: global_tree.apply().unwrap(),
                    timestamp: StarknetBlockTimestamp::new_or_panic(3),
                    gas_price: GasPrice::from(3),
                    sequencer_address: SequencerAddress(starkhash_bytes!(&[3u8])),
                };

                StarknetBlocksTable::insert(transaction, &block3, None).unwrap();

                Ok((contract_address, hash, program, entry_points))
            }
        }

        mod get_block_transaction_count {
            use super::*;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn genesis() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Hash(StarknetBlockHash(starkhash_bytes!(
                    b"genesis"
                ))));
                let count = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap();
                assert_eq!(count, 1);
            }

            mod latest {
                use super::*;
                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn positional_args() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = rpc_params!(BlockId::Latest);
                    let count = client(addr)
                        .request::<u64>("starknet_getBlockTransactionCount", params)
                        .await
                        .unwrap();
                    assert_eq!(count, 3);
                }

                #[tokio::test]
                async fn named_args() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = by_name([("block_id", json!("latest"))]);
                    let count = client(addr)
                        .request::<u64>("starknet_getBlockTransactionCount", params)
                        .await
                        .unwrap();
                    assert_eq!(count, 3);
                }
            }

            #[tokio::test]
            async fn pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let expected = pending_data.block().await.unwrap().transactions.len();
                let params = rpc_params!(BlockId::Pending);
                let count = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap();
                assert_eq!(count, expected as u64);
            }

            #[tokio::test]
            async fn invalid_hash() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Hash(StarknetBlockHash(StarkHash::ZERO)));
                let error = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                    error
                );
            }

            #[tokio::test]
            async fn invalid_number() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(BlockId::Number(StarknetBlockNumber::new_or_panic(123)));
                let error = client(addr)
                    .request::<u64>("starknet_getBlockTransactionCount", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                    error
                );
            }
        }

        mod pending_transactions {
            use super::*;
            use crate::rpc::v01::types::reply::Transaction;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn with_pending() {
                let storage = setup_storage();
                let pending_data = create_pending_data(storage.clone()).await;
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let expected = pending_data
                    .block()
                    .await
                    .unwrap()
                    .transactions
                    .clone()
                    .into_iter()
                    .map(Transaction::from)
                    .collect::<Vec<_>>();

                let transactions = client(addr)
                    .request::<Vec<Transaction>>("starknet_pendingTransactions", rpc_params![])
                    .await
                    .unwrap();

                assert_eq!(transactions, expected);
            }

            #[tokio::test]
            async fn defaults_to_latest() {
                let storage = setup_storage();
                // empty pending data, which should result in `starknet_pendingTransactions` using
                // the `latest` transactions instead.
                let pending_data = PendingData::default();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage.clone(), sequencer, Chain::Testnet, sync_state)
                    .with_pending_data(pending_data.clone());
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                let mut conn = storage.connection().unwrap();
                let db_tx = conn.transaction().unwrap();
                let expected = StarknetTransactionsTable::get_transactions_for_latest_block(&db_tx)
                    .unwrap()
                    .into_iter()
                    .map(Transaction::from)
                    .collect::<Vec<_>>();

                let transactions = client(addr)
                    .request::<Vec<Transaction>>("starknet_pendingTransactions", rpc_params![])
                    .await
                    .unwrap();

                assert_eq!(transactions, expected);
            }
        }

        #[tokio::test]
        async fn get_nonce() {
            use crate::core::ContractNonce;

            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state.clone());
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

            // This contract is created in `setup_storage` and has a nonce set to 0x1.
            let valid_contract = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0"));
            let nonce = client(addr)
                .request::<ContractNonce>("starknet_getNonce", rpc_params!(valid_contract))
                .await
                .unwrap();
            assert_eq!(nonce, ContractNonce(starkhash!("01")));

            // Invalid contract should error.
            let invalid_contract = ContractAddress::new_or_panic(starkhash_bytes!(b"invalid"));
            let error = client(addr)
                .request::<ContractNonce>("starknet_getNonce", rpc_params!(invalid_contract))
                .await
                .expect_err("invalid contract should error");
            let expected = crate::rpc::v01::types::reply::ErrorCode::ContractNotFound;
            assert_eq!(expected, error);
        }

        // FIXME: these tests are largely defunct because they have never used ext_py, and handle
        // parsing issues.
        mod call {
            use super::*;
            use crate::rpc::v01::types::request::Call;
            use crate::{
                core::{CallParam, CallResultValue},
                starkhash,
            };
            use pretty_assertions::assert_eq;

            const INVOKE_CONTRACT_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
                "03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27"
            )));
            const PRE_DEPLOY_CONTRACT_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(
                starkhash!("05ef884a311df4339c8df791ce19bf305d7cf299416666b167bc56dd2d1f435f"),
            ));
            const INVALID_BLOCK_ID: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
                "06d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"
            )));
            const CALL_DATA: [CallParam; 1] = [CallParam(starkhash!("1234"))];

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn latest_invoked_block() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    INVOKE_CONTRACT_BLOCK_ID
                );
                client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }

            mod latest_block {
                use super::*;

                #[ignore = "no longer works without setting up ext_py"]
                #[tokio::test]
                async fn positional_args() {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = rpc_params!(
                        Call {
                            calldata: CALL_DATA.to_vec(),
                            contract_address: VALID_CONTRACT_ADDR,
                            entry_point_selector: Some(VALID_ENTRY_POINT),
                            signature: Default::default(),
                            max_fee: Call::DEFAULT_MAX_FEE,
                            version: Call::DEFAULT_VERSION,
                            nonce: Call::DEFAULT_NONCE,
                        },
                        BlockId::Latest
                    );
                    client(addr)
                        .request::<Vec<CallResultValue>>("starknet_call", params)
                        .await
                        .unwrap();
                }

                #[ignore = "no longer works without setting up ext_py"]
                #[tokio::test]
                async fn named_args() {
                    let storage = Storage::in_memory().unwrap();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                    let params = by_name([
                        (
                            "request",
                            json!({
                                "calldata": &CALL_DATA,
                                "contract_address": VALID_CONTRACT_ADDR,
                                "entry_point_selector": VALID_ENTRY_POINT,
                            }),
                        ),
                        ("block_id", json!("latest")),
                    ]);
                    client(addr)
                        .request::<Vec<CallResultValue>>("starknet_call", params)
                        .await
                        .unwrap();
                }
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn pending_block() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    BlockId::Pending
                );
                client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap();
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn invalid_entry_point() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(INVALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    BlockId::Latest
                );
                let error = client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidMessageSelector,
                    error
                );
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn invalid_contract_address() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: INVALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    BlockId::Latest
                );
                let error = client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::ContractNotFound,
                    error
                );
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn invalid_call_data() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: vec![],
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    BlockId::Latest
                );
                let error = client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidCallData,
                    error
                );
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn uninitialized_contract() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    PRE_DEPLOY_CONTRACT_BLOCK_ID
                );
                let error = client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::ContractNotFound,
                    error
                );
            }

            #[ignore = "no longer works without setting up ext_py"]
            #[tokio::test]
            async fn invalid_block_hash() {
                let storage = Storage::in_memory().unwrap();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let params = rpc_params!(
                    Call {
                        calldata: CALL_DATA.to_vec(),
                        contract_address: VALID_CONTRACT_ADDR,
                        entry_point_selector: Some(VALID_ENTRY_POINT),
                        signature: Default::default(),
                        max_fee: Call::DEFAULT_MAX_FEE,
                        version: Call::DEFAULT_VERSION,
                        nonce: Call::DEFAULT_NONCE,
                    },
                    INVALID_BLOCK_ID
                );
                let error = client(addr)
                    .request::<Vec<CallResultValue>>("starknet_call", params)
                    .await
                    .unwrap_err();
                assert_eq!(
                    crate::rpc::v01::types::reply::ErrorCode::InvalidBlockId,
                    error
                );
            }
        }

        #[tokio::test]
        async fn block_number() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let number = client(addr)
                .request::<u64>("starknet_blockNumber", rpc_params!())
                .await
                .unwrap();
            assert_eq!(number, 2);
        }

        #[tokio::test]
        async fn block_hash_and_number() {
            let storage = setup_storage();
            let sequencer = Client::new(Chain::Testnet).unwrap();
            let sync_state = Arc::new(SyncState::default());
            let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
            let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
            let latest = client(addr)
                .request::<BlockHashAndNumber>("starknet_blockHashAndNumber", rpc_params!())
                .await
                .unwrap();
            let expected = BlockHashAndNumber {
                hash: StarknetBlockHash(starkhash_bytes!(b"latest")),
                number: StarknetBlockNumber::new_or_panic(2),
            };
            assert_eq!(latest, expected);
        }

        #[tokio::test]
        async fn chain_id() {
            use crate::monitoring::metrics::middleware::RpcMetricsMiddleware;
            use futures::stream::StreamExt;

            assert_eq!(
                [Chain::Testnet, Chain::Mainnet]
                    .iter()
                    .map(|set_chain| async {
                        let storage = Storage::in_memory().unwrap();
                        let sequencer = Client::new(*set_chain).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, *set_chain, sync_state);

                        let (__handle, addr) = RpcServer::new(*LOCALHOST, api)
                            .with_middleware(RpcMetricsMiddleware)
                            .run()
                            .await
                            .unwrap();
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

        mod syncing {
            use crate::rpc::v01::types::reply::{syncing, Syncing};
            use pretty_assertions::assert_eq;

            use super::*;

            #[tokio::test]
            async fn not_syncing() {
                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let syncing = client(addr)
                    .request::<Syncing>("starknet_syncing", rpc_params!())
                    .await
                    .unwrap();

                assert_eq!(syncing, Syncing::False(false));
            }

            #[tokio::test]
            async fn syncing() {
                use crate::rpc::v01::types::reply::syncing::NumberedBlock;
                let expected = Syncing::Status(syncing::Status {
                    starting: NumberedBlock::from(("abbacd", 1)),
                    current: NumberedBlock::from(("abbace", 2)),
                    highest: NumberedBlock::from(("abbacf", 3)),
                });

                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                *sync_state.status.write().await = expected.clone();
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();
                let syncing = client(addr)
                    .request::<Syncing>("starknet_syncing", rpc_params!())
                    .await
                    .unwrap();

                assert_eq!(syncing, expected);
            }
        }

        mod events {
            use super::*;

            use crate::rpc::v01::types::reply::{EmittedEvent, GetEventsResult};
            use crate::storage::test_utils;

            fn setup() -> (Storage, Vec<EmittedEvent>) {
                let (storage, events) = test_utils::setup_test_storage();
                let events = events.into_iter().map(EmittedEvent::from).collect();
                (storage, events)
            }

            mod positional_args {
                use super::*;
                use crate::{rpc::v01::types::request::EventFilter, starkhash};

                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn get_events_with_empty_filter() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: vec![],
                        page_size: test_utils::NUM_EVENTS,
                        page_number: 0,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();

                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events,
                            page_number: 0,
                            is_last_page: true,
                        }
                    );
                }

                #[tokio::test]
                async fn get_events_with_fully_specified_filter() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let expected_event = &events[1];
                    let params = rpc_params!(EventFilter {
                        from_block: Some(expected_event.block_number.unwrap().into()),
                        to_block: Some(expected_event.block_number.unwrap().into()),
                        address: Some(expected_event.from_address),
                        // we're using a key which is present in _all_ events
                        keys: vec![EventKey(starkhash!("deadbeef"))],
                        page_size: test_utils::NUM_EVENTS,
                        page_number: 0,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();

                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: vec![expected_event.clone()],
                            page_number: 0,
                            is_last_page: true,
                        }
                    );
                }

                #[tokio::test]
                async fn get_events_by_block() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    const BLOCK_NUMBER: usize = 2;
                    let params = rpc_params!(EventFilter {
                        from_block: Some(
                            StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()
                        ),
                        to_block: Some(
                            StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()
                        ),
                        address: None,
                        keys: vec![],
                        page_size: test_utils::NUM_EVENTS,
                        page_number: 0,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();

                    let expected_events = &events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
                        ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: expected_events.to_vec(),
                            page_number: 0,
                            is_last_page: true,
                        }
                    );
                }

                #[tokio::test]
                async fn get_events_with_invalid_page_size() {
                    let (storage, _events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: vec![],
                        page_size: crate::storage::StarknetEventsTable::PAGE_SIZE_LIMIT + 1,
                        page_number: 0,
                    });
                    let error = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap_err();

                    assert_eq!(
                        crate::rpc::v01::types::reply::ErrorCode::PageSizeTooBig,
                        error
                    );
                }

                #[tokio::test]
                async fn get_events_by_key_with_paging() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let expected_events = &events[27..32];
                    let keys_for_expected_events: Vec<_> =
                        expected_events.iter().map(|e| e.keys[0]).collect();

                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: keys_for_expected_events.clone(),
                        page_size: 2,
                        page_number: 0,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();
                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: expected_events[..2].to_vec(),
                            page_number: 0,
                            is_last_page: false,
                        }
                    );

                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: keys_for_expected_events.clone(),
                        page_size: 2,
                        page_number: 1,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();
                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: expected_events[2..4].to_vec(),
                            page_number: 1,
                            is_last_page: false,
                        }
                    );

                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: keys_for_expected_events.clone(),
                        page_size: 2,
                        page_number: 2,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();
                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: expected_events[4..].to_vec(),
                            page_number: 2,
                            is_last_page: true,
                        }
                    );

                    // nonexistent page
                    let params = rpc_params!(EventFilter {
                        from_block: None,
                        to_block: None,
                        address: None,
                        keys: keys_for_expected_events.clone(),
                        page_size: 2,
                        page_number: 3,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();
                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: vec![],
                            page_number: 3,
                            is_last_page: true,
                        }
                    );
                }
            }

            mod named_args {
                use super::*;

                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn get_events_with_empty_filter() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = by_name([(
                        "filter",
                        json!({"page_size": test_utils::NUM_EVENTS, "page_number": 0}),
                    )]);
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();

                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events,
                            page_number: 0,
                            is_last_page: true,
                        }
                    );
                }

                #[tokio::test]
                async fn get_events_with_fully_specified_filter() {
                    let (storage, events) = setup();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let expected_event = &events[1];
                    let params = by_name([(
                        "filter",
                        json!({
                            "from_block": {
                                "block_number": expected_event.block_number.unwrap().get()
                            },
                            "to_block": {
                                "block_number": expected_event.block_number.unwrap().get()
                            },
                            "address": expected_event.from_address,
                            "keys": [expected_event.keys[0]],
                            "page_size": super::test_utils::NUM_EVENTS,
                            "page_number": 0,
                        }),
                    )]);

                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();

                    assert_eq!(
                        rpc_result,
                        GetEventsResult {
                            events: vec![expected_event.clone()],
                            page_number: 0,
                            is_last_page: true,
                        }
                    );
                }
            }

            mod pending {
                use crate::rpc::v01::types::request::EventFilter;

                use super::*;

                use pretty_assertions::assert_eq;

                #[tokio::test]
                async fn backward_range() {
                    let storage = setup_storage();
                    let pending_data = create_pending_data(storage.clone()).await;
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                        .with_pending_data(pending_data);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let params = rpc_params!(EventFilter {
                        from_block: Some(BlockId::Pending),
                        to_block: Some(BlockId::Latest),
                        address: None,
                        keys: vec![],
                        page_size: 100,
                        page_number: 0,
                    });
                    let rpc_result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", params)
                        .await
                        .unwrap();
                    assert!(rpc_result.events.is_empty());
                }

                #[tokio::test]
                async fn all_events() {
                    let storage = setup_storage();
                    let pending_data = create_pending_data(storage.clone()).await;
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                        .with_pending_data(pending_data);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let mut filter = EventFilter {
                        from_block: None,
                        to_block: Some(BlockId::Latest),
                        address: None,
                        keys: vec![],
                        page_size: 1024,
                        page_number: 0,
                    };

                    let events = client(addr)
                        .request::<GetEventsResult>(
                            "starknet_getEvents",
                            rpc_params!(filter.clone()),
                        )
                        .await
                        .unwrap();

                    filter.from_block = Some(BlockId::Pending);
                    filter.to_block = Some(BlockId::Pending);
                    let pending_events = client(addr)
                        .request::<GetEventsResult>(
                            "starknet_getEvents",
                            rpc_params!(filter.clone()),
                        )
                        .await
                        .unwrap();

                    filter.from_block = None;
                    let all_events = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter))
                        .await
                        .unwrap();

                    let expected = events
                        .events
                        .into_iter()
                        .chain(pending_events.events.into_iter())
                        .collect::<Vec<_>>();

                    assert_eq!(all_events.events, expected);
                    assert!(all_events.is_last_page);
                }

                #[tokio::test]
                async fn paging() {
                    let storage = setup_storage();
                    let pending_data = create_pending_data(storage.clone()).await;
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state)
                        .with_pending_data(pending_data);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let mut filter = EventFilter {
                        from_block: None,
                        to_block: Some(BlockId::Pending),
                        address: None,
                        keys: vec![],
                        page_size: 1024,
                        page_number: 0,
                    };

                    let all = client(addr)
                        .request::<GetEventsResult>(
                            "starknet_getEvents",
                            rpc_params!(filter.clone()),
                        )
                        .await
                        .unwrap()
                        .events;

                    filter.page_size = 2;
                    let mut last_pages = Vec::new();
                    let chunks = all.chunks(filter.page_size);
                    let num_chunks = chunks.len();
                    for (idx, chunk) in chunks.enumerate() {
                        filter.page_number = idx;
                        let result = client(addr)
                            .request::<GetEventsResult>(
                                "starknet_getEvents",
                                rpc_params!(filter.clone()),
                            )
                            .await
                            .unwrap();
                        assert_eq!(result.page_number, idx);
                        assert_eq!(result.events, chunk);

                        last_pages.push(result.is_last_page);
                    }

                    let mut expected = vec![false; last_pages.len() - 1];
                    expected.push(true);
                    assert_eq!(last_pages, expected);

                    // nonexistent page
                    filter.page_number = num_chunks;
                    let result = client(addr)
                        .request::<GetEventsResult>("starknet_getEvents", rpc_params!(filter))
                        .await
                        .unwrap();
                    assert_eq!(
                        result,
                        GetEventsResult {
                            events: vec![],
                            page_number: num_chunks,
                            is_last_page: true,
                        }
                    );
                }
            }
        }

        mod add_transaction {
            use super::*;
            use crate::rpc::v01::types::reply::{
                DeclareTransactionResult, DeployTransactionResult, InvokeTransactionResult,
            };

            lazy_static::lazy_static! {
                pub static ref CALL: ContractCall = ContractCall {
                    contract_address: ContractAddress::new_or_panic(
                        starkhash!("023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd")
                    ),
                    calldata: vec![
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1")),
                        CallParam(starkhash!("0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320")),
                        CallParam(starkhash!("00")),
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("01")),
                        CallParam(starkhash!("2b")),
                        CallParam(starkhash!("00")),
                    ],
                    entry_point_selector: Some(EntryPoint(starkhash!("015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad")))
                };
                pub static ref SIGNATURE: Vec<TransactionSignatureElem> = vec![
                    TransactionSignatureElem(starkhash!("07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5")),
                    TransactionSignatureElem(starkhash!("071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8")),
                ];
                pub static ref MAX_FEE: Fee = Fee(5444010076217u128.to_be_bytes().into());
                pub static ref TRANSACTION_VERSION: TransactionVersion = TransactionVersion(H256::zero());

                pub static ref ENTRY_POINTS_BY_TYPE: HashMap<EntryPointType, Vec<SelectorAndOffset>> =
                    HashMap::from([
                        (EntryPointType::Constructor, vec![]),
                        (
                            EntryPointType::External,
                            vec![
                                SelectorAndOffset {
                                    offset: ByteCodeOffset(starkhash!("3a")),
                                    selector: EntryPoint::hashed(&b"increase_balance"[..]),
                                },
                                SelectorAndOffset{
                                    offset: ByteCodeOffset(starkhash!("5b")),
                                    selector: EntryPoint::hashed(&b"get_balance"[..]),
                                },
                            ],
                        ),
                        (EntryPointType::L1Handler, vec![]),
                    ]);
                pub static ref PROGRAM: String = CONTRACT_DEFINITION_JSON["program"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                pub static ref CONTRACT_DEFINITION: ContractDefinition = ContractDefinition {
                    program: PROGRAM.clone(),
                    entry_points_by_type: ENTRY_POINTS_BY_TYPE.clone(),
                    abi: Some(CONTRACT_DEFINITION_JSON["abi"].clone()),
                };
            }

            mod positional_args {
                use std::collections::HashMap;

                use super::*;
                use crate::{
                    core::{
                        ByteCodeOffset, CallParam, CallSignatureElem, ClassHash, ConstructorParam,
                        ContractAddressSalt, EntryPoint, Fee, TransactionVersion,
                    },
                    rpc::v01::types::request::ContractCall,
                    sequencer::request::{
                        add_transaction::ContractDefinition,
                        contract::{EntryPointType, SelectorAndOffset},
                    },
                    starkhash,
                };

                use pretty_assertions::assert_eq;
                use web3::types::H256;

                #[tokio::test]
                async fn invoke_transaction_v1() {
                    use crate::core::TransactionNonce;

                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Testnet).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    let call = ContractCall {
                        contract_address: ContractAddress::new_or_panic(starkhash!(
                            "03fdcbeb68e607c8febf01d7ef274cbf68091a0bd1556c0b8f8e80d732f7850f"
                        )),
                        calldata: vec![
                            CallParam(starkhash!("01")),
                            CallParam(starkhash!(
                                "01d809111da75d5e735b6f9573a1ddff78fb6ff7633a0b34273e0c5ddeae349a"
                            )),
                            CallParam(starkhash!(
                                "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                            )),
                            CallParam(starkhash!("00")),
                            CallParam(starkhash!("01")),
                            CallParam(starkhash!("01")),
                            CallParam(starkhash!("01")),
                        ],
                        entry_point_selector: None,
                    };
                    let signature = vec![
                        TransactionSignatureElem(starkhash!(
                            "07ccc81b438581c9360120e0ba0ef52c7d031bdf20a4c2bc3820391b29a8945f"
                        )),
                        TransactionSignatureElem(starkhash!(
                            "02c11c60d11daaa0043eccdc824bb44f87bc7eb2e9c2437e1654876ab8fa7cad"
                        )),
                    ];
                    let max_fee = Fee(web3::types::H128::from_low_u64_be(0x630a0aff77));
                    let nonce = TransactionNonce(starkhash!("02"));

                    let params =
                        rpc_params!(call, signature, max_fee, TransactionVersion::ONE, nonce);
                    let rpc_result = client(addr)
                        .request::<InvokeTransactionResult>("starknet_addInvokeTransaction", params)
                        .await
                        .unwrap();

                    assert_eq!(
                        rpc_result,
                        InvokeTransactionResult {
                            transaction_hash: StarknetTransactionHash(starkhash!(
                                "040397a2e590c9707d73cc63ec54683c2d155b65d2e990d6f53d48a395eb3997"
                            ))
                        }
                    );
                }

                #[tokio::test]
                async fn declare_transaction() {
                    let storage = setup_storage();
                    let sequencer = Client::new(Chain::Integration).unwrap();
                    let sync_state = Arc::new(SyncState::default());
                    let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                    let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                    #[tokio::test]
                    async fn invoke_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Testnet).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let params = rpc_params!(
                            CALL.clone(),
                            SIGNATURE.clone(),
                            *MAX_FEE,
                            *TRANSACTION_VERSION
                        );
                        let rpc_result = client(addr)
                            .request::<InvokeTransactionResult>(
                                "starknet_addInvokeTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            InvokeTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
                            ))
                            }
                        );
                    }

                    #[tokio::test]
                    async fn declare_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Integration).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let contract_class = CONTRACT_DEFINITION.clone();

                        let params = rpc_params!(contract_class, *TRANSACTION_VERSION);

                        let rpc_result = client(addr)
                            .request::<DeclareTransactionResult>(
                                "starknet_addDeclareTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            DeclareTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "077ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed"
                            )),
                                class_hash: ClassHash(starkhash!(
                                "0711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"
                            )),
                            }
                        );
                    }

                    #[tokio::test]
                    async fn deploy_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Testnet).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let contract_definition = CONTRACT_DEFINITION.clone();
                        let contract_address_salt = ContractAddressSalt(starkhash!(
                            "05864b5e296c05028ac2bbc4a4c1378f56a3489d13e581f21d566bb94580f76d"
                        ));
                        let constructor_calldata: Vec<ConstructorParam> = vec![];

                        let params = rpc_params!(
                            contract_address_salt,
                            constructor_calldata,
                            contract_definition
                        );

                        let rpc_result = client(addr)
                            .request::<DeployTransactionResult>(
                                "starknet_addDeployTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            DeployTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "057ed4b4c76a1ca0ba044a654dd3ee2d0d3e550343d739350a22aacdd524110d"
                            )),
                                contract_address: ContractAddress::new_or_panic(starkhash!(
                                "03926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
                            )),
                            }
                        );
                    }
                }

                mod named_args {
                    use crate::{core::ClassHash, starkhash};

                    use super::*;

                    use pretty_assertions::assert_eq;

                    #[tokio::test]
                    async fn invoke_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Testnet).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let params = by_name([
                    (
                        "function_invocation",
                        json!({
                            "contract_address": "0x23371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                            "calldata": [
                                "1",
                                "0x677BB1CDC050E8D63855E8743AB6E09179138DEF390676CC03C484DAF112BA1",
                                "0x362398BEC32BC0EBB411203221A35A0301193A96F317EBE5E40BE9F60D15320",
                                "0",
                                "1",
                                "1",
                                "0x2B",
                                "0"
                            ],
                            "entry_point_selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
                        }),
                    ),
                    (
                        "signature",
                        json!([
                            "3557065757165699682249469970267166698995647077461960906176449260016084767701",
                            "3202126414680946801789588986259466145787792017299869598314522555275920413944"
                        ]),
                    ),
                    ("max_fee", json!("0x4f388496839")),
                    ("version", json!("0x0")),
                ]);

                        let rpc_result = client(addr)
                            .request::<InvokeTransactionResult>(
                                "starknet_addInvokeTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            InvokeTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
                            ))
                            }
                        );
                    }

                    #[tokio::test]
                    async fn declare_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Integration).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let params = by_name([
                            ("contract_class", CONTRACT_DEFINITION_JSON.clone()),
                            ("version", json!("0x0")),
                        ]);

                        let rpc_result = client(addr)
                            .request::<DeclareTransactionResult>(
                                "starknet_addDeclareTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            DeclareTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "077ccba4df42cf0f74a8eb59a96d7880fae371edca5d000ca5f9985652c8a8ed"
                            )),
                                class_hash: ClassHash(starkhash!(
                                "0711941b11a8236b8cca42b664e19342ac7300abb1dc44957763cb65877c2708"
                            )),
                            }
                        );
                    }

                    #[tokio::test]
                    async fn deploy_transaction() {
                        let storage = setup_storage();
                        let sequencer = Client::new(Chain::Testnet).unwrap();
                        let sync_state = Arc::new(SyncState::default());
                        let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                        let (__handle, addr) = run_server(*LOCALHOST, api).await.unwrap();

                        let params = by_name([
                            (
                                "contract_address_salt",
                                json!(
                                "0x5864b5e296c05028ac2bbc4a4c1378f56a3489d13e581f21d566bb94580f76d"
                            ),
                            ),
                            ("constructor_calldata", json!([])),
                            ("contract_definition", CONTRACT_DEFINITION_JSON.clone()),
                        ]);

                        let rpc_result = client(addr)
                            .request::<DeployTransactionResult>(
                                "starknet_addDeployTransaction",
                                params,
                            )
                            .await
                            .unwrap();

                        assert_eq!(
                            rpc_result,
                            DeployTransactionResult {
                                transaction_hash: StarknetTransactionHash(starkhash!(
                                "057ed4b4c76a1ca0ba044a654dd3ee2d0d3e550343d739350a22aacdd524110d"
                            )),
                                contract_address: ContractAddress::new_or_panic(starkhash!(
                                "03926aea98213ec34fe9783d803237d221c54c52344422e1f4942a5b340fa6ad"
                            )),
                            }
                        );
                    }
                }
            }

            #[tokio::test]
            async fn per_method_metrics() {
                use crate::monitoring::metrics::test::FakeRecorder;
                use crate::monitoring::metrics::{
                    middleware::RpcMetricsMiddleware, test::RecorderGuard,
                };
                use crate::rpc::v01::types::reply::Block;
                use futures::stream::StreamExt;

                let recorder = FakeRecorder::new(&["starknet_getBlockWithTxHashes"]);
                let handle = recorder.handle();

                let get_all = || {
                    handle.get_counter_value(
                        "rpc_method_calls_total",
                        "starknet_getBlockWithTxHashes",
                    )
                };
                let get_failed = || {
                    handle.get_counter_value(
                        "rpc_method_calls_failed_total",
                        "starknet_getBlockWithTxHashes",
                    )
                };

                // Other concurrent tests could be setting their own recorders
                let _guard = RecorderGuard::lock(recorder);

                let storage = setup_storage();
                let sequencer = Client::new(Chain::Testnet).unwrap();
                let sync_state = Arc::new(SyncState::default());
                let api = RpcApi::new(storage, sequencer, Chain::Testnet, sync_state);
                let (__handle, addr) = RpcServer::new(*LOCALHOST, api)
                    .with_middleware(RpcMetricsMiddleware)
                    .run()
                    .await
                    .unwrap();

                assert_eq!(get_all(), 0);
                assert_eq!(get_failed(), 0);

                // Two successes and a failure
                [
                    StarknetBlockNumber::GENESIS,
                    StarknetBlockNumber::GENESIS + 1,
                    StarknetBlockNumber::MAX,
                ]
                .into_iter()
                .map(|block_number| async move {
                    let _ = client(addr)
                        .request::<Block>(
                            "starknet_getBlockWithTxHashes",
                            rpc_params!(BlockId::Number(block_number)),
                        )
                        .await;
                })
                .collect::<futures::stream::FuturesUnordered<_>>()
                .collect::<Vec<_>>()
                .await;

                assert_eq!(get_all(), 3);
                assert_eq!(get_failed(), 1);
            }
        }
    }
}
