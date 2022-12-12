use crate::context::RpcContext;
use crate::error::RpcError;
use std::sync::Arc;

mod common;
pub mod method;
pub mod types;

/// Registers a JSON-RPC method with the [RpcModule<RpcContext>](jsonrpsee::RpcModule).
///
/// An example signature for `method` is:
/// ```ignore
/// async fn method(context: RpcContext, input: Input) -> Result<Ouput, Error>
/// ```
fn register_method<Input, Output, Error, MethodFuture, Method>(
    module: &mut jsonrpsee::RpcModule<RpcContext>,
    method_name: &'static str,
    method: Method,
) -> anyhow::Result<()>
where
    Input: ::serde::de::DeserializeOwned + Send + Sync,
    Output: 'static + ::serde::Serialize + Send + Sync,
    Error: Into<RpcError>,
    MethodFuture: std::future::Future<Output = Result<Output, Error>> + Send,
    Method: (Fn(RpcContext, Input) -> MethodFuture) + Copy + Send + Sync + 'static,
{
    use anyhow::Context;
    use jsonrpsee::types::Params;
    use tracing::Instrument;

    metrics::register_counter!("rpc_method_calls_total", "method" => method_name);

    let method_callback = move |params: Params<'static>, context: Arc<RpcContext>| {
        // why info here? it's the same used in warp tracing filter for example.
        let span = tracing::info_span!("rpc_method", name = method_name);
        async move {
            let input = params.parse::<Input>()?;
            method((*context).clone(), input).await.map_err(|err| {
                let rpc_err: RpcError = err.into();
                jsonrpsee::core::Error::from(rpc_err)
            })
        }
        .instrument(span)
    };

    module
        .register_async_method(method_name, method_callback)
        .with_context(|| format!("Registering {method_name}"))?;

    Ok(())
}

/// Registers a JSON-RPC method with the [RpcModule<RpcContext>](jsonrpsee::RpcModule).
///
/// An example signature for `method` is:
/// ```ignore
/// async fn method(context: RpcContext) -> Result<Ouput, Error>
/// ```
fn register_method_with_no_input<Output, Error, MethodFuture, Method>(
    module: &mut jsonrpsee::RpcModule<RpcContext>,
    method_name: &'static str,
    method: Method,
) -> anyhow::Result<()>
where
    Output: 'static + ::serde::Serialize + Send + Sync,
    Error: Into<RpcError>,
    MethodFuture: std::future::Future<Output = Result<Output, Error>> + Send,
    Method: (Fn(RpcContext) -> MethodFuture) + Copy + Send + Sync + 'static,
{
    use anyhow::Context;
    use tracing::Instrument;

    metrics::register_counter!("rpc_method_calls_total", "method" => method_name);

    let method_callback = move |_params, context: Arc<RpcContext>| {
        // why info here? it's the same used in warp tracing filter for example.
        let span = tracing::info_span!("rpc_method", name = method_name);
        async move {
            method((*context).clone()).await.map_err(|err| {
                let rpc_err: RpcError = err.into();
                jsonrpsee::core::Error::from(rpc_err)
            })
        }
        .instrument(span)
    };

    module
        .register_async_method(method_name, method_callback)
        .with_context(|| format!("Registering {method_name}"))?;

    Ok(())
}

// Registers all methods for the v0.2 API
pub fn register_all_methods(module: &mut jsonrpsee::RpcModule<RpcContext>) -> anyhow::Result<()> {
    register_method(module, "starknet_call", method::call::call)?;
    register_method_with_no_input(module, "starknet_chainId", method::chain_id::chain_id)?;
    register_method(
        module,
        "starknet_getBlockWithTxHashes",
        method::get_block::get_block_with_tx_hashes,
    )?;
    register_method(
        module,
        "starknet_getBlockWithTxs",
        method::get_block::get_block_with_txs,
    )?;
    register_method(module, "starknet_getClass", method::get_class::get_class)?;
    register_method(
        module,
        "starknet_getClassAt",
        method::get_class_at::get_class_at,
    )?;
    register_method(
        module,
        "starknet_getClassHashAt",
        method::get_class_hash_at::get_class_hash_at,
    )?;
    register_method(module, "starknet_getEvents", method::get_events::get_events)?;
    register_method(
        module,
        "starknet_estimateFee",
        method::estimate_fee::estimate_fee,
    )?;
    register_method(module, "starknet_getNonce", method::get_nonce::get_nonce)?;
    register_method_with_no_input(
        module,
        "starknet_pendingTransactions",
        method::pending_transactions::pending_transactions,
    )?;
    register_method(
        module,
        "starknet_getStateUpdate",
        method::get_state_update::get_state_update,
    )?;
    register_method(
        module,
        "starknet_getStorageAt",
        method::get_storage_at::get_storage_at,
    )?;
    register_method(
        module,
        "starknet_getTransactionByHash",
        method::get_transaction_by_hash::get_transaction_by_hash,
    )?;
    register_method(
        module,
        "starknet_getTransactionByBlockIdAndIndex",
        method::get_transaction_by_block_id_and_index::get_transaction_by_block_id_and_index,
    )?;
    register_method(
        module,
        "starknet_getTransactionReceipt",
        method::get_transaction_receipt::get_transaction_receipt,
    )?;
    register_method_with_no_input(module, "starknet_syncing", method::syncing::syncing)?;
    register_method(
        module,
        "starknet_getBlockTransactionCount",
        method::get_block_transaction_count::get_block_transaction_count,
    )?;
    register_method_with_no_input(
        module,
        "starknet_blockHashAndNumber",
        method::block_hash_and_number::block_hash_and_number,
    )?;
    register_method_with_no_input(
        module,
        "starknet_blockNumber",
        method::block_hash_and_number::block_number,
    )?;

    register_method(
        module,
        "starknet_addInvokeTransaction",
        method::add_invoke_transaction::add_invoke_transaction,
    )?;
    register_method(
        module,
        "starknet_addDeclareTransaction",
        method::add_declare_transaction::add_declare_transaction,
    )?;
    register_method(
        module,
        "starknet_addDeployTransaction",
        method::add_deploy_transaction::add_deploy_transaction,
    )?;
    register_method(
        module,
        "starknet_addDeployAccountTransaction",
        method::add_deploy_account_transaction::add_deploy_account_transaction,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::RpcContext;
    use crate::test_client::TestClientBuilder;
    use crate::{RpcApi, RpcServer};
    use jsonrpsee::rpc_params;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[tokio::test]
    async fn registered_method_is_callable_via_json_rpc() {
        let ctx = RpcContext::for_tests();
        let api = RpcApi::new(
            ctx.storage.clone(),
            ctx.sequencer.clone(),
            ctx.chain_id,
            ctx.sync_status.clone(),
        );
        let (__handle, addr) = RpcServer::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            api,
        )
        .run()
        .await
        .unwrap();

        let client = TestClientBuilder::default()
            .request_timeout(std::time::Duration::from_secs(120))
            .address(addr)
            .build()
            .expect("Create v0.2 RPC client on default path");

        // A method with no params via `register_method_with_no_input`
        let params = rpc_params!();
        let number = client
            .request::<u64>("starknet_blockNumber", params)
            .await
            .unwrap();
        assert_eq!(number, 2);

        // A method with params via `register_method`
        let params = rpc_params!("latest");
        let number = client
            .request::<u64>("starknet_getBlockTransactionCount", params)
            .await
            .unwrap();
        assert_eq!(number, 3);
    }
}
