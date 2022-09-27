use std::sync::Arc;

use super::error::RpcError;
use crate::{core::Chain, state::SyncState};
use crate::{state::PendingData, storage::Storage};

pub mod method;
pub mod types;

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: Option<PendingData>,
    pub sync_status: Arc<SyncState>,
    pub chain: Chain,
}

impl RpcContext {
    pub fn new(storage: Storage, sync_status: Arc<SyncState>, chain: Chain) -> Self {
        Self {
            storage,
            sync_status,
            chain,
            pending_data: None,
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        let storage = super::tests::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        Self::new(storage, sync_state, Chain::Testnet)
    }

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data: Some(pending_data),
            ..self
        }
    }

    #[cfg(test)]
    pub async fn for_tests_with_pending() -> Self {
        // This is a bit silly with the arc in and out, but since its for tests the ergonomics of
        // having Arc also constructed is nice.
        let context = Self::for_tests();
        let pending_data = super::tests::create_pending_data(context.storage.clone()).await;
        context.with_pending_data(pending_data)
    }
}

// FIXME
// We could as well extract rpc version agnostic context to be fed into both v01::RpcApi and v02::RpcContext.
// Rework once all v0.2 methods are implemented.
impl From<&super::v01::api::RpcApi> for RpcContext {
    fn from(v01: &super::v01::api::RpcApi) -> Self {
        Self {
            storage: v01.storage.clone(),
            pending_data: v01.pending_data.clone(),
            sync_status: v01.sync_state.clone(),
            chain: v01.chain,
        }
    }
}

/// Registers a JSON-RPC method with the [RpcModule<RpcContext>](jsonrpsee::RpcModule).
///
/// An example signature for `method` is:
/// ```ignore
/// async fn method(context: Arc<RpcContext>, input: Input) -> Result<Ouput, Error>
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
/// async fn method(context: Arc<RpcContext>) -> Result<Ouput, Error>
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
    register_method_with_no_input(module, "starknet_chainId", method::chain_id::chain_id)?;
    register_method(module, "starknet_getNonce", method::get_nonce::get_nonce)?;
    register_method(
        module,
        "starknet_getTransactionByHash",
        method::get_transaction_by_hash::get_transaction_by_hash,
    )?;
    register_method(
        module,
        "starknet_getTransactionReceipt",
        method::get_transaction_receipt::get_transaction_receipt,
    )?;
    register_method_with_no_input(module, "starknet_syncing", method::syncing::syncing)?;

    Ok(())
}
