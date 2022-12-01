use super::error::RpcError;
use crate::cairo::ext_py;
use crate::rpc::gas_price;
use crate::state::SyncState;
use crate::{state::PendingData, storage::Storage};
use pathfinder_common::ChainId;
use std::sync::Arc;

mod common;
pub mod method;
pub mod types;

type SequencerClient = crate::sequencer::Client;

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: Option<PendingData>,
    pub sync_status: Arc<SyncState>,
    pub chain_id: ChainId,
    pub call_handle: Option<ext_py::Handle>,
    pub eth_gas_price: Option<gas_price::Cached>,
    pub sequencer: SequencerClient,
}

impl RpcContext {
    pub fn new(
        storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        sequencer: SequencerClient,
    ) -> Self {
        Self {
            storage,
            sync_status,
            chain_id,
            pending_data: None,
            call_handle: None,
            eth_gas_price: None,
            sequencer,
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::Testnet)
    }

    #[cfg(test)]
    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        assert_ne!(chain, Chain::Mainnet, "Testing on MainNet?");

        use pathfinder_common::Chain;
        let chain_id = match chain {
            Chain::Mainnet => ChainId::MAINNET,
            Chain::Testnet => ChainId::TESTNET,
            Chain::Integration => ChainId::INTEGRATION,
            Chain::Testnet2 => ChainId::TESTNET2,
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::tests::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        let sequencer = SequencerClient::new(chain).unwrap();
        Self::new(storage, sync_state, chain_id, sequencer)
    }

    #[cfg(test)]
    pub fn with_storage(self, storage: Storage) -> Self {
        Self { storage, ..self }
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

    pub fn with_call_handling(self, call_handle: ext_py::Handle) -> Self {
        Self {
            call_handle: Some(call_handle),
            ..self
        }
    }

    pub fn with_eth_gas_price(self, gas_price: gas_price::Cached) -> Self {
        Self {
            eth_gas_price: Some(gas_price),
            ..self
        }
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
            chain_id: v01.chain_id,
            call_handle: v01.call_handle.clone(),
            eth_gas_price: v01.shared_gas_price.clone(),
            sequencer: v01.sequencer.clone(),
        }
    }
}

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
    register_method(
        module,
        "pathfinder_getProof",
        method::get_storage_proofs::get_storage_proofs,
    )?;
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
    use crate::rpc::test_client::TestClientBuilder;
    use crate::rpc::{RpcApi, RpcServer};
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
