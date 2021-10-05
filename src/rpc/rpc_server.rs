//! Logic for instantiating the JSON-RPC server.
use crate::{
    config::HttpRpcConfig,
    rpc::{rpc_impl::RpcImpl, rpc_trait::RpcApiServer},
};
use jsonrpsee::http_server::HttpServerBuilder;
use std::net::SocketAddr;

/// Starts the HTTP-RPC server.
pub async fn run_server(config: &HttpRpcConfig) -> anyhow::Result<()> {
    if !config.enable {
        println!("🚫 HTTP-RPC server is disabled.");
        return Ok(());
    }

    let server = HttpServerBuilder::default().build(SocketAddr::new(
        config
            .address
            .expect("Default listening interface is provided when HTTP-RPC server is enabled"),
        config
            .port
            .expect("Default listening port is provided when HTTP-RPC server is enabled"),
    ))?;

    let addr = server.local_addr()?;

    println!("📡 HTTP-RPC server started on: {}", addr);

    let handle = tokio::spawn(async move { server.start(RpcImpl::new().into_rpc()).await });

    handle.await??;

    Ok(())
}
