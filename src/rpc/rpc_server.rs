//! Logic for instantiating the JSON-RPC server.
use super::{rpc_impl::RpcImpl, rpc_trait::RpcApiServer};
use jsonrpsee::http_server::HttpServerBuilder;
use std::{net::SocketAddr, str::FromStr};

pub async fn run_server() -> anyhow::Result<SocketAddr> {
    let server = HttpServerBuilder::default().build(SocketAddr::from_str("127.0.0.1:1234")?)?;

    let addr = server.local_addr()?;
    let _stop_handle = server.stop_handle();

    eprintln!("RPC server on address: {}", addr);

    let handle = tokio::spawn(async move { server.start(RpcImpl.into_rpc()).await });

    handle.await??;

    Ok(addr)
}
