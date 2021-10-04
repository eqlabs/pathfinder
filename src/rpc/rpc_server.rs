//! Logic for instantiating the JSON-RPC server.
use crate::rpc::{rpc_impl::RpcImpl, rpc_trait::RpcApiServer};
use jsonrpsee::{http_server::HttpServerBuilder, types::Error};
use std::{net::SocketAddr, result::Result};

/// Starts the HTTP-RPC server.
pub async fn run_server(addr: SocketAddr) -> Result<(), Error> {
    let server = HttpServerBuilder::default().build(addr)?;
    println!("📡 HTTP-RPC server started on: {}", server.local_addr()?);
    server.start(RpcImpl::new().into_rpc()).await
}
