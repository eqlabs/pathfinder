//! StarkNet node JSON-RPC related modules.
pub mod rpc_impl;
pub mod rpc_trait;

use crate::rpc::{rpc_impl::RpcImpl, rpc_trait::RpcApiServer};
use jsonrpsee::{http_server::HttpServerBuilder, types::Error};
use std::{net::SocketAddr, result::Result};

/// Starts the HTTP-RPC server.
pub async fn run_server(addr: SocketAddr) -> Result<(), Error> {
    let server = HttpServerBuilder::default().build(addr)?;
    println!("📡 HTTP-RPC server started on: {}", server.local_addr()?);
    server.start(RpcImpl::new().into_rpc()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::rpc_trait::RpcApiClient;
    use jsonrpsee::{
        http_client::{HttpClient, HttpClientBuilder},
        http_server::{HttpServer, HttpServerBuilder},
    };
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        str::FromStr,
    };
    use web3::types::{H256, U256};

    /// Helper rpc client
    fn client(addr: SocketAddr) -> HttpClient {
        HttpClientBuilder::default()
            .build(format!("http://{}", addr))
            .expect("Failed to create HTTP-RPC client")
    }

    /// Helper server build function which allows for actual address retrieval
    fn build_server() -> (HttpServer, SocketAddr) {
        let server = HttpServerBuilder::default()
            .build(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("Server build failed");
        let addr = server.local_addr().expect("Failed to get address");
        (server, addr)
    }

    /// Server spawn wrapper
    async fn spawn_server(srv: HttpServer) {
        tokio::spawn(srv.start(RpcImpl::new().into_rpc()));
    }

    #[tokio::test]
    async fn block_number() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).block_number().await.expect("Call failed");
    }

    #[tokio::test]
    async fn get_block_by_hash_latest() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_block_by_hash("latest".to_owned())
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    #[should_panic]
    async fn get_block_by_hash() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_block_by_hash("0xa38e".to_owned())
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_block_by_number() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_block_by_number("latest".to_owned())
            .await
            .expect("Call failed");
        client(addr)
            .get_block_by_number("0x1000".to_owned())
            .await
            .expect("Call failed");
        client(addr)
            .get_block_by_number("0xa38e".to_owned())
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    #[should_panic]
    async fn get_transaction_by_hash() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_by_hash("0x23c86".to_owned())
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_transaction_by_number() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_by_number("0x23c86".to_owned())
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_transaction_by_latest_block_hash_and_index() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_by_block_hash_and_index("latest".to_owned(), 0)
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    #[should_panic]
    async fn get_transaction_by_block_hash_and_index() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_by_block_hash_and_index("0x3e4a".to_owned(), 7)
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_transaction_by_block_number_and_index() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_by_block_number_and_index("latest".to_owned(), 0)
            .await
            .expect("Call failed");
        client(addr)
            .get_transaction_by_block_number_and_index("0x3e4a".to_owned(), 7)
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_storage() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_storage(
                H256::from_str(
                    "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                )
                .unwrap(),
                U256::from_str_radix(
                    "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091",
                    16,
                )
                .unwrap(),
            )
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn get_code() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_code(
                H256::from_str(
                    "0x04eab694d0c8dbcccf5b9e661ce97d6c37793014ecab873dcbe68cb452b3dffc",
                )
                .unwrap(),
            )
            .await
            .expect("Call failed");
    }

    #[tokio::test]
    async fn call() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .call(
                H256::from_str(
                    "0x0399d3cf2405e997b1cda8c45f5ba919a6499f3d3b00998d5a91d6d9bcbc9128",
                )
                .unwrap(),
                vec![],
                H256::from_str(
                    "0x039e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
                )
                .unwrap(),
            )
            .await
            .expect("Call failed");
    }
}
