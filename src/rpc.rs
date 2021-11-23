//! StarkNet node JSON-RPC related modules.
pub mod rpc_impl;
pub mod rpc_trait;
pub mod types;

use crate::rpc::{rpc_impl::RpcImpl, rpc_trait::RpcApiServer};
use jsonrpsee::{http_server::HttpServerBuilder, types::Error};
use std::{net::SocketAddr, result::Result};

/// Starts the HTTP-RPC server.
pub async fn run_server(addr: SocketAddr) -> Result<(), Error> {
    let server = HttpServerBuilder::default().build(addr)?;
    println!("📡 HTTP-RPC server started on: {}", server.local_addr()?);
    server.start(RpcImpl::default().into_rpc()).await
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
        tokio::spawn(srv.start(RpcImpl::default().into_rpc()));
    }

    mod get_block_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};
        use web3::types::H256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_hash(BlockHashOrTag::Hash(H256::zero() /*TODO*/))
                .await
                .unwrap();
        }
    }

    mod get_block_by_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        // "middle" means < latest && > genesis
        #[tokio::test]
        async fn middle() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Number(U256::from(4096)))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Number(U256::zero()))
                .await
                .unwrap();
        }
    }

    mod get_state_update_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};
        use web3::types::H256;

        #[tokio::test]
        #[should_panic]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_state_update_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_state_update_by_hash(BlockHashOrTag::Hash(H256::zero() /*TODO*/))
                .await
                .unwrap();
        }
    }

    mod get_storage_at {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};
        use web3::types::H256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    H256::from_str(
                        "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                    )
                    .unwrap()
                    .into(),
                    H256::from_str(
                        "0x0206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091",
                    )
                    .unwrap()
                    .into(),
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    H256::from_str(
                        "0x4c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                    )
                    .unwrap()
                    .into(),
                    H256::from_str(
                        "0x206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091",
                    )
                    .unwrap()
                    .into(),
                    BlockHashOrTag::Hash(H256::zero() /*TODO hash for block 5272*/),
                )
                .await
                .unwrap();
        }
    }

    mod get_storage_at_by_block_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};
        use web3::types::H256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at_by_block_number(
                    H256::from_str(
                        "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                    )
                    .unwrap()
                    .into(),
                    H256::from_str(
                        "0x0206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091",
                    )
                    .unwrap()
                    .into(),
                    BlockNumberOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at_by_block_number(
                    H256::from_str(
                        "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                    )
                    .unwrap()
                    .into(),
                    H256::from_str(
                        "0x0206f38f7e4f15e87567361213c28f235cccdaa1d7fd34c9db1dfe9489c6a091",
                    )
                    .unwrap()
                    .into(),
                    BlockNumberOrTag::Number(U256::from(5272)),
                )
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_hash {
        use super::*;
        use web3::types::H256;

        #[tokio::test]
        async fn get_transaction_by_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_hash(
                    H256::from_str(
                        "0x0285b9a272dd72769789d06400bf0da86ed80555b98ca8a6df0cc888c694e3f1",
                    )
                    .unwrap()
                    .into(),
                )
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_block_hash_and_index {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};
        use web3::types::H256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(BlockHashOrTag::Tag(Tag::Latest), 0)
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(
                    BlockHashOrTag::Hash(H256::zero() /*TODO*/),
                    0,
                )
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_block_number_and_index {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};
        use web3::types::U256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_number_and_index(BlockNumberOrTag::Tag(Tag::Latest), 0)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_number_and_index(
                    BlockNumberOrTag::Number(U256::from(5272)),
                    0,
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn get_transaction_receipt() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_transaction_receipt(
                H256::from_str(
                    "0x0285b9a272dd72769789d06400bf0da86ed80555b98ca8a6df0cc888c694e3f1",
                )
                .unwrap()
                .into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_code() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr)
            .get_code(
                H256::from_str(
                    "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                )
                .unwrap()
                .into(),
            )
            .await
            .unwrap();
    }

    mod get_block_transaction_count_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_hash(BlockHashOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_hash(BlockHashOrTag::Hash(
                    H256::zero(), /*TODO*/
                ))
                .await
                .unwrap();
        }
    }

    mod get_block_transaction_count_by_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};
        use web3::types::U256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_number(BlockNumberOrTag::Number(U256::from(5272)))
                .await
                .unwrap();
        }
    }

    mod call {
        use super::*;
        use crate::{
            rpc::types::{BlockHashOrTag, Tag},
            sequencer::request::Call,
        };

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: H256::from_str(
                            "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                        )
                        .unwrap(),
                        entry_point_selector: H256::from_str(
                            "0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                        )
                        .unwrap(),
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic]
        async fn not_latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: H256::from_str(
                            "0x04c988a22c691166946fdcfcd1608518333065e6deb1519d5d5f8def8b6c3e78",
                        )
                        .unwrap(),
                        entry_point_selector: H256::from_str(
                            "0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                        )
                        .unwrap(),
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(H256::zero() /*TODO*/),
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn block_number() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).block_number().await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn chain_id() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).chain_id().await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn pending_transactions() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).pending_transactions().await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn protocol_version() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).protocol_version().await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn syncing() {
        let (srv, addr) = build_server();
        spawn_server(srv).await;
        client(addr).syncing().await.unwrap();
    }
}
