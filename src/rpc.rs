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
    use crate::rpc::{rpc_trait::RpcApiClient, types::relaxed};
    use jsonrpsee::{
        http_client::{HttpClient, HttpClientBuilder},
        http_server::{HttpServer, HttpServerBuilder},
    };
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        str::FromStr,
    };
    use web3::types::H256;

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

    lazy_static::lazy_static! {
        static ref GENESIS_BLOCK_HASH: H256 = H256::from_str("0x07d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b").unwrap();
        static ref INVALID_BLOCK_HASH: H256 = H256::from_str("0x13d8d8bb5716cd3f16e54e3a6ff1a50542461d9022e5f4dec7a4b064041ab8d7").unwrap();
        static ref UNKNOWN_BLOCK_HASH: H256 = H256::from_str("0x017adea6567a9f605d5011ac915bdda56dc1db37e17a7057b3dd7fa99c4ba30b").unwrap();
        static ref CONTRACT_BLOCK_HASH: H256 = H256::from_str("0x009aaa1733f916339979d0df10e2969c4a12146e80c8aa5bafbec876605bf35a").unwrap();
        static ref VALID_TX_HASH: relaxed::H256 = H256::from_str("0x0493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap().into();
        static ref INVALID_TX_HASH: relaxed::H256 = H256::from_str("0x1493d8fab73af67e972788e603aee18130facd3c7685f16084ecd98b07153e24").unwrap().into();
        static ref UNKNOWN_TX_HASH: relaxed::H256 = H256::from_str("0x015e4bb72df94be3044139fea2116c4d54add05cf9ef8f35aea114b5cea94713").unwrap().into();
        static ref VALID_CONTRACT_ADDR: relaxed::H256 = H256::from_str("0x06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap().into();
        static ref INVALID_CONTRACT_ADDR: relaxed::H256 = H256::from_str("0x16fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39").unwrap().into();
        static ref UNKNOWN_CONTRACT_ADDR: relaxed::H256 = H256::from_str("0x0739636829ad5205d81af792a922a40e35c0ec7a72f4859843ee2e2a0d6f0af0").unwrap().into();
        static ref VALID_ENTRY_POINT: relaxed::H256 = H256::from_str("0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320").unwrap().into();
    }

    mod get_block_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
        #[ignore = "currently causes HTTP 504"]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_hash(BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH))
                .await
                .unwrap();
        }

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
        async fn not_found() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_hash(BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH))
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_hash(BlockHashOrTag::Hash(*INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
        }
    }

    mod get_block_by_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};

        #[tokio::test]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Number(0))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_number() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_by_number(BlockNumberOrTag::Number(u64::MAX))
                .await
                .unwrap_err();
        }
    }

    mod get_state_update_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
        #[should_panic]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_state_update_by_hash(BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH))
                .await
                .unwrap();
        }

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
    }

    mod get_storage_at {
        use super::*;
        use crate::rpc::types::{relaxed, BlockHashOrTag, Tag};
        use web3::types::H256;

        lazy_static::lazy_static! {
            static ref VALID_KEY: relaxed::H256 = H256::from_str("0x0206F38F7E4F15E87567361213C28F235CCCDAA1D7FD34C9DB1DFE9489C6A091").unwrap().into();
            static ref CONTRACT_BLOCK: H256 = H256::from_str("0x03871c8a0c3555687515a07f365f6f5b1d8c2ae953f7844575b8bde2b2efed27").unwrap();
        }

        #[tokio::test]
        async fn invalid_contract() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *INVALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_key() {
            // Invalid key results with storage value of zero
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *VALID_CONTRACT_ADDR,
                    H256::zero().into(),
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn block_not_found() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Hash(H256::zero()),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn contract_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn latest_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_storage_at(
                    *VALID_CONTRACT_ADDR,
                    *VALID_KEY,
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_hash {
        use super::*;

        #[tokio::test]
        async fn accepted() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_hash(*VALID_TX_HASH)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_hash(*INVALID_TX_HASH)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_hash(*UNKNOWN_TX_HASH)
                .await
                .unwrap();
        }
    }

    mod get_transaction_by_block_hash_and_index {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

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
        #[ignore = "currently causes HTTP 504"]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(
                    BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH),
                    0,
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(
                    BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                    0,
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(
                    BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
                    0,
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_transaction_index() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_hash_and_index(
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
                    u64::MAX,
                )
                .await
                .unwrap_err();
        }
    }

    mod get_transaction_by_block_number_and_index {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};

        #[tokio::test]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_number_and_index(BlockNumberOrTag::Number(0), 0)
                .await
                .unwrap();
        }

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
        async fn invalid_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_by_block_number_and_index(BlockNumberOrTag::Number(u64::MAX), 0)
                .await
                .unwrap_err();
        }
    }

    mod get_transaction_receipt {
        use super::*;

        #[tokio::test]
        async fn accepted() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_receipt(*VALID_TX_HASH)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_receipt(*INVALID_TX_HASH)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_transaction_receipt(*UNKNOWN_TX_HASH)
                .await
                .unwrap();
        }
    }

    mod get_code {
        use super::*;

        #[tokio::test]
        async fn invalid_contract_address() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_code(*INVALID_CONTRACT_ADDR)
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown_contract_address() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr).get_code(*UNKNOWN_CONTRACT_ADDR).await.unwrap();
        }

        #[tokio::test]
        async fn success() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr).get_code(*VALID_CONTRACT_ADDR).await.unwrap();
        }
    }

    mod get_block_transaction_count_by_hash {
        use super::*;
        use crate::rpc::types::{BlockHashOrTag, Tag};

        #[tokio::test]
        #[ignore = "currently causes HTTP 504"]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_hash(BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH))
                .await
                .unwrap();
        }

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
        async fn invalid() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_hash(BlockHashOrTag::Hash(*INVALID_BLOCK_HASH))
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_hash(BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH))
                .await
                .unwrap_err();
        }
    }

    mod get_block_transaction_count_by_number {
        use super::*;
        use crate::rpc::types::{BlockNumberOrTag, Tag};

        #[tokio::test]
        async fn genesis() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_number(BlockNumberOrTag::Number(0))
                .await
                .unwrap();
        }

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
        async fn invalid() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .get_block_transaction_count_by_number(BlockNumberOrTag::Number(u64::MAX))
                .await
                .unwrap_err();
        }
    }

    mod call {
        use super::*;
        use crate::{
            rpc::types::{BlockHashOrTag, Tag},
            sequencer::request::Call,
        };
        use web3::types::U256;

        #[tokio::test]
        async fn latest() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn invalid_entry_point() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: H256::zero(),
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_contract_address() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **INVALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_call_data() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Tag(Tag::Latest),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn uninitialized_contract() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(*GENESIS_BLOCK_HASH),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn invalid_block_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(*INVALID_BLOCK_HASH),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn unknown_block_hash() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(*UNKNOWN_BLOCK_HASH),
                )
                .await
                .unwrap_err();
        }

        #[tokio::test]
        async fn latest_invoked_block() {
            let (srv, addr) = build_server();
            spawn_server(srv).await;
            client(addr)
                .call(
                    Call {
                        calldata: vec![U256::from(1234)],
                        contract_address: **VALID_CONTRACT_ADDR,
                        entry_point_selector: **VALID_ENTRY_POINT,
                        signature: vec![],
                    },
                    BlockHashOrTag::Hash(*CONTRACT_BLOCK_HASH),
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
