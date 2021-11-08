//! Contains abstractions around the core StarkNet contract(s).
//!
//! The core contract uses a proxy pattern. The core contract stores
//! the address to the actual core implementation contract. This address
//! can be changed, which lets the contract be updated without requiring
//! the users to update their addresses.
//!
//! The core contract simply forwards any function calls it's ABI doesn't
//! support to the core implementation contract. In effect, the core
//! contract therefore has a combined ABI of both the proxy as well as the
//! implementation.

use std::str::FromStr;

use web3::{
    contract::{Contract, Options},
    transports::WebSocket,
    types::{H160, U256},
    Web3,
};

use anyhow::Result;

use crate::ethereum::BlockId;

/// The address of the core StarkNet contract (proxy).
const CORE_PROXY_ADDR: &str = "0x67D629978274b4E1e07256Ec2ef39185bb3d4D0d";
/// The address of the core contract implementation.
const CORE_IMPL_ADDR: &str = "0x4e5e71dc0eb7a6ddc3f6030542a327c0db849397";

const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_proxy.json"
));

const CORE_IMPL_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_impl.json"
));

pub struct CoreContract {
    contract: Contract<WebSocket>,
}

impl CoreContract {
    /// Creates a new [CoreContract].
    pub fn load(ws: Web3<WebSocket>) -> CoreContract {
        // Load the implementation ABI but with the proxy's address.
        //
        // Note: It's possible to support both proxy and impl ABI by
        //       combining the json of both. However, we don't really
        //       care about the proxy's ABI currently.
        let addr = H160::from_str(CORE_PROXY_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), addr, CORE_IMPL_ABI).unwrap();

        CoreContract { contract }
    }

    /// Returns the StarkNet state root at [BlockId].
    pub async fn state_root(&self, block: BlockId) -> Result<U256> {
        Ok(self
            .contract
            .query(
                "stateRoot",
                (),
                None,
                Options::default(),
                Some(block.into()),
            )
            .await?)
    }

    /// Returns the StarkNet sequence number at [BlockId].
    pub async fn sequence_number(&self, block: BlockId) -> Result<U256> {
        Ok(self
            .contract
            .query(
                "stateSequenceNumber",
                (),
                None,
                Options::default(),
                Some(block.into()),
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use web3::{contract::Options, types::Address, Web3};

    use super::*;

    async fn test_web_socket() -> Web3<WebSocket> {
        let url = std::env::var("STARTNET_ETHEREUM_WEBSOCKET_URL").expect(
            "Ethereum websocket URL environment var not set (STARTNET_ETHEREUM_WEBSOCKET_URL)",
        );
        let ws = WebSocket::new(&url).await.unwrap();
        web3::Web3::new(ws)
    }

    /// The StarkNet core contract uses the proxy pattern. This test checks that the
    /// implementation address is still the same. If it isn't, then we may need to
    /// update our [CORE_IMPL_ABI].
    #[tokio::test]
    async fn proxy_impl_addr() {
        let ws = test_web_socket().await;

        let addr = H160::from_str(CORE_PROXY_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), addr, CORE_PROXY_ABI).unwrap();

        let resp: Address = contract
            .query(
                "implementation",
                (),
                None,
                Options::default(),
                Some(BlockId::Latest.into()),
            )
            .await
            .unwrap();

        let impl_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

        assert_eq!(dbg!(resp), impl_addr);
    }

    #[tokio::test]
    async fn sequence_number() {
        let block = BlockId::Number(5812351);
        let expected = U256::from(10712);

        let ws = test_web_socket().await;
        let contract = CoreContract::load(ws);

        let sequence_number = contract.sequence_number(block).await.unwrap();

        assert_eq!(sequence_number, expected);
    }

    #[tokio::test]
    async fn state_root() {
        let block = BlockId::Number(5812351);
        let expected = U256::from_dec_str(
            "1724604860892884760768923826804298080954001104771551712720979626020277290307",
        )
        .unwrap();

        let ws = test_web_socket().await;
        let contract = CoreContract::load(ws);

        let state_root = contract.state_root(block).await.unwrap();

        assert_eq!(state_root, expected);
    }
}
