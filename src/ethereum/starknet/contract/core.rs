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

use web3::{transports::WebSocket, types::H160, Web3};

/// The address of the core StarkNet contract (proxy).
const CORE_PROXY_ADDR: &str = "0xde29d060D45901Fb19ED6C6e959EB22d8626708e";
/// The address of the core contract implementation.
const CORE_IMPL_ADDR: &str = "0xF10EfCF03796D38E0f6c5b87c471368e6E0DC674";

const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_proxy.json"
));

const CORE_IMPL_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_impl.json"
));

pub struct CoreContract {
    pub address: H160,
}

impl CoreContract {
    /// Creates a new [CoreContract].
    pub fn load(ws: Web3<WebSocket>) -> CoreContract {
        // Load the implementation ABI but with the proxy's address.
        //
        // Note: It's possible to support both proxy and impl ABI by
        //       combining the json of both. However, we don't really
        //       care about the proxy's ABI currently.
        let address = H160::from_str(CORE_PROXY_ADDR).unwrap();

        CoreContract { address }
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum::{test::create_test_websocket_transport, BlockId};
    use web3::{
        contract::{Contract, Options},
        types::Address,
    };

    use super::*;

    /// The StarkNet core contract uses the proxy pattern. This test checks that the
    /// implementation address is still the same. If it isn't, then we may need to
    /// update our [CORE_IMPL_ABI].
    #[tokio::test]
    async fn proxy_impl_addr() {
        let ws = create_test_websocket_transport().await;

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
}
