use ethers::abi::{Contract, Event};
use ethers::providers::Middleware;
use ethers::types::H160;
use pathfinder_common::{GlobalRoot, StarknetBlockNumber};


/// Groups the Starknet contract addresses for a specific chain.
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
    pub mempage: H160,
}

/// Starknet contract addresses on L1 Mainnet.
pub const MAINNET_ADDRESSES: ContractAddresses = ContractAddresses {
    // `core` and `gps` addresses can be fetched from https://alpha-mainnet.starknet.io/feeder_gateway/get_contract_addresses
    core: H160([
        198, 98, 196, 16, 192, 236, 247, 71, 84, 63, 91, 169, 6, 96, 246, 171, 235, 217, 200, 196,
    ]),
    gps: H160([
        71, 49, 36, 80, 179, 172, 139, 91, 142, 36, 122, 107, 182, 213, 35, 231, 96, 91, 219, 96,
    ]),
    mempage: H160([
        198, 98, 196, 16, 192, 236, 247, 71, 84, 63, 91, 169, 6, 96, 246, 171, 235, 217, 200, 196,
    ]),
};

/// Starknet contract addresses on L1 Goerli for testnet.
pub const TESTNET_ADDRESSES: ContractAddresses = ContractAddresses {
    core: H160([
        222, 41, 208, 96, 212, 89, 1, 251, 25, 237, 108, 110, 149, 158, 178, 45, 134, 38, 112, 142,
    ]),
    gps: H160([
        94, 243, 201, 128, 191, 151, 15, 206, 91, 188, 33, 120, 53, 116, 62, 169, 240, 56, 143, 79,
    ]),
    mempage: H160([
        116, 55, 137, 255, 47, 248, 43, 251, 144, 112, 9, 201, 145, 26, 125, 166, 54, 211, 79, 167,
    ]),
};

/// Starknet contract addresses on L1 Goerli for testnet 2.
pub const TESTNET2_ADDRESSES: ContractAddresses = ContractAddresses {
    core: H160([
        0xa4, 0xed, 0x3a, 0xd2, 0x7c, 0x29, 0x45, 0x65, 0xcb, 0x0d, 0xcc, 0x99, 0x3b, 0xdd, 0xcc,
        0x75, 0x43, 0x2d, 0x49, 0x8c,
    ]),
    gps: H160([
        171, 67, 186, 72, 201, 237, 244, 194, 196, 187, 1, 35, 115, 72, 209, 215, 178, 142, 241,
        104,
    ]),
    // FIXME: This was copied from testnet addresses as this info is not available from the gateway.
    //        Currently not important as it is not used.
    mempage: TESTNET_ADDRESSES.mempage,
};

/// Starknet contract addresses on L1 Goerli for integration.
pub const INTEGRATION_ADDRESSES: ContractAddresses = ContractAddresses {
    core: H160([
        213, 195, 37, 209, 131, 197, 146, 201, 73, 152, 0, 12, 94, 14, 237, 158, 102, 85, 192, 32,
    ]),
    gps: H160([
        171, 67, 186, 72, 201, 237, 244, 194, 196, 187, 1, 35, 115, 72, 209, 215, 178, 142, 241,
        104,
    ]),
    // FIXME: This was copied from testnet addresses as this info is not available from the gateway.
    //        Currently not important as it is not used.
    mempage: TESTNET_ADDRESSES.mempage,
};

const CORE_IMPL_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_impl.json"
));

lazy_static::lazy_static!(
    pub static ref STATE_UPDATE_EVENT: Event = core_contract().event("LogStateUpdate")
            .expect("LogStateUpdate event not found in core contract ABI").to_owned();
);

fn core_contract() -> Contract {
    Contract::load(CORE_IMPL_ABI).expect("Core contract ABI is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    mod contract {
        use ethers::{
            // contract::Options,
            types::{BlockId, BlockNumber},
        };

        use crate::transport::HttpTransport;
        use pathfinder_common::Chain;

        use super::*;

        #[test]
        fn core() {
            let _contract = core_contract();
        }

        mod core_impl {
            use super::*;
            use pretty_assertions::assert_eq;

            // The L1 Starknet contracts often use a proxy pattern. This is common for
            // Ethereum contracts. The main entry-point contract is a proxy which has
            // a few built-in functions to handle things like changing the backing
            // implementation, or making it immutable. Every function call that is
            // not one of these proxy-management functions is then delegated to the
            // actual backing implementation contract.
            //
            // The advantage of this is that one gets to update / tweak the
            // implementation without changing the "entry-point" contract address.
            //
            // For us this is therefore fully opaque -- we shouldn't really care about
            // this changing -- except we care about the implementation ABI: we read
            // some of the logs.
            // These tests ensure we know when its changed, and we can check if the
            // ABI was updated.

            #[tokio::test]
            async fn testnet() {
                // Checks that Starknet's core proxy contract still points to the same
                // core implementation contract. If this address changes, we should
                // update the address and more importantly, the ABI.
                //
                // ** Updating the ABI **
                // The new ABI can be retrieved from etherscan by visiting the new contract's
                // address and navigating to the `Contract -> Code` tab. Scrolling down will then
                // show the contract's ABI. e.g.
                //  https://goerli.etherscan.io/address/0x70c8a579ad08339cca19d77d8646f4b6f0fd098a#code
                //
                // The ABI diff should be inspected for any changes that impact us -- currently restricted to
                // log changes as read these. In particular, any of the `XXX_EVENT` consts.

                // The current address of Starknet's core contract implementation.
                // const CORE_IMPL_ADDR: &str = "0x70c8a579ad08339cca19d77d8646f4b6f0fd098a";
                // let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

                // // The proxy's ABI.
                // const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                //     env!("CARGO_MANIFEST_DIR"),
                //     "/resources/contracts/core_proxy.json"
                // ));

                // let transport = HttpTransport::test_transport(Chain::Testnet);

                // let core_proxy = ethers::contract::Contract::from_json(
                //     transport.eth(),
                //     TESTNET_ADDRESSES.core,
                //     CORE_PROXY_ABI,
                // )
                // .unwrap();

                // let impl_addr: H160 = core_proxy
                //     .query(
                //         "implementation",
                //         (),
                //         None,
                //         Options::default(),
                //         Some(BlockId::Number(BlockNumber::Latest)),
                //     )
                //     .await
                //     .unwrap();

                // assert_eq!(impl_addr, expect_addr);
                todo!("FIXME");
            }

            #[tokio::test]
            async fn mainnet() {
                // Checks that Starknet's core proxy contract still points to the same
                // core implementation contract. If this address changes, we should
                // update the address and more importantly, the ABI.

                // The current address of Starknet's core contract implementation.
                // const CORE_IMPL_ADDR: &str = "0xe267213b0749bb94c575f6170812c887330d9ce3";
                // let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

                // // The proxy's ABI.
                // const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                //     env!("CARGO_MANIFEST_DIR"),
                //     "/resources/contracts/core_proxy.json"
                // ));

                // let transport = HttpTransport::test_transport(Chain::Mainnet);

                // let core_proxy = ethers::contract::Contract::from_json(
                //     transport.eth(),
                //     MAINNET_ADDRESSES.core,
                //     CORE_PROXY_ABI,
                // )
                // .unwrap();

                // let impl_addr: H160 = core_proxy
                //     .query(
                //         "implementation",
                //         (),
                //         None,
                //         Options::default(),
                //         Some(BlockId::Number(BlockNumber::Latest)),
                //     )
                //     .await
                //     .unwrap();

                // assert_eq!(impl_addr, expect_addr);
                todo!("FIXME");
            }

            #[tokio::test]
            async fn integration() {
                // Checks that Starknet's core proxy contract still points to the same
                // core implementation contract. If this address changes, we should
                // update the address and more importantly, the ABI once it reaches testnet.

                // The current address of Starknet's core contract implementation.
                // const CORE_IMPL_ADDR: &str = "0x70c8a579ad08339cca19d77d8646f4b6f0fd098a";
                // let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

                // // The proxy's ABI.
                // const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                //     env!("CARGO_MANIFEST_DIR"),
                //     "/resources/contracts/core_proxy.json"
                // ));

                // let transport = HttpTransport::test_transport(Chain::Integration);

                // let core_proxy = ethers::contract::Contract::from_json(
                //     transport.eth(),
                //     INTEGRATION_ADDRESSES.core,
                //     CORE_PROXY_ABI,
                // )
                // .unwrap();

                // let impl_addr: H160 = core_proxy
                //     .query(
                //         "implementation",
                //         (),
                //         None,
                //         Options::default(),
                //         Some(BlockId::Number(BlockNumber::Latest)),
                //     )
                //     .await
                //     .unwrap();

                // assert_eq!(impl_addr, expect_addr);
                todo!("FIXME");
            }
        }
    }

    mod address {
        use super::*;

        mod testnet {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn core() {
                let expect = H160::from_str("0xde29d060D45901Fb19ED6C6e959EB22d8626708e").unwrap();
                assert_eq!(TESTNET_ADDRESSES.core, expect);
            }

            #[test]
            fn gps() {
                let expect = H160::from_str("0x5EF3C980Bf970FcE5BbC217835743ea9f0388f4F").unwrap();
                assert_eq!(TESTNET_ADDRESSES.gps, expect);
            }

            #[test]
            fn mempage() {
                let expect = H160::from_str("0x743789ff2fF82Bfb907009C9911a7dA636D34FA7").unwrap();
                assert_eq!(TESTNET_ADDRESSES.mempage, expect);
            }
        }

        mod mainnet {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn core() {
                let expect = H160::from_str("0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4").unwrap();
                assert_eq!(MAINNET_ADDRESSES.core, expect);
            }

            #[test]
            fn gps() {
                let expect = H160::from_str("0x47312450B3Ac8b5b8e247a6bB6d523e7605bDb60").unwrap();
                assert_eq!(MAINNET_ADDRESSES.gps, expect);
            }

            #[test]
            fn mempage() {
                let expect = H160::from_str("0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4").unwrap();
                assert_eq!(MAINNET_ADDRESSES.mempage, expect);
            }
        }

        mod integration {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn core() {
                let expect = H160::from_str("0xd5c325D183C592C94998000C5e0EED9e6655c020").unwrap();
                assert_eq!(INTEGRATION_ADDRESSES.core, expect);
            }

            #[test]
            fn gps() {
                let expect = H160::from_str("0xAB43bA48c9edF4C2C4bB01237348D1D7B28ef168").unwrap();
                assert_eq!(INTEGRATION_ADDRESSES.gps, expect);
            }

            #[test]
            fn mempage() {
                let expect = H160::from_str("0x743789ff2fF82Bfb907009C9911a7dA636D34FA7").unwrap();
                assert_eq!(INTEGRATION_ADDRESSES.mempage, expect);
            }
        }
    }

    mod event {
        use super::*;

        #[test]
        fn state_update() {
            let _event = STATE_UPDATE_EVENT.clone();
        }
    }
}
