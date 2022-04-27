// use std::str::FromStr;

use web3::ethabi::{Contract, Event, Function};
use web3::types::H160;

use crate::ethereum::Chain;

/// Groups the Starknet contract addresses for a specific chain.
pub struct ContractAddresses {
    pub core: H160,
    pub gps: H160,
    pub mempage: H160,
}

/// Starknet contract addresses on L1 Mainnet.
const MAINNET_ADDRESSES: ContractAddresses = ContractAddresses {
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

/// Starknet contract addresses on L1 Goerli.
const GOERLI_ADDRESSES: ContractAddresses = ContractAddresses {
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

/// Returns the Starknet contract addresses for the given L1 chain.
pub fn addresses(chain: Chain) -> ContractAddresses {
    match chain {
        Chain::Mainnet => MAINNET_ADDRESSES,
        Chain::Goerli => GOERLI_ADDRESSES,
    }
}

const CORE_IMPL_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/core_impl.json"
));

const GPS_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/gps_statement_verifier.json"
));

const MEMPAGE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/memory_page_fact_registry.json"
));

lazy_static::lazy_static!(
    pub static ref STATE_UPDATE_EVENT: Event = core_contract().event("LogStateUpdate")
            .expect("LogStateUpdate event not found in core contract ABI").to_owned();
    pub static ref STATE_TRANSITION_FACT_EVENT: Event = core_contract().event("LogStateTransitionFact")
            .expect("LogStateTransitionFact event not found in core contract ABI").to_owned();
    pub static ref MEMORY_PAGE_HASHES_EVENT: Event = gps_contract().event("LogMemoryPagesHashes")
            .expect("LogMemoryPagesHashes event not found in GPS contract ABI").to_owned();
    pub static ref MEMORY_PAGE_FACT_CONTINUOUS_EVENT: Event = mempage_contract().event("LogMemoryPageFactContinuous")
            .expect("LogMemoryPageFactContinuous event not found in Memory Page Fact Registry contract ABI").to_owned();

    pub static ref REGISTER_MEMORY_PAGE_FUNCTION: Function = mempage_contract().function("registerContinuousMemoryPage")
            .expect("registerContinuousMemoryPage function not found in Memory Page Fact Registry contract ABI").to_owned();
);

fn core_contract() -> Contract {
    Contract::load(CORE_IMPL_ABI).expect("Core contract ABI is invalid")
}

fn gps_contract() -> Contract {
    Contract::load(GPS_ABI).expect("GPS contract ABI is invalid")
}

fn mempage_contract() -> Contract {
    Contract::load(MEMPAGE_ABI).expect("Mempage contract ABI is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    mod contract {
        use web3::{
            contract::Options,
            types::{BlockId, BlockNumber},
        };

        use crate::ethereum::{test_transport, Chain};

        use super::*;

        #[test]
        fn core() {
            let _contract = core_contract();
        }

        #[test]
        fn gps() {
            let _contract = gps_contract();
        }

        #[test]
        fn mempage() {
            let _contract = mempage_contract();
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
            async fn goerli() {
                // Checks that Starknet's core proxy contract still points to the same
                // core implementation contract. If this address changes, we should
                // update the address and more importantly, the ABI.

                // The current address of Starknet's core contract implementation.
                const CORE_IMPL_ADDR: &str = "0xced89ecc622d1e1b4b5151415e862ffbb17f159c";
                let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

                // The proxy's ABI.
                const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/resources/contracts/core_proxy.json"
                ));

                let transport = test_transport(Chain::Goerli);

                let core_proxy = web3::contract::Contract::from_json(
                    transport.0.eth(),
                    GOERLI_ADDRESSES.core,
                    CORE_PROXY_ABI,
                )
                .unwrap();

                let impl_addr: H160 = core_proxy
                    .query(
                        "implementation",
                        (),
                        None,
                        Options::default(),
                        Some(BlockId::Number(BlockNumber::Latest)),
                    )
                    .await
                    .unwrap();

                assert_eq!(impl_addr, expect_addr);
            }

            #[tokio::test]
            async fn mainnet() {
                // Checks that Starknet's core proxy contract still points to the same
                // core implementation contract. If this address changes, we should
                // update the address and more importantly, the ABI.

                // The current address of Starknet's core contract implementation.
                const CORE_IMPL_ADDR: &str = "0xdc109c4a1a3084ed15a97692fbef3e1fb32a6955";
                let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

                // The proxy's ABI.
                const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/resources/contracts/core_proxy.json"
                ));

                let transport = test_transport(Chain::Mainnet);

                let core_proxy = web3::contract::Contract::from_json(
                    transport.0.eth(),
                    MAINNET_ADDRESSES.core,
                    CORE_PROXY_ABI,
                )
                .unwrap();

                let impl_addr: H160 = core_proxy
                    .query(
                        "implementation",
                        (),
                        None,
                        Options::default(),
                        Some(BlockId::Number(BlockNumber::Latest)),
                    )
                    .await
                    .unwrap();

                assert_eq!(impl_addr, expect_addr);
            }
        }
    }

    mod address {
        use super::*;

        mod goerli {
            use super::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn core() {
                let expect = H160::from_str("0xde29d060D45901Fb19ED6C6e959EB22d8626708e").unwrap();
                assert_eq!(GOERLI_ADDRESSES.core, expect);
            }

            #[test]
            fn gps() {
                let expect = H160::from_str("0x5EF3C980Bf970FcE5BbC217835743ea9f0388f4F").unwrap();
                assert_eq!(GOERLI_ADDRESSES.gps, expect);
            }

            #[test]
            fn mempage() {
                let expect = H160::from_str("0x743789ff2fF82Bfb907009C9911a7dA636D34FA7").unwrap();
                assert_eq!(GOERLI_ADDRESSES.mempage, expect);
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
    }

    mod event {
        use super::*;

        #[test]
        fn state_update() {
            let _event = STATE_UPDATE_EVENT.clone();
        }

        #[test]
        fn state_transition_fact() {
            let _event = STATE_TRANSITION_FACT_EVENT.clone();
        }

        #[test]
        fn memory_page_hashes() {
            let _event = MEMORY_PAGE_HASHES_EVENT.clone();
        }

        #[test]
        fn memory_page_fact() {
            let _event = MEMORY_PAGE_FACT_CONTINUOUS_EVENT.clone();
        }
    }
}
