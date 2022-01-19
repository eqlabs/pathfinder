use std::str::FromStr;

use web3::ethabi::{Contract, Event, Function};
use web3::types::H160;

/// The address of Starknet's core contract (proxy).
const CORE_PROXY_ADDR: &str = "0xde29d060D45901Fb19ED6C6e959EB22d8626708e";
/// The address of Starknet's general purpose solver contract.
const GPS_ADDR: &str = "0x5EF3C980Bf970FcE5BbC217835743ea9f0388f4F";
/// The address of Starknet's memory page contract.
const MEMPAGE_ADDR: &str = "0x743789ff2fF82Bfb907009C9911a7dA636D34FA7";

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
    pub static ref CORE_CONTRACT_ADDRESS: H160 = H160::from_str(CORE_PROXY_ADDR).expect("Core contract address failed to parse");
    pub static ref GPS_CONTRACT_ADDRESS: H160 = H160::from_str(GPS_ADDR).expect("GPS contract address failed to parse");
    pub static ref MEMPAGE_CONTRACT_ADDRESS: H160 = H160::from_str(MEMPAGE_ADDR).expect("Mempage contract address failed to parse");

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
    use crate::ethereum::test::create_test_websocket_transport;

    use super::*;

    mod contract {
        use web3::{
            contract::Options,
            types::{BlockId, BlockNumber},
        };

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

        #[tokio::test]
        async fn core_impl() {
            // Checks that Starknet's core proxy contract still points to the same
            // core implementation contract. If this address changes, we should
            // update the address and more importantly, the ABI.

            // The current address of Starknet's core contract implementation.
            const CORE_IMPL_ADDR: &str = "0xe267213b0749bb94c575f6170812c887330d9ce3";
            let expect_addr = H160::from_str(CORE_IMPL_ADDR).unwrap();

            // The proxy's ABI.
            const CORE_PROXY_ABI: &[u8] = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/resources/contracts/core_proxy.json"
            ));

            let transport = create_test_websocket_transport().await;

            let core_proxy = web3::contract::Contract::from_json(
                transport.eth(),
                *CORE_CONTRACT_ADDRESS,
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

            pretty_assertions::assert_eq!(impl_addr, expect_addr);
        }
    }

    mod address {
        use super::*;

        #[test]
        fn core() {
            let _addr = *CORE_CONTRACT_ADDRESS;
        }

        #[test]
        fn gps() {
            let _addr = *GPS_CONTRACT_ADDRESS;
        }

        #[test]
        fn memory_page() {
            let _addr = *MEMPAGE_CONTRACT_ADDRESS;
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
