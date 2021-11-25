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
    contract::{tokens::Tokenizable, Contract},
    transports::WebSocket,
    types::{H160, H256, U256},
    Web3,
};

use anyhow::{Context, Result};

use crate::ethereum::{get_log_param, starknet::StarknetEvent};

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
    pub state_transition_event: StarknetEvent<StateTransitionFactLog>,
    pub state_update_event: StarknetEvent<StateUpdateLog>,
}

/// Log emitted identifying the [FactLog](super::FactLog) which led to the
/// state transition.
///
/// This log will always be emitted before [StateUpdateLog] (and in the same
/// transaction).
#[derive(Debug)]
pub struct StateTransitionFactLog {
    pub fact_hash: H256,
}

/// Log emitted when the L1 Starknet state has been updated. Specifies the
/// new global root and sequence number.
///
/// This log will always be emitted together with [StateTransitionFactLog],
/// in the same transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct StateUpdateLog {
    pub global_root: U256,
    pub sequence_number: U256,
}

impl TryFrom<web3::ethabi::Log> for StateTransitionFactLog {
    type Error = anyhow::Error;

    fn try_from(log: web3::ethabi::Log) -> Result<Self, Self::Error> {
        let fact_hash = H256::from_token(get_log_param(&log, "stateTransitionFact")?.value)
            .context("fact hash could not be parsed")?;

        Ok(Self { fact_hash })
    }
}

impl TryFrom<web3::ethabi::Log> for StateUpdateLog {
    type Error = anyhow::Error;

    fn try_from(log: web3::ethabi::Log) -> Result<Self, Self::Error> {
        let global_root = get_log_param(&log, "globalRoot")?
            .value
            .into_uint()
            .context("global root could not be parsed")?;

        let sequence_number = get_log_param(&log, "sequenceNumber")?
            .value
            .into_int()
            .context("sequence number could not be parsed")?;

        Ok(Self {
            global_root,
            sequence_number,
        })
    }
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
        let contract = Contract::from_json(ws.eth(), address, CORE_IMPL_ABI).unwrap();

        let state_transition_event = contract
            .abi()
            .event("LogStateTransitionFact")
            .unwrap()
            .clone();

        let state_update_event = contract.abi().event("LogStateUpdate").unwrap().clone();

        CoreContract {
            address,
            state_transition_event: StarknetEvent::new(state_transition_event),
            state_update_event: StarknetEvent::new(state_update_event),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum::{
        test::{create_test_websocket_transport, retrieve_log, StarknetTransaction},
        BlockId, EthOrigin,
    };
    use web3::{contract::Options, types::Address};

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

    // An Ethereum transaction containing both [StateUpdateLog] and [StateTransitionFactLog]
    // (since these are emitted as pairs).
    fn log_test_tx() -> EthOrigin {
        EthOrigin {
            block_hash: H256::from_str(
                "0x4fb0ff4e87c763447ac11c7d263081292057e09bdcc7400a5badb5539eafa130",
            )
            .unwrap(),
            block_number: 5859227,
            transaction_hash: H256::from_str(
                "0x6fca7b2f652bcb5ce56dd582fa1a77c6b653277ef7f6ae3127afa836c69275d1",
            )
            .unwrap(),
            transaction_index: 1,
        }
    }

    #[tokio::test]
    async fn parse_state_update_log() {
        let ws = create_test_websocket_transport().await;
        let contract = CoreContract::load(ws.clone());

        let test_tx = StarknetTransaction {
            origin: log_test_tx(),
            log_index: 1,
        };

        let log = retrieve_log(&test_tx).await;

        let signature = *log.topics.first().unwrap();
        assert_eq!(contract.state_update_event.signature(), signature);

        let state_update_log = contract.state_update_event.parse_log(&log).unwrap();
        assert_eq!(state_update_log.origin, test_tx.origin);
    }

    #[tokio::test]
    async fn parse_state_transition_log() {
        let ws = create_test_websocket_transport().await;
        let contract = CoreContract::load(ws.clone());

        let test_tx = StarknetTransaction {
            origin: log_test_tx(),
            log_index: 0,
        };

        let log = retrieve_log(&test_tx).await;

        let signature = *log.topics.first().unwrap();
        assert_eq!(contract.state_transition_event.signature(), signature);

        let state_transition_log = contract.state_transition_event.parse_log(&log).unwrap();
        assert_eq!(state_transition_log.origin, test_tx.origin);
    }
}
