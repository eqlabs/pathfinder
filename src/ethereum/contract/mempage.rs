//! Contains abstractions around StarkNet's Memory Page Ethereum contract.
//!
//! This includes the Mempage log events emitted by the contract.
use std::{convert::TryFrom, str::FromStr};

use anyhow::{Context, Result};
use web3::{
    contract::Contract,
    ethabi::{Event, RawLog},
    transports::WebSocket,
    types::{H160, H256},
    Web3,
};

use crate::ethereum::{contract::get_log_param, EthOrigin};

const MEMPAGE_ADDR: &str = "0xb609Eba1DC0298A984Fa8a34528966E997C5BB13";
const MEMPAGE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/memory_page_fact_registry.json"
));

/// Abstraction for StarkNet's Memory Page contract. It can be used to
/// identify and parse generic Ethereum logs into [MempageLogs](MempageLog)
/// using its [MempageEvent].
pub struct MempageContract {
    contract: Contract<WebSocket>,
    pub mempage_event: MempageEvent,
}

/// Parses StarkNet [MempageLogs](MempageLog) emitted by [MempageContract].
pub struct MempageEvent {
    event: Event,
}

/// An Ethereum log representing a StarkNet memory page.
///
/// The actual memory page data is contained in the origin
/// transaction's input data.
#[derive(Debug, Clone)]
pub struct MempageLog {
    pub origin: EthOrigin,
    pub hash: H256,
}

impl MempageContract {
    /// Creates a new [MempageContract].
    pub fn load(ws: Web3<WebSocket>) -> MempageContract {
        let addr = H160::from_str(MEMPAGE_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), addr, MEMPAGE_ABI).unwrap();
        let event = contract
            .abi()
            .event("LogMemoryPageFactContinuous")
            .unwrap()
            .clone();

        MempageContract {
            contract,
            mempage_event: MempageEvent { event },
        }
    }

    /// The [MempageContract's](MempageContract) address.
    pub fn address(&self) -> H160 {
        self.contract.address()
    }
}

impl MempageEvent {
    /// The [MempageEvent's](MempageEvent) signature. Can be used
    /// to identify an Ethereum log by comparing to its first topic.
    pub fn signature(&self) -> H256 {
        self.event.signature()
    }

    /// Parses an Ethereum log into a [MempageLog].
    pub fn parse_log(&self, log: &web3::types::Log) -> Result<MempageLog> {
        let origin = EthOrigin::try_from(log)?;

        let log = RawLog {
            topics: log.topics.clone(),
            data: log.data.0.clone(),
        };

        let log = self.event.parse_log(log)?;
        let hash = get_log_param(&log, "memoryHash")?
            .value
            .into_uint()
            .context("mempage hash could not be cast to uint")?;
        let mut be_bytes = vec![0u8; 32];
        hash.to_big_endian(&mut be_bytes);
        let hash = H256::from_slice(&be_bytes);

        Ok(MempageLog { hash, origin })
    }
}

#[cfg(test)]
mod tests {

    use crate::ethereum::test::{create_test_websocket_transport, mempage_test_tx, retrieve_log};

    use super::*;

    #[tokio::test]
    async fn load() {
        let ws = create_test_websocket_transport().await;
        MempageContract::load(ws);
    }

    #[tokio::test]
    async fn address() {
        let ws = create_test_websocket_transport().await;
        let address = MempageContract::load(ws).address();
        let expected = H160::from_str(MEMPAGE_ADDR).unwrap();

        assert_eq!(address, expected);
    }

    #[tokio::test]
    async fn parse_log() {
        let ws = create_test_websocket_transport().await;
        let contract = MempageContract::load(ws.clone());
        let mempage_tx = mempage_test_tx();

        let log = retrieve_log(&mempage_tx).await;

        let signature = *log.topics.first().unwrap();
        assert_eq!(contract.mempage_event.signature(), signature);

        let mempage_log = contract.mempage_event.parse_log(&log).unwrap();
        assert_eq!(mempage_log.origin, mempage_tx.origin);
    }
}
