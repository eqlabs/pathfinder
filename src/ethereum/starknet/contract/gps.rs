//! Contains abstractions around StarkNet's Generic Proof Service Ethereum contract.
//!
//! This includes the Fact log events emitted by the contract.
use std::{convert::TryFrom, str::FromStr};

use anyhow::{Context, Result};
use web3::{
    contract::{tokens::Tokenizable, Contract},
    ethabi::{Event, RawLog},
    transports::WebSocket,
    types::{H160, H256},
    Web3,
};

use crate::ethereum::{get_log_param, EthOrigin};

const GPS_ADDR: &str = "0xB02D49C4d89f0CeA504C4C93934E7fC66e20A257";
const GPS_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/gps_statement_verifier.json"
));

/// Abstraction for StarkNet's Generic Proof Service contract. It can
/// be used to identify and parse generic Ethereum logs into
///  [FactLogs](FactLog) using its [FactEvent].
pub struct GpsContract {
    pub address: H160,
    pub fact_event: StarknetEvent<FactLog>,
}

/// A StarkNet Ethereum log containing a Fact.
///
/// Contains a list of memory pages which can be
/// parsed to reveal the state updates provided
/// by this [FactLog].
#[derive(Debug, Clone, PartialEq)]
pub struct FactLog {
    pub origin: EthOrigin,
    pub hash: H256,
    pub mempage_hashes: Vec<H256>,
}

impl GpsContract {
    /// Creates a new [GpsContract].
    pub fn load(ws: Web3<WebSocket>) -> GpsContract {
        let address = H160::from_str(GPS_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), address, GPS_ABI).unwrap();
        let event = contract
            .abi()
            .event("LogMemoryPagesHashes")
            .unwrap()
            .clone();

        GpsContract {
            address,
        }
    }
}

impl FactEvent {
    /// The [FactEvent's](FactEvent) signature. Can be used
    /// to identify an Ethereum log by comparing to its first topic.
    pub fn signature(&self) -> H256 {
        self.event.signature()
    }

    /// Parses an Ethereum log into a [FactLog].
    pub fn parse_log(&self, log: &web3::types::Log) -> Result<FactLog> {
        let origin = EthOrigin::try_from(log)?;

        let log = RawLog {
            topics: log.topics.clone(),
            data: log.data.0.clone(),
        };

        let log = self.event.parse_log(log)?;

        let hash = get_log_param(&log, "factHash")
            .map(|param| H256::from_token(param.value))
            .context("fact hash could not be cast to hash")??;

        let mempage_hashes = get_log_param(&log, "pagesHashes")?;
        let mempage_hashes = mempage_hashes
            .value
            .into_array()
            .context("page hashes could not be cast to array")?
            .iter()
            .map(|token| H256::from_token(token.clone()))
            .collect::<Result<Vec<_>, _>>()
            .context("page hash could not be parsed")?;

        Ok(FactLog {
            origin,
            mempage_hashes,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ethereum::test::{create_test_websocket_transport, fact_test_tx, retrieve_log};

    use super::*;

    #[tokio::test]
    async fn load() {
        let ws = create_test_websocket_transport().await;
        GpsContract::load(ws);
    }

    #[tokio::test]
    async fn address() {
        let ws = create_test_websocket_transport().await;
        let address = GpsContract::load(ws).address;
        let expected = H160::from_str(GPS_ADDR).unwrap();

        assert_eq!(address, expected);
    }

    #[tokio::test]
    async fn parse_log() {
        let ws = create_test_websocket_transport().await;
        let contract = GpsContract::load(ws.clone());

        let fact_tx = fact_test_tx();
        let log = retrieve_log(&fact_tx).await;

        let signature = *log.topics.first().unwrap();
        assert_eq!(contract.fact_event.signature(), signature);

        let fact_log = contract.fact_event.parse_log(&log).unwrap();
        assert_eq!(fact_log.origin, fact_tx.origin);
    }
}
