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

use crate::ethereum::{contract::get_log_param, EthOrigin};

const GPS_ADDR: &str = "0xB02D49C4d89f0CeA504C4C93934E7fC66e20A257";
const GPS_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/gps_statement_verifier.json"
));

/// Abstraction for StarkNet's Generic Proof Service contract. It can
/// be used to identify and parse generic Ethereum logs into
///  [FactLogs](FactLog) using its [FactEvent].
pub struct GpsContract {
    contract: Contract<WebSocket>,
    pub fact_event: FactEvent,
}

/// Parses StarkNet [FactLogs](FactLog) emitted by [GpsContract].
pub struct FactEvent {
    event: Event,
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
        let addr = H160::from_str(GPS_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), addr, GPS_ABI).unwrap();
        let event = contract
            .abi()
            .event("LogMemoryPagesHashes")
            .unwrap()
            .clone();

        GpsContract {
            contract,
            fact_event: FactEvent { event },
        }
    }

    /// The [GpsContract's](GpsContract) address.
    pub fn address(&self) -> H160 {
        self.contract.address()
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
    use crate::ethereum::test::create_test_websocket_transport;

    use super::*;

    #[tokio::test]
    async fn load() {
        let ws = create_test_websocket_transport().await;
        GpsContract::load(ws);
    }

    #[tokio::test]
    async fn address() {
        let ws = create_test_websocket_transport().await;
        let address = GpsContract::load(ws).address();
        let expected = H160::from_str(GPS_ADDR).unwrap();

        assert_eq!(address, expected);
    }

    #[tokio::test]
        let ws = create_test_websocket_transport().await;
        let contract = GpsContract::load(ws.clone());

        // Transaction with a known Fact log (the second log).
        //
        // This was identified using https://goerli.etherscan.io by checking events emitted by the GPS contract.
        let eth_origin = EthOrigin {
            block_hash: H256::from_str(
                "0x17c7105d8d2c9e0b8e6a8ce9ba845889146a69443d90850d14d809af89009b82",
            )
            .unwrap(),
            block_number: 5806884,
            transaction_hash: H256::from_str(
                "0x573354d51d28514519b8fe8604e1ef5152a608aa6bfc8fb59fe5dbb89a5a9cd1",
            )
            .unwrap(),
            transaction_index: 11,
        };
        // Get the log from Ethereum.
        let tx = ws
            .eth()
            .transaction_receipt(eth_origin.transaction_hash)
            .await
            .unwrap()
            .unwrap();
        let log = &tx.logs[1];

        let signature = *log.topics.first().unwrap();
        assert_eq!(contract.fact_event.signature(), signature);

        let fact_log = contract.fact_event.parse_log(log).unwrap();
        assert_eq!(fact_log.origin, eth_origin);
    }
}
