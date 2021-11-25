//! Contains abstractions around StarkNet's Memory Page Ethereum contract.
//!
//! This includes the Mempage log events emitted by the contract.
use std::{convert::TryFrom, str::FromStr};

use anyhow::{Context, Result};
use web3::{
    contract::Contract,
    ethabi::Function,
    transports::WebSocket,
    types::{Transaction, H160, H256, U256},
    Web3,
};

use crate::ethereum::{get_log_param, starknet::StarknetEvent};

const MEMPAGE_ADDR: &str = "0x743789ff2fF82Bfb907009C9911a7dA636D34FA7";
const MEMPAGE_ABI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/contracts/memory_page_fact_registry.json"
));

/// Abstraction for StarkNet's Memory Page contract. It can be used to
/// identify and parse generic Ethereum logs into [MempageLogs](MempageLog).
pub struct MempageContract {
    pub address: H160,
    mempage_register_function: Function,
    pub mempage_event: StarknetEvent<MempageLog>,
}

/// An Ethereum log representing a StarkNet memory page.
///
/// The actual memory page data is contained in the origin
/// transaction's input data.
#[derive(Debug)]
pub struct MempageLog {
    pub hash: H256,
}

impl TryFrom<web3::ethabi::Log> for MempageLog {
    type Error = anyhow::Error;

    fn try_from(log: web3::ethabi::Log) -> Result<Self, Self::Error> {
        let hash = get_log_param(&log, "memoryHash")?
            .value
            .into_uint()
            .context("mempage hash could not be cast to U256")?;
        let mut bytes = vec![0; 32];
        hash.to_big_endian(&mut bytes);
        let hash = H256::from_slice(&bytes);

        Ok(Self { hash })
    }
}

impl MempageContract {
    /// Creates a new [MempageContract].
    pub fn load(ws: Web3<WebSocket>) -> MempageContract {
        let address = H160::from_str(MEMPAGE_ADDR).unwrap();
        let contract = Contract::from_json(ws.eth(), address, MEMPAGE_ABI).unwrap();
        let mempage_event = contract
            .abi()
            .event("LogMemoryPageFactContinuous")
            .unwrap()
            .clone();
        let function = contract
            .abi()
            .function("registerContinuousMemoryPage")
            .unwrap()
            .clone();

        let mempage_event = StarknetEvent::new(mempage_event);

        MempageContract {
            address,
            mempage_event,
            mempage_register_function: function,
        }
    }

    pub fn decode_mempage(&self, transaction: &Transaction) -> Result<Vec<U256>> {
        // The first 4 bytes of data represent the short-signature of the function.
        // These must exist in order to be valid. We should compare the signature as
        // well, but this requires web3 to bump ethabi to v15.
        anyhow::ensure!(
            transaction.input.0.len() >= 4,
            "transaction input contained no data"
        );

        // The mempage data is stored in 'values' (2nd token), which is an array of U256.
        //
        // The complete structure is defined in the mempage json ABI.
        self.mempage_register_function
            // `decode_input` wants the raw data, excluding the short-signature.
            // The indexing is safe due to the `ensure` above.
            .decode_input(&transaction.input.0[4..])
            .context("mempage input decoding failed")?
            .get(1)
            .cloned()
            .context("missing values array field")?
            .into_array()
            .context("values field could not be cast to an array")?
            .iter()
            .map(|t| {
                t.clone()
                    .into_uint()
                    .context("values element could not be cast to U256")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use web3::types::TransactionId;

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
        let address = MempageContract::load(ws).address;
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

    #[tokio::test]
    async fn decode_mempage() {
        let ws = create_test_websocket_transport().await;
        let contract = MempageContract::load(ws.clone());

        let tx_hash = TransactionId::Hash(mempage_test_tx().origin.transaction_hash);

        let tx = ws.eth().transaction(tx_hash).await.unwrap().unwrap();
        contract.decode_mempage(&tx).unwrap();
    }
}
