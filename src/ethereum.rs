use std::convert::TryFrom;

use anyhow::Context;
use web3::types::{BlockNumber, H256};
pub mod contract;
pub mod starknet;

pub enum BlockId {
    Latest,
    Earliest,
    Number(u64),
    Hash(H256),
}

/// An Ethereum origin point.
#[derive(Debug, Clone, PartialEq)]
pub struct EthOrigin {
    pub block_hash: H256,
    pub block_number: u64,
    pub transaction_hash: H256,
    pub transaction_index: u64,
}

impl From<BlockId> for web3::types::BlockId {
    fn from(id: BlockId) -> Self {
        type W3 = web3::types::BlockId;
        match id {
            BlockId::Latest => W3::Number(BlockNumber::Latest),
            BlockId::Earliest => W3::Number(BlockNumber::Earliest),
            BlockId::Number(x) => W3::Number(BlockNumber::Number(x.into())),
            BlockId::Hash(x) => W3::Hash(x),
        }
    }
}

impl TryFrom<&web3::types::Log> for EthOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &web3::types::Log) -> Result<Self, Self::Error> {
        let block_hash = log.block_hash.context("missing block hash")?;
        let block_number = log.block_number.context("missing block hash")?.as_u64();
        let transaction_hash = log.transaction_hash.context("missing transaction hash")?;
        let transaction_index = log
            .transaction_index
            .context("missing transaction index")?
            .as_u64();

        Ok(EthOrigin {
            block_hash,
            block_number,
            transaction_hash,
            transaction_index,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use web3::transports::WebSocket;
    use web3::types::H256;
    use web3::Web3;

    use crate::ethereum::EthOrigin;

    /// Information about an Ethereum transaction
    /// known to contain a StarkNet log of interest.
    pub struct StarknetTransaction {
        /// Ethereum origin point
        pub origin: EthOrigin,
        /// The log index
        pub log_index: usize,
    }

    /// An Ethereum transaction known to contain a StarkNet Mempage log.
    ///
    /// This was identified using https://goerli.etherscan.io by checking events emitted by the Mempage contract.
    pub fn mempage_test_tx() -> StarknetTransaction {
        StarknetTransaction {
            origin: EthOrigin {
                block_hash: H256::from_str(
                    "0x17c7105d8d2c9e0b8e6a8ce9ba845889146a69443d90850d14d809af89009b82",
                )
                .unwrap(),
                block_number: 5806884,
                transaction_hash: H256::from_str(
                    "0x93f9609808869a6360cd734fae6cd1792fed0b79e45b2e05836f5353ab4a2ce3",
                )
                .unwrap(),
                transaction_index: 10,
            },
            log_index: 0,
        }
    }

    /// An Ethereum transaction known to contain a StarkNet Fact log.
    ///
    /// This was identified using https://goerli.etherscan.io by checking events emitted by the GPS contract.
    pub fn fact_test_tx() -> StarknetTransaction {
        StarknetTransaction {
            origin: EthOrigin {
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
            },
            log_index: 1,
        }
    }

    /// Retrieves an Ethereum log from the given transaction.
    pub async fn retrieve_log(from: &StarknetTransaction) -> web3::types::Log {
        let ws = create_test_websocket_transport().await;
        // Get the log from Ethereum.
        let tx = ws
            .eth()
            .transaction_receipt(from.origin.transaction_hash)
            .await
            .unwrap()
            .unwrap();
        tx.logs[from.log_index].clone()
    }

    /// Creates a [Web3<WebSocket>] as specified by [create_test_websocket].
    pub async fn create_test_websocket_transport() -> Web3<WebSocket> {
        web3::Web3::new(create_test_websocket().await)
    }

    /// Creates a [WebSocket] which connects to the Ethereum node specified by
    /// the `STARKNET_ETHEREUM_WEBSOCKET_URL` environment variable.
    pub async fn create_test_websocket() -> WebSocket {
        let url = std::env::var("STARKNET_ETHEREUM_WEBSOCKET_URL").expect(
            "Ethereum websocket URL environment var not set (STARKNET_ETHEREUM_WEBSOCKET_URL)",
        );

        WebSocket::new(&url).await.unwrap()
    }
}
