use std::convert::TryFrom;

use anyhow::Context;
use web3::types::{BlockNumber, H256};
pub mod contract;

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
    use web3::transports::WebSocket;
    use web3::Web3;
    /// A test helper utility.
    pub async fn create_test_websocket() -> Web3<WebSocket> {
        let url = std::env::var("STARKNET_ETHEREUM_WEBSOCKET_URL").expect(
            "Ethereum websocket URL environment var not set (STARKNET_ETHEREUM_WEBSOCKET_URL)",
        );

        let ws = WebSocket::new(&url).await.unwrap();
        web3::Web3::new(ws)
    }
}
