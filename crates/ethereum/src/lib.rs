use std::convert::TryFrom;

use anyhow::{Context, Result};

use pathfinder_common::{
    EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
    EthereumTransactionIndex,
};

pub mod contract;
pub mod log;
pub mod provider;
pub mod state_update;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct BlockOrigin {
    pub hash: EthereumBlockHash,
    pub number: EthereumBlockNumber,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct TransactionOrigin {
    pub hash: EthereumTransactionHash,
    pub index: EthereumTransactionIndex,
}

/// An Ethereum origin point.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct EthOrigin {
    pub block: BlockOrigin,
    pub transaction: TransactionOrigin,
    pub log_index: EthereumLogIndex,
}

impl TryFrom<&ethers::types::Log> for BlockOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &ethers::types::Log) -> Result<Self, Self::Error> {
        let hash = log.block_hash.context("missing block hash")?;
        let hash = EthereumBlockHash(hash);
        let number = log.block_number.context("missing block number")?.as_u64();
        let number = EthereumBlockNumber(number);
        Ok(Self { hash, number })
    }
}

impl TryFrom<&ethers::types::Log> for TransactionOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &ethers::types::Log) -> Result<Self, Self::Error> {
        let hash = log.transaction_hash.context("missing transaction hash")?;
        let hash = EthereumTransactionHash(hash);
        let index = log
            .transaction_index
            .context("missing transaction index")?
            .as_u64();
        let index = EthereumTransactionIndex(index);
        Ok(Self { hash, index })
    }
}

impl TryFrom<&ethers::types::Log> for EthOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &ethers::types::Log) -> Result<Self, Self::Error> {
        let block = BlockOrigin::try_from(log)?;
        let transaction = TransactionOrigin::try_from(log)?;
        let log_index = log.log_index.context("missing log index")?.as_u64();

        Ok(EthOrigin {
            block,
            transaction,
            log_index: EthereumLogIndex(log_index),
        })
    }
}

#[cfg(test)]
mod tests {
    mod chain {
        use crate::provider::{EthereumTransport, HttpProvider};
        use pathfinder_common::{Chain, EthereumChain};

        #[tokio::test]
        async fn testnet() {
            let expected_chain = EthereumChain::Goerli;
            let transport = HttpProvider::test_provider(Chain::Testnet);
            let chain = transport.chain().await.unwrap();

            assert_eq!(chain, expected_chain);
        }

        #[tokio::test]
        async fn integration() {
            let expected_chain = EthereumChain::Goerli;
            let transport = HttpProvider::test_provider(Chain::Integration);
            let chain = transport.chain().await.unwrap();

            assert_eq!(chain, expected_chain);
        }

        #[tokio::test]
        async fn mainnet() {
            let expected_chain = EthereumChain::Mainnet;
            let transport = HttpProvider::test_provider(Chain::Mainnet);
            let chain = transport.chain().await.unwrap();

            assert_eq!(chain, expected_chain);
        }
    }
}
