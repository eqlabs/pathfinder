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

/// List of semi-official Ethereum RPC errors taken from [EIP-1474] (which is stagnant).
///
/// The issue of standardizing the Ethereum RPC seems to now be taking
/// place here: <https://github.com/eea-oasis/eth1.x-JSON-RPC-API-standard/issues>.
///
/// [EIP-1474]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1474.md#error-codes
#[derive(Debug, Clone, Copy, PartialEq)]
enum RpcErrorCode {
    _ParseError,
    _InvalidRequest,
    _MethodNotFound,
    InvalidParams,
    _InternalError,
    InvalidInput,
    _ResourceNotFound,
    _ResourceUnavailable,
    _TransactionRejected,
    _MethodNotSupported,
    LimitExceeded,
    _JsonRpcVersion,
}

impl RpcErrorCode {
    fn code(&self) -> i64 {
        match self {
            RpcErrorCode::_ParseError => -32700,
            RpcErrorCode::_InvalidRequest => -32600,
            RpcErrorCode::_MethodNotFound => -32601,
            RpcErrorCode::InvalidParams => -32602,
            RpcErrorCode::_InternalError => -32603,
            RpcErrorCode::InvalidInput => -32000,
            RpcErrorCode::_ResourceNotFound => -32001,
            RpcErrorCode::_ResourceUnavailable => -32002,
            RpcErrorCode::_TransactionRejected => -32003,
            RpcErrorCode::_MethodNotSupported => -32004,
            RpcErrorCode::LimitExceeded => -32005,
            RpcErrorCode::_JsonRpcVersion => -32006,
        }
    }

    fn _reason(&self) -> &str {
        match self {
            RpcErrorCode::_ParseError => "Invalid JSON",
            RpcErrorCode::_InvalidRequest => "JSON is not a valid request object",
            RpcErrorCode::_MethodNotFound => "Method does not exist",
            RpcErrorCode::InvalidParams => "Invalid method parameters",
            RpcErrorCode::_InternalError => "Internal JSON-RPC error",
            RpcErrorCode::InvalidInput => "Missing or invalid parameters",
            RpcErrorCode::_ResourceNotFound => "Requested resource not found",
            RpcErrorCode::_ResourceUnavailable => "Requested resource not available",
            RpcErrorCode::_TransactionRejected => "Transaction creation failed",
            RpcErrorCode::_MethodNotSupported => "Method is not implemented",
            RpcErrorCode::LimitExceeded => "Request exceeds defined limit",
            RpcErrorCode::_JsonRpcVersion => "Version of JSON-RPC protocol is not supported",
        }
    }
}

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
