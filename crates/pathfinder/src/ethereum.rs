use std::convert::TryFrom;

use anyhow::{Context, Result};
use web3::{
    types::{H256, U256},
    Transport, Web3,
};

use crate::core::{
    EthereumBlockHash, EthereumBlockNumber, EthereumTransactionHash, EthereumTransactionIndex, EthereumLogIndex,
};
pub mod contract;
pub mod log;
pub mod state_update;

/// Ethereum network chains runnings Starknet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Chain {
    /// The Ethereum mainnet chain.
    Mainnet,
    /// The Ethereum Goerli test network chain.
    Goerli,
}

/// List of semi-official Ethereum RPC errors taken from EIP-1474 (which is stagnant).
///
/// The issue of standardizing the Ethereum RPC seems to now be taking
/// place here: https://github.com/eea-oasis/eth1.x-JSON-RPC-API-standard/issues.
///
/// EIP-1474:
///     https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1474.md#error-codes
#[derive(Debug, Clone, Copy, PartialEq)]
enum RpcErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    InvalidInput,
    ResourceNotFound,
    ResourceUnavailable,
    TransactionRejected,
    MethodNotSupported,
    LimitExceeded,
    JsonRpcVersion,
}

impl RpcErrorCode {
    fn code(&self) -> i64 {
        match self {
            RpcErrorCode::ParseError => -32700,
            RpcErrorCode::InvalidRequest => -32600,
            RpcErrorCode::MethodNotFound => -32601,
            RpcErrorCode::InvalidParams => -32602,
            RpcErrorCode::InternalError => -32603,
            RpcErrorCode::InvalidInput => -32000,
            RpcErrorCode::ResourceNotFound => -32001,
            RpcErrorCode::ResourceUnavailable => -32002,
            RpcErrorCode::TransactionRejected => -32003,
            RpcErrorCode::MethodNotSupported => -32004,
            RpcErrorCode::LimitExceeded => -32005,
            RpcErrorCode::JsonRpcVersion => -32006,
        }
    }

    fn reason(&self) -> &str {
        match self {
            RpcErrorCode::ParseError => "Invalid JSON",
            RpcErrorCode::InvalidRequest => "JSON is not a valid request object",
            RpcErrorCode::MethodNotFound => "Method does not exist",
            RpcErrorCode::InvalidParams => "Invalid method parameters",
            RpcErrorCode::InternalError => "Internal JSON-RPC error",
            RpcErrorCode::InvalidInput => "Missing or invalid parameters",
            RpcErrorCode::ResourceNotFound => "Requested resource not found",
            RpcErrorCode::ResourceUnavailable => "Requested resource not available",
            RpcErrorCode::TransactionRejected => "Transaction creation failed",
            RpcErrorCode::MethodNotSupported => "Method is not implemented",
            RpcErrorCode::LimitExceeded => "Request exceeds defined limit",
            RpcErrorCode::JsonRpcVersion => "Version of JSON-RPC protocol is not supported",
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

impl TryFrom<&web3::types::Log> for BlockOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &web3::types::Log) -> Result<Self, Self::Error> {
        let hash = log.block_hash.context("missing block hash")?;
        let hash = EthereumBlockHash(hash);
        let number = log.block_number.context("missing block number")?.as_u64();
        let number = EthereumBlockNumber(number);
        Ok(Self { hash, number })
    }
}

impl TryFrom<&web3::types::Log> for TransactionOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &web3::types::Log) -> Result<Self, Self::Error> {
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

impl TryFrom<&web3::types::Log> for EthOrigin {
    type Error = anyhow::Error;

    fn try_from(log: &web3::types::Log) -> Result<Self, Self::Error> {
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

/// Identifies the Ethereum [Chain] behind the given Ethereum transport.
///
/// Will error if it's not one of the valid Starknet [Chain] variants.
pub async fn chain<T: Transport>(transport: Web3<T>) -> anyhow::Result<Chain> {
    match transport.eth().chain_id().await? {
        id if id == U256::from(1u32) => Ok(Chain::Mainnet),
        id if id == U256::from(5u32) => Ok(Chain::Goerli),
        other => anyhow::bail!("Unsupported chain ID: {}", other),
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use web3::transports::WebSocket;
    use web3::Web3;

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

    mod chain {
        use super::*;

        #[tokio::test]
        async fn goerli() {
            let transport = create_test_websocket_transport().await;

            let chain = chain(transport).await.unwrap();

            assert_eq!(chain, Chain::Goerli);
        }

        #[tokio::test]
        #[should_panic = "No way of getting mainnet test endpoint yet"]
        async fn mainnet() {
            let transport = create_test_websocket_transport().await;

            let chain = chain(transport).await.unwrap();

            assert_eq!(chain, Chain::Mainnet);
        }
    }
}
