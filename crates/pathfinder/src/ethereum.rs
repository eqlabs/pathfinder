use std::convert::TryFrom;

use anyhow::{Context, Result};

use crate::core::{
    EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
    EthereumTransactionIndex,
};
pub mod contract;
pub mod log;
pub mod state_update;

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
        let number = log.block_number.context("missing block hash")?.as_u64();
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

#[cfg(test)]
mod test {
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
}
