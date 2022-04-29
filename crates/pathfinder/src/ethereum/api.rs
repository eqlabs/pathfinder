//! Wrapper for the parts of the [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html) API that [the ethereum module](super) uses.
use crate::retry::Retry;

use std::future::Future;
use std::num::NonZeroU64;
use std::time::Duration;

use futures::TryFutureExt;
use tracing::{debug, error, info};
use web3::{
    types::{Block, BlockId, Filter, Log, Transaction, TransactionId, H256, U256},
    Error, Transport, Web3,
};

/// Error returned by [`Web3EthImpl::logs`].
#[derive(Debug, thiserror::Error)]
pub enum LogsError {
    /// Query exceeded limits (time or result length).
    #[error("Query limit exceeded.")]
    QueryLimit,
    /// One of the blocks specified in the filter is unknown. Currently only
    /// known to occur for Alchemy endpoints.
    #[error("Unknown block.")]
    UnknownBlock,
    #[error(transparent)]
    Other(#[from] web3::Error),
}

/// Contains only those functions from [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// that [the ethereum module](super) uses.
#[async_trait::async_trait]
pub trait Web3EthApi {
    async fn block(&self, block: BlockId) -> web3::Result<Option<Block<H256>>>;
    async fn block_number(&self) -> web3::Result<u64>;
    async fn chain_id(&self) -> web3::Result<U256>;
    async fn logs(&self, filter: Filter) -> std::result::Result<Vec<Log>, LogsError>;
    async fn transaction(&self, id: TransactionId) -> web3::Result<Option<Transaction>>;
}

/// An implementation of [`Web3EthApi`] which uses [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// wrapped in an [exponential backoff retry utility](Retry).
///
/// Initial backoff time is 30 seconds and saturates at 1 hour:
///
/// `backoff [secs] = min((2 ^ N) * 15, 3600) [secs]`
///
/// where `N` is the consecutive retry iteration number `{1, 2, ...}`.
#[derive(Clone, Debug)]
pub struct Web3EthImpl<T>(pub Web3<T>)
where
    T: Transport + Send + Sync,
    T::Out: Send;

#[async_trait::async_trait]
impl<T: Transport> Web3EthApi for Web3EthImpl<T>
where
    T: Transport + Send + Sync,
    T::Out: Send,
{
    /// Wraps [`Web3::eth().block()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.block)
    /// into exponential retry on __all__ errors.
    async fn block(&self, block: BlockId) -> web3::Result<Option<Block<H256>>> {
        retry(|| self.0.eth().block(block), log_and_always_retry).await
    }

    /// Wraps [`Web3::eth().block_number()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.block_number)
    /// into exponential retry on __all__ errors.
    async fn block_number(&self) -> web3::Result<u64> {
        retry(|| self.0.eth().block_number(), log_and_always_retry)
            .await
            .map(|n| n.as_u64())
    }

    /// Wraps [`Web3::chain_id()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.chain_id)
    /// into exponential retry on __all__ errors.
    async fn chain_id(&self) -> web3::Result<U256> {
        retry(|| self.0.eth().chain_id(), log_and_always_retry).await
    }

    /// Wraps [`Web3::logs()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.logs)
    /// into exponential retry on __some__ errors.
    async fn logs(&self, filter: Filter) -> std::result::Result<Vec<Log>, LogsError> {
        use super::RpcErrorCode::*;
        /// Error message generated by spurious decoder error which occurs on Infura endpoints from
        /// time to time. It appears that the returned value is simply empty.
        const DECODER_ERR: &str =
            "Error(\"invalid type: null, expected a sequence\", line: 0, column: 0)";
        const ALCHEMY_UNKNOWN_BLOCK_ERR: &str =
            "One of the blocks specified in filter (fromBlock, toBlock or blockHash) cannot be found.";
        const ALCHEMY_QUERY_TIMEOUT_ERR: &str =
            "Query timeout exceeded. Consider reducing your block range.";

        retry(
            || {
                self.0.eth().logs(filter.clone()).map_err(|e| match e {
                    Error::Rpc(err) if err.code.code() == LimitExceeded.code() => {
                        LogsError::QueryLimit
                    }
                    Error::Rpc(err)
                        if err.code.code() == InvalidParams.code()
                            && err.message.starts_with("Log response size exceeded") =>
                    {
                        // Handle Alchemy query limit error response. Uses InvalidParams which is unusual.
                        LogsError::QueryLimit
                    }
                    Error::Rpc(err)
                        if err.code.code() == InvalidInput.code()
                            && err.message == ALCHEMY_UNKNOWN_BLOCK_ERR =>
                    {
                        LogsError::UnknownBlock
                    }
                    Error::Rpc(err)
                        if err.code.code() == InvalidInput.code()
                            && err.message == ALCHEMY_QUERY_TIMEOUT_ERR =>
                    {
                        LogsError::QueryLimit
                    }
                    _ => LogsError::Other(e),
                })
            },
            |e| match e {
                LogsError::Other(Error::Decoder(msg)) if msg == DECODER_ERR => {
                    tracing::trace!("Spurious L1 log decoder error occurred, retrying");
                    true
                }
                LogsError::Other(error) => log_and_always_retry(error),
                _ => false,
            },
        )
        .await
    }

    /// Wraps [`Web3::transaction()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.transaction)
    /// into exponential retry on __all__ errors.
    async fn transaction(&self, id: TransactionId) -> web3::Result<Option<Transaction>> {
        retry(
            || self.0.eth().transaction(id.clone()),
            log_and_always_retry,
        )
        .await
    }
}

/// A helper function to keep the backoff strategy consistent across different Web3 Eth API calls.
async fn retry<T, E, Fut, FutureFactory, RetryCondition>(
    future_factory: FutureFactory,
    retry_condition: RetryCondition,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
    FutureFactory: FnMut() -> Fut,
    RetryCondition: FnMut(&E) -> bool,
{
    Retry::exponential(future_factory, NonZeroU64::new(2).unwrap())
        .factor(NonZeroU64::new(15).unwrap())
        .max_delay(Duration::from_secs(60 * 60))
        .when(retry_condition)
        .await
}

/// A helper function to log Web3 Eth API errors. Always yields __true__.
fn log_and_always_retry(error: &Error) -> bool {
    match error {
        Error::Unreachable | Error::InvalidResponse(_) | Error::Transport(_) => {
            debug!(reason=%error, "L1 request failed, retrying")
        }
        Error::Decoder(_) | Error::Internal | Error::Io(_) | Error::Recovery(_) => {
            error!(reason=%error, "L1 request failed, retrying")
        }
        Error::Rpc(_) => info!(reason=%error, "L1 request failed, retrying"),
    }

    true
}

#[cfg(test)]
mod tests {
    mod logs {
        use crate::ethereum::{
            api::{LogsError, Web3EthApi},
            test_transport,
        };

        use assert_matches::assert_matches;
        use web3::types::{BlockNumber, FilterBuilder, H256};

        #[tokio::test]
        async fn ok() {
            use std::str::FromStr;
            // Create a filter which includes just a single block with a small, known amount of logs.
            let filter = FilterBuilder::default()
                .block_hash(
                    H256::from_str(
                        "0x0d82aea6f64525def8594e3192497153b83d8c568bb76adee980042d85dec931",
                    )
                    .unwrap(),
                )
                .build();

            let transport = test_transport(crate::ethereum::Chain::Goerli);

            let result = transport.logs(filter).await;
            assert_matches!(result, Ok(logs) if logs.len() == 85);
        }

        #[tokio::test]
        async fn query_limit() {
            // Create a filter which includes all logs ever. This should cause the API to return
            // error with a query limit variant.
            let filter = FilterBuilder::default()
                .from_block(BlockNumber::Earliest)
                .to_block(BlockNumber::Latest)
                .build();

            let transport = test_transport(crate::ethereum::Chain::Goerli);

            let result = transport.logs(filter).await;
            assert_matches!(result, Err(LogsError::QueryLimit));
        }

        #[tokio::test]
        async fn unknown_block() {
            // This test covers the scenario where we query a block range which exceeds the current
            // Ethereum chain.
            //
            // Infura and Alchemy handle this differently.
            //  - Infura accepts the query as valid and simply returns logs for whatever part of the range it has.
            //  - Alchemy throws a RPC::ServerError which `Web3EthImpl::logs` maps to `UnknownBlock`.
            let transport = test_transport(crate::ethereum::Chain::Goerli);
            let latest = transport.block_number().await.unwrap();

            let filter = FilterBuilder::default()
                .from_block(BlockNumber::Number((latest + 10).into()))
                .to_block(BlockNumber::Number((latest + 20).into()))
                .build();

            let result = transport.logs(filter).await;
            match result {
                // This occurs for an Infura endpoint
                Ok(logs) => assert!(logs.is_empty()),
                // This occurs for an Alchemy endpoint
                Err(e) => assert_matches!(e, LogsError::UnknownBlock),
            }
        }
    }
}
