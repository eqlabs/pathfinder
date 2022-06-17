//! Wrapper for the parts of the [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html) API that [the ethereum module](super) uses.
use crate::config::EthereumConfig;
use crate::ethereum::Chain;
use crate::retry::Retry;

use std::future::Future;
use std::num::NonZeroU64;
use std::time::Duration;

use anyhow::Context;
use futures::TryFutureExt;
use tracing::{debug, error, info};
use web3::{
    transports::Http,
    types::{Block, BlockId, Filter, Log, Transaction, TransactionId, H256, U256},
    Error, Web3,
};

/// Error returned by [`HttpTransport::logs`].
#[derive(Debug, thiserror::Error)]
pub enum LogsError {
    /// Query exceeded limits (time or result length).
    #[error("query limit exceeded")]
    QueryLimit,
    /// One of the blocks specified in the filter is unknown. Currently only
    /// known to occur for Alchemy endpoints.
    #[error("unknown block")]
    UnknownBlock,
    #[error(transparent)]
    Other(#[from] web3::Error),
}

/// Contains only those functions from [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// that [the ethereum module](super) uses.
#[async_trait::async_trait]
pub trait EthereumTransport {
    async fn block(&self, block: BlockId) -> web3::Result<Option<Block<H256>>>;
    async fn block_number(&self) -> web3::Result<u64>;
    async fn chain(&self) -> anyhow::Result<Chain>;
    async fn logs(&self, filter: Filter) -> std::result::Result<Vec<Log>, LogsError>;
    async fn transaction(&self, id: TransactionId) -> web3::Result<Option<Transaction>>;
    async fn gas_price(&self) -> web3::Result<U256>;
}

/// An implementation of [`EthereumTransport`] which uses [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// wrapped in an [exponential backoff retry utility](Retry).
///
/// Initial backoff time is 30 seconds and saturates at 1 hour:
///
/// `backoff [secs] = min((2 ^ N) * 15, 3600) [secs]`
///
/// where `N` is the consecutive retry iteration number `{1, 2, ...}`.
#[derive(Clone, Debug)]
pub struct HttpTransport(Web3<Http>);

impl HttpTransport {
    /// Creates new [`HttpTransport`] from [`Web3<Http>`]
    pub fn new(http: Web3<Http>) -> Self {
        Self(http)
    }

    /// Creates new [`HttpTransport`] from [configuration](EthereumConfig)
    ///
    /// This includes setting:
    /// - the [Url](reqwest::Url)
    /// - the user-agent (if provided)
    /// - the password (if provided)
    pub fn from_config(config: EthereumConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder();

        let client = client
            .user_agent(crate::consts::USER_AGENT)
            .build()
            .context("Creating HTTP client")?;

        let mut url = config.url;
        url.set_password(config.password.as_deref())
            .map_err(|_| anyhow::anyhow!("Setting password"))?;

        let client = Http::with_client(client, url);

        Ok(Self::new(Web3::new(client)))
    }

    #[cfg(test)]
    /// Creates a [HttpTransport](api::HttpTransport) transport from the Ethereum endpoint specified by the relevant environment variables.
    ///
    /// Requires an environment variable for both the URL and (optional) password.
    ///
    /// Panics if the environment variables are not specified.
    ///
    /// Goerli:  PATHFINDER_ETHEREUM_HTTP_GOERLI_URL
    ///          PATHFINDER_ETHEREUM_HTTP_GOERLI_PASSWORD (optional)
    ///
    /// Mainnet: PATHFINDER_ETHEREUM_HTTP_MAINNET_URL
    ///          PATHFINDER_ETHEREUM_HTTP_MAINNET_PASSWORD (optional)
    pub fn test_transport(chain: Chain) -> Self {
        let key_prefix = match chain {
            Chain::Mainnet => "PATHFINDER_ETHEREUM_HTTP_MAINNET",
            Chain::Goerli => "PATHFINDER_ETHEREUM_HTTP_GOERLI",
        };

        let url_key = format!("{}_URL", key_prefix);
        let password_key = format!("{}_PASSWORD", key_prefix);

        let url = std::env::var(&url_key)
            .unwrap_or_else(|_| panic!("Ethereum URL environment var not set {url_key}"));

        let password = std::env::var(password_key).ok();

        let mut url = url.parse::<reqwest::Url>().expect("Bad Ethereum URL");
        url.set_password(password.as_deref()).unwrap();

        let client = reqwest::Client::builder().build().unwrap();
        let transport = Http::with_client(client, url);

        Self::new(Web3::new(transport))
    }
}

#[async_trait::async_trait]
impl EthereumTransport for HttpTransport {
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

    /// Identifies the Ethereum [Chain] behind the given Ethereum transport.
    ///
    /// Will error if it's not one of the valid Starknet [Chain] variants.
    /// Internaly wraps [`Web3::chain_id()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.chain_id)
    /// into exponential retry on __all__ errors.
    async fn chain(&self) -> anyhow::Result<Chain> {
        match retry(|| self.0.eth().chain_id(), log_and_always_retry).await? {
            id if id == U256::from(1u32) => Ok(Chain::Mainnet),
            id if id == U256::from(5u32) => Ok(Chain::Goerli),
            other => anyhow::bail!("Unsupported chain ID: {}", other),
        }
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

    async fn gas_price(&self) -> web3::Result<U256> {
        Retry::exponential(|| self.0.eth().gas_price(), NonZeroU64::new(1).unwrap())
            .factor(NonZeroU64::new(2).unwrap())
            .max_delay(Duration::from_secs(5))
            .when(log_and_always_retry)
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
impl std::ops::Deref for HttpTransport {
    type Target = Web3<Http>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    mod logs {
        use crate::ethereum::{
            transport::{EthereumTransport, HttpTransport, LogsError},
            Chain,
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

            let transport = HttpTransport::test_transport(Chain::Goerli);

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

            let transport = HttpTransport::test_transport(Chain::Goerli);

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
            //  - Alchemy throws a RPC::ServerError which `HttpTransport::logs` maps to `UnknownBlock`.
            let transport = HttpTransport::test_transport(Chain::Goerli);
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
