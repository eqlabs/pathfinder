use ethers::providers::Middleware;
use ethers::types::{Block, BlockId, Filter, Log, Transaction, TxHash, H256, U256};
use futures::TryFutureExt;
use pathfinder_common::EthereumChain;
use pathfinder_retry::Retry;
use reqwest::Url;
use std::future::Future;
use std::num::NonZeroU64;
use std::time::Duration;
use tracing::error;

/// Error returned by [`HttpProvider::logs`].
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
    Other(#[from] ethers::providers::ProviderError),
}

/// Contains only those functions from that [the ethereum module](super) uses.
#[async_trait::async_trait]
pub trait EthereumTransport {
    async fn block(&self, block: BlockId) -> anyhow::Result<Option<Block<H256>>>;
    async fn block_number(&self) -> anyhow::Result<u64>;
    async fn chain(&self) -> anyhow::Result<EthereumChain>;
    async fn logs(&self, filter: Filter) -> std::result::Result<Vec<Log>, LogsError>;
    async fn transaction(&self, id: TxHash) -> anyhow::Result<Option<Transaction>>;
    async fn gas_price(&self) -> anyhow::Result<U256>;
}

/// An implementation of [`EthereumTransport`] wrapped with a [exponential backoff retry utility](Retry).
///
/// Initial backoff time is 30 seconds and saturates at 10 minutes:
///
/// `backoff [secs] = min((2 ^ N) * 15, 600) [secs]`
///
/// where `N` is the consecutive retry iteration number `{1, 2, ...}`.
#[derive(Clone, Debug)]
pub struct HttpProvider(ethers::providers::Provider<ethers::providers::Http>);

impl HttpProvider {
    /// Creates new [`HttpProvider`].
    pub fn new(http: ethers::providers::Provider<ethers::providers::Http>) -> Self {
        Self(http)
    }

    /// Creates new [`HttpProvider`] from url and optional password
    ///
    /// This includes setting:
    /// - the [Url](reqwest::Url)
    /// - the password (if provided)
    pub fn from_config(url: Url, password: Option<String>) -> anyhow::Result<Self> {
        let mut url = url;
        url.set_password(password.as_deref())
            .map_err(|_| anyhow::anyhow!("Setting password"))?;

        let provider = ethers::providers::Http::new(url);
        let provider = ethers::providers::Provider::new(provider);

        Ok(Self::new(provider))
    }

    /// Creates a [`HttpProvider`] transport from the Ethereum endpoint specified by the relevant environment variables.
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
    pub fn test_provider(chain: pathfinder_common::Chain) -> Self {
        use pathfinder_common::Chain;
        let key_prefix = match chain {
            Chain::Mainnet => "PATHFINDER_ETHEREUM_HTTP_MAINNET",
            Chain::Testnet | Chain::Testnet2 | Chain::Integration => {
                "PATHFINDER_ETHEREUM_HTTP_GOERLI"
            }
            Chain::Custom => unreachable!("Chain::Custom should not be used in testing"),
        };

        let url_key = format!("{key_prefix}_URL");
        let password_key = format!("{key_prefix}_PASSWORD");

        let url = std::env::var(&url_key)
            .unwrap_or_else(|_| panic!("Ethereum URL environment var not set {url_key}"));

        let password = std::env::var(password_key).ok();

        let url = url.parse::<reqwest::Url>().expect("Bad Ethereum URL");

        Self::from_config(url, password).unwrap()
    }
}

#[async_trait::async_trait]
impl EthereumTransport for HttpProvider {
    async fn block(&self, block: BlockId) -> anyhow::Result<Option<Block<H256>>> {
        Ok(retry(|| self.0.get_block(block), log_and_always_retry).await?)
    }

    async fn block_number(&self) -> anyhow::Result<u64> {
        Ok(retry(|| self.0.get_block_number(), log_and_always_retry)
            .await
            .map(|n| n.as_u64())?)
    }

    /// Identifies the [EthereumChain] behind the given Ethereum transport.
    ///
    /// Will error if it's not one of the valid Starknet [EthereumChain] variants.
    async fn chain(&self) -> anyhow::Result<EthereumChain> {
        match retry(|| self.0.get_chainid(), log_and_always_retry).await? {
            id if id == U256::from(1u32) => Ok(EthereumChain::Mainnet),
            id if id == U256::from(5u32) => Ok(EthereumChain::Goerli),
            other => anyhow::bail!("Unsupported chain ID: {}", other),
        }
    }

    async fn logs(&self, filter: Filter) -> std::result::Result<Vec<Log>, LogsError> {
        const INVALID_PARAMS: i64 = -32602;
        const LIMIT_EXCEEDED: i64 = -32005;
        const INVALID_INPUT: i64 = -32000;
        const RESOURCE_NOT_FOUND: i64 = -32001;

        retry(
            || {
                use ethers::providers::ProviderError;
                use ethers::providers::HttpClientError;

                self.0.get_logs(&filter).map_err(|err| {
                    let rpc_err = match err {
                        ProviderError::JsonRpcClientError(inner) => inner,
                        other => return LogsError::Other(other),
                    };

                    let rpc_err = match rpc_err.downcast::<HttpClientError>() {
                        Ok(a) => a,
                        Err(b) => return LogsError::Other(b.into()),
                    };

                    let rpc_err = match *rpc_err {
                        HttpClientError::JsonRpcError(rpc_err) => rpc_err,
                        other => return LogsError::Other(other.into()),
                    };

                    match (rpc_err.code, rpc_err.message.as_str()) {
                        (LIMIT_EXCEEDED, _) => LogsError::QueryLimit,
                        (INVALID_PARAMS, msg) if msg.starts_with("Log response size exceeded") => {
                            LogsError::QueryLimit
                        }
                        (INVALID_PARAMS, msg) if msg.starts_with("query returned more than") => {
                            LogsError::QueryLimit
                        }
                        // This error is emitted by the Nethermind node if `toBlock > latest`.
                        (RESOURCE_NOT_FOUND, msg) if msg.ends_with("could not be found") => {
                            LogsError::QueryLimit
                        }
                        (INVALID_INPUT, "Query timeout exceeded. Consider reducing your block range.") => LogsError::QueryLimit,
                        (INVALID_INPUT, "One of the blocks specified in filter (fromBlock, toBlock or blockHash) cannot be found.") => LogsError::UnknownBlock,
                        _ => LogsError::Other(HttpClientError::JsonRpcError(rpc_err).into()),
                    }
                })
            },
            |e| match e {
                LogsError::Other(error) => log_and_always_retry(error),
                _ => false,
            },
        )
        .await
    }

    async fn transaction(&self, id: TxHash) -> anyhow::Result<Option<Transaction>> {
        Ok(retry(|| self.0.get_transaction(id), log_and_always_retry).await?)
    }

    async fn gas_price(&self) -> anyhow::Result<U256> {
        Ok(retry(|| self.0.get_gas_price(), log_and_always_retry).await?)
    }
}

/// A helper function to keep the backoff strategy consistent across different Eth API calls.
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
        .max_delay(Duration::from_secs(10 * 60))
        .when(retry_condition)
        .await
}

/// A helper function to log API errors. Always yields __true__.
fn log_and_always_retry(error: &ethers::providers::ProviderError) -> bool {
    error!(reason=%error, "L1 request failed, retrying");

    true
}

#[cfg(test)]
impl std::ops::Deref for HttpProvider {
    type Target = ethers::providers::Provider<ethers::providers::Http>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    mod logs {
        use crate::provider::{EthereumTransport, HttpProvider, LogsError};
        use assert_matches::assert_matches;
        use ethers::types::{BlockNumber, H256};
        use pathfinder_common::Chain;

        #[tokio::test]
        async fn ok() {
            use std::str::FromStr;
            // Create a filter which includes just a single block with a small, known amount of logs.
            let filter = ethers::types::Filter::default().at_block_hash(
                H256::from_str(
                    "0x0d82aea6f64525def8594e3192497153b83d8c568bb76adee980042d85dec931",
                )
                .unwrap(),
            );

            let transport = HttpProvider::test_provider(Chain::Testnet);

            let result = transport.logs(filter).await;
            assert_matches!(result, Ok(logs) if logs.len() == 85);
        }

        #[tokio::test]
        async fn query_limit() {
            // Create a filter which includes all logs ever. This should cause the API to return
            // error with a query limit variant.
            let filter = ethers::types::Filter::default()
                .from_block(BlockNumber::Earliest)
                .to_block(BlockNumber::Latest);

            let transport = HttpProvider::test_provider(Chain::Testnet);

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
            //  - Alchemy throws a RPC::ServerError which `HttpProvider::logs` maps to `UnknownBlock`.
            let transport = HttpProvider::test_provider(Chain::Testnet);
            let latest = transport.block_number().await.unwrap();

            let filter = ethers::types::Filter::default()
                .from_block(BlockNumber::Number((latest + 10).into()))
                .to_block(BlockNumber::Number((latest + 20).into()));

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
