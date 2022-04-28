//! Wrapper for the parts of the [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html) API that [the ethereum module](super) uses.
use crate::retry::Retry;

use std::future::Future;
use std::num::NonZeroU64;
use std::time::Duration;

use tracing::{debug, error, info};
use web3::{
    error::{Error, Result},
    types::{Block, BlockId, Filter, Log, Transaction, TransactionId, H256, U256},
    Transport, Web3,
};

#[async_trait::async_trait]
/// Contains only those functions from [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// that [the ethereum module](super) uses.
pub trait Web3EthApi {
    async fn block(&self, block: BlockId) -> Result<Option<Block<H256>>>;
    async fn block_number(&self) -> Result<u64>;
    async fn chain_id(&self) -> Result<U256>;
    async fn logs(&self, filter: Filter) -> Result<Vec<Log>>;
    async fn transaction(&self, id: TransactionId) -> Result<Option<Transaction>>;
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
    async fn block(&self, block: BlockId) -> Result<Option<Block<H256>>> {
        retry(|| self.0.eth().block(block), log_and_always_retry).await
    }

    /// Wraps [`Web3::eth().block_number()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.block_number)
    /// into exponential retry on __all__ errors.
    async fn block_number(&self) -> Result<u64> {
        retry(|| self.0.eth().block_number(), log_and_always_retry)
            .await
            .map(|n| n.as_u64())
    }

    /// Wraps [`Web3::chain_id()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.chain_id)
    /// into exponential retry on __all__ errors.
    async fn chain_id(&self) -> Result<U256> {
        retry(|| self.0.eth().chain_id(), log_and_always_retry).await
    }

    /// Wraps [`Web3::logs()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.logs)
    /// into exponential retry on __some__ errors.
    async fn logs(&self, filter: Filter) -> Result<Vec<Log>> {
        retry(|| self.0.eth().logs(filter.clone()), |_| false).await
    }

    /// Wraps [`Web3::transaction()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html#method.transaction)
    /// into exponential retry on __all__ errors.
    async fn transaction(&self, id: TransactionId) -> Result<Option<Transaction>> {
        retry(
            || self.0.eth().transaction(id.clone()),
            log_and_always_retry,
        )
        .await
    }
}

/// A helper function to keep the backoff strategy consistent across different Web3 Eth API calls.
async fn retry<T, Fut, FutureFactory, RetryCondition>(
    future_factory: FutureFactory,
    retry_condition: RetryCondition,
) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
    FutureFactory: FnMut() -> Fut,
    RetryCondition: FnMut(&web3::Error) -> bool,
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
