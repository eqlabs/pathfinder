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
    /// TODO
    async fn block(&self, block: BlockId) -> Result<Option<Block<H256>>>;
    /// TODO
    async fn block_number(&self) -> Result<u64>;
    /// TODO
    async fn chain_id(&self) -> Result<U256>;
    /// TODO
    async fn logs(&self, filter: Filter) -> Result<Vec<Log>>;
    /// TODO
    async fn transaction(&self, id: TransactionId) -> Result<Option<Transaction>>;
}

/// An implementation of [`Web3EthApi`] which uses [`Web3::eth()`](https://docs.rs/web3/latest/web3/api/struct.Eth.html)
/// wrapped in an [exponential backoff retry utility](Retry).
///
/// Retry is performed on __TODO__ types of errors __except for__ TODO.
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
    async fn block(&self, block: BlockId) -> Result<Option<Block<H256>>> {
        retry(|| self.0.eth().block(block), retry_condition).await
    }

    async fn block_number(&self) -> Result<u64> {
        retry(|| self.0.eth().block_number(), retry_condition)
            .await
            .map(|n| n.as_u64())
    }

    async fn chain_id(&self) -> Result<U256> {
        retry(|| self.0.eth().chain_id(), retry_condition).await
    }

    async fn logs(&self, filter: Filter) -> Result<Vec<Log>> {
        retry(|| self.0.eth().logs(filter.clone()), |_| false).await
    }

    async fn transaction(&self, id: TransactionId) -> Result<Option<Transaction>> {
        retry(|| self.0.eth().transaction(id.clone()), retry_condition).await
    }
}

/// A helper function to keep the backoff strategy consistent across different Eth Web3 API calls.
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

fn retry_condition(error: &Error) -> bool {
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
