use futures::Future;
use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_retry::Retry;
use primitive_types::H160;
use std::{num::NonZeroU64, time::Duration};
use tokio::sync::mpsc;

// TODO(SM): remove `Event` wrapper
/// Events and queries emitted by L1 sync process.
#[derive(Debug)]
pub enum Event {
    /// New L1 [update](EthereumStateUpdate).
    Update(EthereumStateUpdate),
}

/// Syncs L1 state update logs. Emits [sync events](Event) which should be handled
/// to update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<Event>,
    ethereum: T,
    chain: Chain,
    core_address: H160,
) -> anyhow::Result<()>
where
    T: EthereumApi + Send + Sync + Clone,
{
    // The core sync logic implementation.
    sync_impl(ethereum, tx_event, chain, core_address).await
}

#[allow(dead_code)] // TODO(SM): remove
/// A helper function to keep the backoff strategy construction separated.
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

async fn sync_impl(
    ethereum: impl EthereumApi,
    tx_event: mpsc::Sender<Event>,
    chain: Chain,
    core_address: H160,
) -> anyhow::Result<()> {
    use crate::state::sync::head_poll_interval;

    let head_poll_interval = head_poll_interval(chain);

    loop {
        let state_update = ethereum.get_starknet_state(&core_address).await?;
        tx_event.send(Event::Update(state_update)).await?;

        tokio::time::sleep(head_poll_interval).await;
        continue;
    }
}
