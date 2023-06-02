use std::num::NonZeroU64;

use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_retry::Retry;
use primitive_types::H160;
use tokio::sync::mpsc;

use super::head_poll_interval;

/// Syncs L1 state update logs. Emits [Ethereum state update](EthereumStateUpdate)
/// which should be handled to update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<EthereumStateUpdate>,
    ethereum: T,
    chain: Chain,
    core_address: H160,
) where
    T: EthereumApi + Clone,
{
    let head_poll_interval = head_poll_interval(chain);

    loop {
        let maybe_update = Retry::exponential(
            || async { ethereum.get_starknet_state(&core_address).await },
            NonZeroU64::new(1).unwrap(),
        )
        .factor(NonZeroU64::new(2).unwrap())
        .max_delay(head_poll_interval / 2)
        .when(|_| true)
        .await;
        match maybe_update {
            Ok(state_update) => {
                tx_event.send(state_update).await.ok();
            }
            Err(e) => {
                tracing::warn!(reason=?e, "Failed to fetch L1 state");
            }
        }
        tokio::time::sleep(head_poll_interval).await;
    }
}
