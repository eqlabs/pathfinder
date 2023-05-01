use pathfinder_ethereum::{EthereumClientApi, L1StateUpdate};
use tokio::sync::mpsc::Sender;

use crate::delay::{ExpBackoffDelay, Delay};

/// Syncs L1 state updates.
pub async fn sync(
    tx_event: Sender<L1StateUpdate>,
    ethereum_client: impl EthereumClientApi,
    poll_interval: std::time::Duration,
) {
    let delay = ExpBackoffDelay::new(std::time::Duration::from_secs(1), poll_interval);
    loop {
        tokio::time::sleep(delay.get()).await;

        match ethereum_client.get_starknet_state().await {
            Ok(state) => {
                delay.success();
                if let Err(e) = tx_event.send(state).await {
                    tracing::error!(reason=?e, "L1 update failed");
                }
            }
            Err(e) => {
                delay.failure();
                tracing::debug!(reason=?e, "L1 call failed");
            }
        }
    }
}
