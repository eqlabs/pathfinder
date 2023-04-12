use pathfinder_ethereum::{EthereumClient, L1StateUpdate};
use tokio::sync::mpsc::Sender;

/// Syncs L1 state updates.
pub async fn sync(
    tx_event: Sender<L1StateUpdate>,
    ethereum_client: EthereumClient,
    poll_interval: std::time::Duration,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(poll_interval).await;

        match ethereum_client.get_starknet_state().await {
            Ok(state) => tx_event.send(state).await?,
            Err(e) => tracing::error!("L1 call failed: {e:?}"),
        }
    }
}
