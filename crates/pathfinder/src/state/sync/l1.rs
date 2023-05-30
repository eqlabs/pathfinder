use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use primitive_types::H160;
use tokio::sync::mpsc;

/// Syncs L1 state update logs. Emits [sync events](Event) which should be handled
/// to update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<EthereumStateUpdate>,
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

async fn sync_impl(
    ethereum: impl EthereumApi,
    tx_event: mpsc::Sender<EthereumStateUpdate>,
    chain: Chain,
    core_address: H160,
) -> anyhow::Result<()> {
    use crate::state::sync::head_poll_interval;

    let head_poll_interval = head_poll_interval(chain);

    loop {
        let state_update = ethereum.get_starknet_state(&core_address).await?;
        tx_event.send(state_update).await?;

        tokio::time::sleep(head_poll_interval).await;
        continue;
    }
}
