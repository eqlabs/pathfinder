use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumClient, L1StateUpdate};
use primitive_types::H160;
use tokio::sync::mpsc::Sender;

/// Syncs L1 state updates.
pub async fn sync(
    tx_event: Sender<L1StateUpdate>,
    ethereum_client: EthereumClient,
    chain: Chain,
    core_address: H160,
) -> anyhow::Result<()> {
    let poll_interval = crate::state::sync::head_poll_interval(chain);

    loop {
        // TODO(SM): impl
        tokio::time::sleep(poll_interval).await;
    }
}
