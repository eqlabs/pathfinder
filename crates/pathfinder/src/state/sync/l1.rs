use std::{num::NonZeroU64, time::Duration};

use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_retry::Retry;
use primitive_types::H160;
use tokio::sync::mpsc;

use crate::state::sync::SyncEvent;

#[derive(Clone)]
pub struct L1SyncContext<EthereumClient> {
    pub ethereum: EthereumClient,
    pub chain: Chain,
    /// The Starknet core contract address on Ethereum
    pub core_address: H160,
    pub poll_interval: Duration,
}

/// Syncs L1 state update logs. Emits [Ethereum state update](EthereumStateUpdate)
/// which should be handled to update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<SyncEvent>,
    context: L1SyncContext<T>,
) -> anyhow::Result<()>
where
    T: EthereumApi + Clone,
{
    let L1SyncContext {
        ethereum,
        chain: _,
        core_address,
        poll_interval,
    } = context;

    let mut previous = EthereumStateUpdate::default();

    loop {
        let state_update = Retry::exponential(
            || async { ethereum.get_starknet_state(&core_address).await },
            NonZeroU64::new(1).unwrap(),
        )
        .factor(NonZeroU64::new(2).unwrap())
        .max_delay(poll_interval / 2)
        .when(|_| true)
        .await?;

        if previous != state_update {
            previous = state_update.clone();
            tx_event.send(SyncEvent::L1Update(state_update)).await?;
        }

        tokio::time::sleep(poll_interval).await;
    }
}
