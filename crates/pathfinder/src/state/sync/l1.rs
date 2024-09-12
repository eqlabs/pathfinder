use std::time::Duration;

use pathfinder_common::Chain;
use pathfinder_ethereum::{EthereumApi, EthereumEvent};
use primitive_types::H160;
use tokio::sync::mpsc;

use crate::state::sync::SyncEvent;

#[derive(Clone)]
pub struct L1SyncContext<EthereumClient> {
    pub ethereum: EthereumClient,
    /// The Ethereum chain to sync from
    pub chain: Chain,
    /// The Starknet core contract address on Ethereum
    pub core_address: H160,
    /// The interval at which to poll for updates on finalized blocks
    pub poll_interval: Duration,
}

/// Syncs L1 state update logs. Emits [Ethereum state
/// update](pathfinder_ethereum::EthereumStateUpdate) which should be handled to
/// update storage and respond to queries.
pub async fn sync<T>(
    tx_event: mpsc::Sender<SyncEvent>,
    context: L1SyncContext<T>,
) -> anyhow::Result<()>
where
    T: EthereumApi + Clone,
{
    let L1SyncContext {
        mut ethereum,
        chain: _,
        core_address,
        poll_interval,
    } = context;

    // Fetch the current Starknet state from Ethereum
    let state_update = ethereum.get_starknet_state(&core_address).await?;
    let _ = tx_event.send(SyncEvent::L1Update(state_update)).await;

    // Subscribe to subsequent state updates and message logs
    let tx_event = std::sync::Arc::new(tx_event);
    ethereum
        .listen(&core_address, poll_interval, move |event| {
            let tx_event = tx_event.clone();
            async move {
                match event {
                    EthereumEvent::StateUpdate(state_update) => {
                        let _ = tx_event.send(SyncEvent::L1Update(state_update)).await;
                    }
                    EthereumEvent::MessageLog(log) => {
                        let _ = tx_event.send(SyncEvent::L1ToL2Message(log)).await;
                    }
                }
            }
        })
        .await?;

    Ok(())
}
