use std::time::Duration;

use pathfinder_common::{Chain, L1BlockNumber};
use pathfinder_ethereum::{EthereumApi, EthereumClient};
use primitive_types::H160;
use tokio::sync::mpsc;

use crate::state::l1_gas_price::L1GasPriceProvider;
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

/// Syncs L1 state update logs.
///
/// Emits [Ethereum state update](pathfinder_ethereum::EthereumStateUpdate)
/// which should be handled to update storage and respond to queries.
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

    let tx_event = std::sync::Arc::new(tx_event);

    // Subscribe to subsequent state updates and message logs
    ethereum
        .sync_and_listen(&core_address, poll_interval, move |state_update| {
            let tx_event = tx_event.clone();
            async move {
                let _ = tx_event.send(SyncEvent::L1Update(state_update)).await;
            }
        })
        .await?;

    Ok(())
}

/// Configuration for L1 gas price synchronization.
#[derive(Debug, Clone)]
pub struct L1GasPriceSyncConfig {
    /// Number of historical blocks to fetch on startup.
    /// Default: 10
    pub startup_blocks: u64,
}

impl Default for L1GasPriceSyncConfig {
    fn default() -> Self {
        Self { startup_blocks: 10 }
    }
}

/// Syncs L1 gas prices from block headers into the provider.
///
/// Uses historical data at startup, and then subscribes to new block headers
/// and adds gas prices as they arrive.
pub async fn sync_gas_prices(
    ethereum: EthereumClient,
    provider: L1GasPriceProvider,
    config: L1GasPriceSyncConfig,
) -> anyhow::Result<()> {
    // Get the finalized block to determine where to start historical fetch
    let finalized = ethereum.get_finalized_block_number().await?;
    tracing::debug!(finalized_block = %finalized, "Starting L1 gas price sync");

    // Fetch historical gas prices to populate the buffer
    let start_block = finalized.get().saturating_sub(config.startup_blocks).max(1);
    let start_block = L1BlockNumber::new_or_panic(start_block);

    tracing::debug!(
        start = %start_block,
        end = %finalized,
        "Fetching historical gas prices"
    );

    let historical_data = ethereum
        .get_gas_price_data_range(start_block, finalized)
        .await?;

    let fetched_count = historical_data.len();
    if let Err(e) = provider.add_samples(historical_data) {
        tracing::warn!(error = %e, "Failed to add historical gas price samples");
    }

    tracing::debug!(
        samples = fetched_count,
        "Populated gas price buffer with historical data"
    );

    // Subscribe to new block headers
    ethereum
        .subscribe_block_headers(move |data| {
            let provider = provider.clone();
            async move {
                if let Err(e) = provider.add_sample(data) {
                    tracing::warn!(
                        block = %data.block_number,
                        error = %e,
                        "Failed to add gas price sample"
                    );
                } else {
                    tracing::trace!(
                        block = %data.block_number,
                        base_fee = data.base_fee_per_gas,
                        blob_fee = data.blob_fee,
                        "Added gas price sample"
                    );
                }
            }
        })
        .await
}
