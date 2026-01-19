use std::time::Duration;

use pathfinder_common::Chain;
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
) -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pathfinder_ethereum::EthereumClient;

    use super::sync_gas_prices;
    use crate::state::l1_gas_price::{L1GasPriceConfig, L1GasPriceProvider};

    #[ignore = "Uses network, takes too long..."]
    #[test_log::test(tokio::test(flavor = "multi_thread"))]
    async fn test_sync_gas_prices() {
        // see https://github.com/snapview/tokio-tungstenite/issues/339
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let client_url = reqwest::Url::parse("wss://eth.llamarpc.com").unwrap();
        let ethereum_client = EthereumClient::new(client_url).unwrap();
        let provider = L1GasPriceProvider::new(L1GasPriceConfig::default());
        let provider2 = provider.clone();
        util::task::spawn(async move {
            sync_gas_prices(ethereum_client, provider2).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(60)).await;
        // provider should have got some new (IOW not initial, but
        // from its subscription) samples by now
        let sample_count = provider.sample_count();
        tracing::debug!("sample_count = {sample_count}");
        assert!(sample_count > 3);
    }
}
