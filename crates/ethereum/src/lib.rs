use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::pubsub::PubSubFrontend;
use alloy::rpc::types::{Filter, Log};
use anyhow::Context;
use futures::{FutureExt, StreamExt};
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    EthereumChain,
    L1BlockNumber,
    L1ToL2MessageLog,
    L1TransactionHash,
    StateCommitment,
};
use primitive_types::{H160, H256, U256};
use reqwest::{IntoUrl, Url};
use starknet::StarknetCoreContract;
use tokio::select;

use crate::utils::*;

mod starknet;
mod utils;

/// Starknet core contract addresses
pub mod core_addr {
    use const_decoder::Decoder;

    /// Ethereum address of the Starknet core contract on Mainnet
    pub const MAINNET: [u8; 20] = Decoder::Hex.decode(b"c662c410C0ECf747543f5bA90660f6ABeBD9C8c4");

    /// Ethereum address of the Starknet core contract on Sepolia testnet
    pub const SEPOLIA_TESTNET: [u8; 20] =
        Decoder::Hex.decode(b"E2Bb56ee936fd6433DC0F6e7e3b8365C906AA057");

    /// Ethereum address of the Starknet core contract on Sepolia integration
    /// testnet
    pub const SEPOLIA_INTEGRATION: [u8; 20] =
        Decoder::Hex.decode(b"4737c0c1B4D5b1A687B42610DdabEE781152359c");
}

pub mod block_numbers {
    use super::{BlockNumber, L1BlockNumber};
    pub mod mainnet {
        use super::{BlockNumber, L1BlockNumber};
        /// The first v0.13.2 block number
        pub const FIRST_V0_13_2_BLOCK: BlockNumber = BlockNumber::new_or_panic(671_813);
        /// The first L1 block number with a state update corresponding to
        /// v0.13.2 of Starknet
        pub const FIRST_L1_BLOCK_STARKNET_V0_13_2: L1BlockNumber =
            L1BlockNumber::new_or_panic(20_627_771);
    }

    pub mod sepolia {
        use super::{BlockNumber, L1BlockNumber};
        /// The first v0.13.2 block number
        pub const FIRST_V0_13_2_BLOCK: BlockNumber = BlockNumber::new_or_panic(86_311);
        /// The first L1 block number with a state update corresponding to
        /// v0.13.2 of Starknet
        pub const FIRST_L1_BLOCK_STARKNET_V0_13_2: L1BlockNumber =
            L1BlockNumber::new_or_panic(6_453_990);
    }
}

/// Events that can be emitted by the Ethereum client
#[derive(Debug)]
pub enum EthereumEvent {
    StateUpdate(EthereumStateUpdate),
    MessageLog(L1ToL2MessageLog),
}

/// State update from Ethereum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EthereumStateUpdate {
    pub state_root: StateCommitment,
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
    pub l1_block_number: Option<L1BlockNumber>,
}

/// Ethereum API trait
#[async_trait::async_trait]
pub trait EthereumApi {
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate>;
    async fn get_chain(&self) -> anyhow::Result<EthereumChain>;
    async fn get_message_logs(
        &self,
        address: &H160,
        from_block: L1BlockNumber,
        to_block: L1BlockNumber,
    ) -> anyhow::Result<Vec<L1ToL2MessageLog>>;
    async fn get_state_updates(
        &self,
        address: &H160,
        from_block: L1BlockNumber,
        to_block: L1BlockNumber,
    ) -> anyhow::Result<Vec<EthereumStateUpdate>>;
    async fn sync_and_listen<F, Fut>(
        &mut self,
        address: &H160,
        from_block: L1BlockNumber,
        poll_interval: Duration,
        callback: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(EthereumEvent) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static;
}

/// Ethereum client
#[derive(Clone, Debug)]
pub struct EthereumClient {
    url: Url,
    pending_state_updates: BTreeMap<L1BlockNumber, EthereumStateUpdate>,
}

impl EthereumClient {
    /// Creates a new [EthereumClient]
    pub fn new<U: IntoUrl>(url: U) -> anyhow::Result<Self> {
        Ok(Self {
            url: url.into_url()?,
            pending_state_updates: BTreeMap::new(),
        })
    }

    /// Creates a new password-protected [EthereumClient]
    pub fn with_password<U: IntoUrl>(url: U, password: &str) -> anyhow::Result<Self> {
        let mut url = url.into_url()?;
        url.set_password(Some(password))
            .map_err(|_| anyhow::anyhow!("Setting password failed"))?;
        Self::new(url)
    }

    /// Returns the block number of the last finalized block
    async fn get_finalized_block_number(&self) -> anyhow::Result<L1BlockNumber> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        // Fetch the finalized block number
        provider
            .get_block_by_number(BlockNumberOrTag::Finalized, false)
            .await?
            .map(|block| L1BlockNumber::new_or_panic(block.header.number))
            .context("Failed to fetch finalized block hash")
    }
}

#[async_trait::async_trait]
impl EthereumApi for EthereumClient {
    /// Listens for Ethereum events and notifies the caller using the provided
    /// callback. State updates will only be emitted once they belong to a
    /// finalized block.
    async fn sync_and_listen<F, Fut>(
        &mut self,
        address: &H160,
        from_block: L1BlockNumber,
        poll_interval: Duration,
        callback: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(EthereumEvent) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Fetch the current Starknet state from Ethereum
        let state_update = self.get_starknet_state(address).await?;
        let _ = callback(EthereumEvent::StateUpdate(state_update)).await;

        // Sync logs from the last known L1 handler block up to the latest finalized
        // block
        let logs = self
            .get_message_logs(
                address,
                from_block,
                state_update
                    .l1_block_number
                    .expect("missing l1 block number"),
            )
            .await?;

        tracing::trace!(
            number_of_logs=%logs.len(),
            from_block=%from_block,
            to_block=?state_update.l1_block_number.unwrap(),
            "Fetched L1 to L2 message logs",
        );

        for log in logs {
            let _ = callback(EthereumEvent::MessageLog(log)).await;
        }

        // Prevent a gap between the latest confirmed L1 block and the tip of the chain
        // when syncing logs.
        let mut logs_in_sync = false;

        // Create the StarknetCoreContract instance
        let core_address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(core_address, provider.clone());

        // Listen for L1 to L2 message events
        let mut logs = provider
            .subscribe_logs(&core_contract.LogMessageToL2_filter().filter)
            .await?
            .into_stream();

        // Listen for state update events
        let mut state_updates = provider
            .subscribe_logs(&core_contract.LogStateUpdate_filter().filter)
            .await?
            .into_stream();

        // Poll regularly for finalized block number
        let provider_clone = provider.clone();
        let (finalized_block_tx, mut finalized_block_rx) =
            tokio::sync::mpsc::channel::<L1BlockNumber>(1);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            loop {
                interval.tick().await;
                if let Ok(Some(finalized_block)) = provider_clone
                    .get_block_by_number(BlockNumberOrTag::Finalized, false)
                    .await
                {
                    let block_number = L1BlockNumber::new_or_panic(finalized_block.header.number);
                    let _ = finalized_block_tx.send(block_number).await.unwrap();
                }
            }
        });

        // Process incoming events
        loop {
            select! {
                Some(state_update) = state_updates.next() => {
                    // Decode the state update
                    let eth_block = L1BlockNumber::new_or_panic(
                        state_update.block_number.expect("missing eth block number")
                    );
                    let state_update: Log<StarknetCoreContract::LogStateUpdate> = state_update.log_decode()?;
                    let block_number = get_block_number(state_update.inner.blockNumber);
                    // Add or remove to/from pending state updates accordingly
                    if !state_update.removed {
                        let state_update = EthereumStateUpdate {
                            block_number,
                            block_hash: get_block_hash(state_update.inner.blockHash),
                            state_root: get_state_root(state_update.inner.globalRoot),
                            l1_block_number: None,
                        };
                        self.pending_state_updates.insert(eth_block, state_update);
                    } else {
                        self.pending_state_updates.remove(&eth_block);
                    }
                }
                Some(log) = logs.next() => {
                    // Fetch potentially unsynced logs from the last finalized block number
                    // up to the block number of the current log.
                    if !logs_in_sync {
                        let log_l1_block_number = log.block_number.map(L1BlockNumber::new_or_panic);
                        let unsynced_logs = self.get_message_logs(
                            address,
                            state_update
                                .l1_block_number
                                .expect("missing l1 block number"),
                            log_l1_block_number
                                .expect("missing l1 block number"),
                        )
                        .await?;
                        tracing::trace!(
                            number_of_logs=%unsynced_logs.len(),
                            from_block=?state_update.l1_block_number,
                            to_block=?log_l1_block_number,
                            "Fetched unsynced L1 to L2 message logs",
                        );
                        for log in unsynced_logs {
                            callback(EthereumEvent::MessageLog(log)).await;
                        }
                        logs_in_sync = true;
                    }
                    // Decode the message
                    let log: Log<StarknetCoreContract::LogMessageToL2> = log.log_decode()?;
                    // Create L1ToL2MessageHash from the log data
                    let msg = L1ToL2MessageLog {
                        message_hash: H256::from(log.inner.message_hash().to_be_bytes()),
                        l1_block_number: log.block_number.map(L1BlockNumber::new_or_panic),
                        l1_tx_hash: log.transaction_hash.map(|hash| L1TransactionHash::from(hash.0)),
                        l2_tx_hash: None,
                    };
                    // Emit the message log
                    callback(EthereumEvent::MessageLog(msg)).await;
                }
                Some(block_number) = finalized_block_rx.recv() => {
                    // Collect all state updates up to (and including) the finalized block
                    let pending_state_updates: Vec<EthereumStateUpdate> = self.pending_state_updates
                        .range(..=block_number)
                        .map(|(_, &update)| update)
                        .collect();
                    // Remove emitted updates from the map
                    self.pending_state_updates.retain(|&k, _| k > block_number);
                    // Emit the state updates
                    for state_update in pending_state_updates {
                        callback(EthereumEvent::StateUpdate(state_update)).await;
                    }
                }
            }
        }
    }

    /// Get the Starknet state
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Create the StarknetCoreContract instance
        let address = Address::new((*address).into());
        let contract = StarknetCoreContract::new(address, provider);

        // Get the finalized block hash
        let finalized_block_number = self.get_finalized_block_number().await?;
        let block_id = BlockId::Number(BlockNumberOrTag::Number(finalized_block_number.get()));

        // Call the contract methods
        let state_root = contract.stateRoot().block(block_id).call().await?;
        let block_hash = contract.stateBlockHash().block(block_id).call().await?;
        let block_number = contract.stateBlockNumber().block(block_id).call().await?;

        // Return the state update
        Ok(EthereumStateUpdate {
            state_root: get_state_root(state_root._0),
            block_hash: get_block_hash(block_hash._0),
            block_number: get_block_number(block_number._0),
            l1_block_number: Some(finalized_block_number),
        })
    }

    /// Get the Ethereum chain
    async fn get_chain(&self) -> anyhow::Result<EthereumChain> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Get the chain ID
        let chain_id = provider.get_chain_id().await?;
        let chain_id = U256::from(chain_id);

        // Map the chain ID to the corresponding Ethereum chain
        Ok(match chain_id {
            x if x == U256::from(1u32) => EthereumChain::Mainnet,
            x if x == U256::from(11155111u32) => EthereumChain::Sepolia,
            x => EthereumChain::Other(x),
        })
    }

    /// Get the L1 to L2 message logs for a given address and block range
    async fn get_message_logs(
        &self,
        address: &H160,
        from_block: L1BlockNumber,
        to_block: L1BlockNumber,
    ) -> anyhow::Result<Vec<L1ToL2MessageLog>> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Create the StarknetCoreContract instance
        let address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(address, provider.clone());

        // Create the filter
        let filter = core_contract.LogMessageToL2_filter().filter;

        // Fetch the logs
        let mut logs = Vec::new();
        get_logs_recursive(&provider, &filter, from_block, to_block, &mut logs, 10_000).await?;

        tracing::trace!(
            number_of_logs=%logs.len(),
            %from_block,
            %to_block,
            "Fetched L1ToL2MessageLog logs"
        );

        let logs: Vec<L1ToL2MessageLog> = logs
            .into_iter()
            .filter_map(|log| {
                log.log_decode::<StarknetCoreContract::LogMessageToL2>()
                    .ok()
                    .map(|decoded| L1ToL2MessageLog {
                        message_hash: H256::from(decoded.inner.message_hash().to_be_bytes()),
                        l1_block_number: log.block_number.map(L1BlockNumber::new_or_panic),
                        l1_tx_hash: log
                            .transaction_hash
                            .map(|hash| L1TransactionHash::from(hash.0)),
                        l2_tx_hash: None,
                    })
            })
            .collect();

        Ok(logs)
    }

    /// Get state updates for a given address and block range
    async fn get_state_updates(
        &self,
        address: &H160,
        from_block: L1BlockNumber,
        to_block: L1BlockNumber,
    ) -> anyhow::Result<Vec<EthereumStateUpdate>> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Create the StarknetCoreContract instance
        let address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(address, provider.clone());

        // Create the filter
        let filter = core_contract.LogStateUpdate_filter().filter;

        // Fetch the logs
        let mut logs = Vec::new();
        get_logs_recursive(&provider, &filter, from_block, to_block, &mut logs, 2_000).await?;

        let logs: Vec<EthereumStateUpdate> = logs
            .into_iter()
            .filter_map(|log| {
                log.log_decode::<StarknetCoreContract::LogStateUpdate>()
                    .ok()
                    .map(|decoded| EthereumStateUpdate {
                        state_root: get_state_root(decoded.inner.globalRoot),
                        block_hash: get_block_hash(decoded.inner.blockHash),
                        block_number: get_block_number(decoded.inner.blockNumber),
                        l1_block_number: log.block_number.map(L1BlockNumber::new_or_panic),
                    })
            })
            .collect();

        Ok(logs)
    }
}

/// Recursively fetches logs while respecting provider limits
fn get_logs_recursive<'a>(
    provider: &'a RootProvider<PubSubFrontend>,
    base_filter: &'a Filter,
    from_block: L1BlockNumber,
    to_block: L1BlockNumber,
    logs: &'a mut Vec<Log>,
    // Limits
    max_block_range: u64,
) -> futures::future::BoxFuture<'a, anyhow::Result<()>> {
    async move {
        // Nothing to do
        if from_block > to_block {
            return Ok(());
        }

        // If the block range exceeds the maximum, split it
        let block_range = to_block.get() - from_block.get() + 1;
        if block_range > max_block_range {
            let mid_block = from_block + block_range / 2;
            get_logs_recursive(
                provider,
                base_filter,
                from_block,
                mid_block - 1,
                logs,
                max_block_range,
            )
            .await?;
            get_logs_recursive(
                provider,
                base_filter,
                mid_block,
                to_block,
                logs,
                max_block_range,
            )
            .await?;

            return Ok(());
        }

        // Adjust the base filter to the current block range
        let from_block_id = BlockNumberOrTag::Number(from_block.get());
        let to_block_id = BlockNumberOrTag::Number(to_block.get());
        let filter = (*base_filter)
            .clone()
            .from_block(from_block_id)
            .to_block(to_block_id);

        // Attempt to fetch the logs
        let result = provider.get_logs(&filter).await;
        match result {
            Ok(new_logs) => {
                logs.extend(new_logs);
            }
            Err(e) => {
                tracing::debug!(%from_block, error=?e, "Get logs error at block");
                if let Some(err) = e.as_error_resp() {
                    // Retry the request splitting the block range in half
                    //
                    // Multiple providers have multiple restrictions. The max range limit can help
                    // with the obvious restrictions, but not with those that depend on the response
                    // size. And because there's no way we can predict this, retrying with a smaller
                    // range is the best we can do.
                    if err.is_retry_err() {
                        tracing::debug!(
                            %from_block,
                            error=?err,
                            "Retrying request (splitting) at block"
                        );
                        let mid_block = from_block + block_range / 2;
                        get_logs_recursive(
                            provider,
                            base_filter,
                            from_block,
                            mid_block - 1,
                            logs,
                            max_block_range,
                        )
                        .await?;
                        get_logs_recursive(
                            provider,
                            base_filter,
                            mid_block,
                            to_block,
                            logs,
                            max_block_range,
                        )
                        .await?;
                        return Ok(());
                    } else {
                        tracing::error!(
                            %from_block,
                            error=?err,
                            "get_logs provider error"
                        );
                    }
                } else {
                    tracing::error!(
                        %from_block,
                        error=?e,
                        "get_logs: Unknown error"
                    );
                }
            }
        }

        Ok(())
    }
    .boxed()
}
