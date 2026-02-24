use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::network::Ethereum;
use alloy::primitives::{Address, TxHash};
use alloy::providers::fillers::{
    BlobGasFiller,
    ChainIdFiller,
    FillProvider,
    GasFiller,
    JoinFill,
    NonceFiller,
};
use alloy::providers::{Identity, Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::{FilteredParams, Log};
use anyhow::Context;
use pathfinder_common::prelude::*;
use pathfinder_common::transaction::L1HandlerTransaction;
use pathfinder_common::{EthereumChain, L1BlockHash, L1BlockNumber, L1TransactionHash};
use pathfinder_crypto::Felt;
use primitive_types::{H160, U256};
use reqwest::{IntoUrl, Url};
use starknet::StarknetCoreContract;
use tokio::select;
use tokio::time::MissedTickBehavior;

use crate::utils::*;

mod starknet;
mod utils;

/// Type alias for the WebSocket provider returned by alloy when calling
/// `ProviderBuilder::new().connect_ws()`
type WsProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider<Ethereum>,
>;

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

/// State update from Ethereum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EthereumStateUpdate {
    pub state_root: StateCommitment,
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
}

/// Gas price data extracted from an L1 block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L1GasPriceData {
    /// The L1 block number
    pub block_number: L1BlockNumber,
    /// The block's own hash
    pub block_hash: L1BlockHash,
    /// The parent block's hash (used for reorg detection)
    pub parent_hash: L1BlockHash,
    /// Unix timestamp of the block
    pub timestamp: u64,
    /// EIP-1559 base fee per gas (wei)
    pub base_fee_per_gas: u128,
    /// EIP-4844 blob fee per gas (wei)
    pub blob_fee: u128,
}

/// Computes the blob fee from excess_blob_gas
fn compute_blob_fee(excess_blob_gas: Option<u64>) -> u128 {
    excess_blob_gas
        .map(alloy::eips::eip4844::calc_blob_gasprice)
        .unwrap_or(alloy::eips::eip4844::BLOB_TX_MIN_BLOB_GASPRICE)
}

/// Ethereum client
#[derive(Clone)]
pub struct EthereumClient {
    url: Url,
    /// Lazily initialized WebSocket connection for query methods (get_chain,
    /// get_starknet_state, etc.). Note: `sync_and_listen` uses its own
    /// dedicated connection for subscriptions.
    provider: Arc<RwLock<Option<WsProvider>>>,
    pending_state_updates: BTreeMap<L1BlockNumber, EthereumStateUpdate>,
}

impl std::fmt::Debug for EthereumClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthereumClient")
            .field("url", &self.url)
            .field("provider", &"<WsProvider>")
            .field("pending_state_updates", &self.pending_state_updates)
            .finish()
    }
}

impl EthereumClient {
    /// Creates a new [EthereumClient]
    pub fn new<U: IntoUrl>(url: U) -> anyhow::Result<Self> {
        Ok(Self {
            url: url.into_url()?,
            provider: Arc::new(RwLock::new(None)),
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

    /// Gets or creates the shared WebSocket provider for query methods.
    async fn provider(&self) -> anyhow::Result<WsProvider> {
        {
            let lock = self.provider.read().unwrap();
            // If a provider exists, return it
            if let Some(provider) = lock.as_ref() {
                return Ok(provider.clone());
            }
        }

        // Create a new WebSocket provider
        let ws = WsConnect::new(self.url.clone());
        let new_provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .context("Failed to establish WebSocket connection to Ethereum node")?;

        let mut lock = self.provider.write().unwrap();
        *lock = Some(new_provider.clone());
        Ok(new_provider)
    }

    /// Returns the block number of the last finalized block
    pub async fn get_finalized_block_number(&self) -> anyhow::Result<L1BlockNumber> {
        let provider = self.provider().await?;
        provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?
            .map(|block| L1BlockNumber::new_or_panic(block.header.number))
            .context("Failed to fetch finalized block hash")
    }

    /// Returns the block number of the latest block
    pub async fn get_latest_block_number(&self) -> anyhow::Result<L1BlockNumber> {
        let provider = self.provider().await?;
        provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .map(|block| L1BlockNumber::new_or_panic(block.header.number))
            .context("Failed to fetch latest block")
    }

    /// Fetches gas price data from a specific L1 block header.
    pub async fn get_gas_price_data(
        &self,
        block_number: L1BlockNumber,
    ) -> anyhow::Result<L1GasPriceData> {
        let provider = self.provider().await?;
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number.get()))
            .await?
            .context("Block not found")?;

        let block_hash = L1BlockHash::from(block.header.hash.0);
        let parent_hash = L1BlockHash::from(block.header.parent_hash.0);
        let base_fee_per_gas = block.header.base_fee_per_gas.unwrap_or(0) as u128;
        let blob_fee = compute_blob_fee(block.header.excess_blob_gas);

        Ok(L1GasPriceData {
            block_number,
            block_hash,
            parent_hash,
            timestamp: block.header.timestamp,
            base_fee_per_gas,
            blob_fee,
        })
    }

    /// Fetches gas price data for a range of blocks (inclusive).
    ///
    /// We use this to initialize our gas price buffer. After initialization we
    /// subscribe to latest updates via subscribe_block_headers.
    pub async fn get_gas_price_data_range(
        &self,
        start: L1BlockNumber,
        end: L1BlockNumber,
    ) -> anyhow::Result<Vec<L1GasPriceData>> {
        let mut results = Vec::with_capacity((end.get() - start.get() + 1) as usize);

        for block_num in start.get()..=end.get() {
            let block_number = L1BlockNumber::new_or_panic(block_num);
            let data = self
                .get_gas_price_data(block_number)
                .await
                .with_context(|| format!("Fetching gas price data for block {block_num}"))?;
            results.push(data);
        }

        Ok(results)
    }

    /// Subscribes to new block headers and sends gas price data to the
    /// provided channel for each block as it arrives.
    ///
    /// This uses a dedicated WebSocket connection for the subscription stream.
    /// Re-subscribes automatically if the stream ends due to errors.
    /// Returns `Ok(())` if the receiver is dropped (clean shutdown).
    /// Returns `Err` if the WebSocket connection cannot be re-established.
    pub async fn subscribe_block_headers(
        &self,
        tx: tokio::sync::mpsc::Sender<L1GasPriceData>,
    ) -> anyhow::Result<()> {
        // Create a dedicated WebSocket connection for subscriptions
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

        // Subscribe to new block headers
        let mut block_stream = provider.subscribe_blocks().await?;

        loop {
            match block_stream.recv().await {
                Ok(header) => {
                    let data = L1GasPriceData {
                        block_number: L1BlockNumber::new_or_panic(header.number),
                        block_hash: L1BlockHash::from(header.hash.0),
                        parent_hash: L1BlockHash::from(header.parent_hash.0),
                        timestamp: header.timestamp,
                        base_fee_per_gas: header.base_fee_per_gas.unwrap_or(0) as u128,
                        blob_fee: compute_blob_fee(header.excess_blob_gas),
                    };
                    if tx.send(data).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Block subscription ended, re-subscribing");
                    block_stream = provider.subscribe_blocks().await?;
                }
            }
        }
    }
}

impl EthereumClient {
    /// Listens for Ethereum events and notifies the caller using the provided
    /// callback. State updates will only be emitted once they belong to a
    /// finalized block.
    pub async fn sync_and_listen<F, Fut>(
        &mut self,
        address: &H160,
        poll_interval: Duration,
        callback: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(EthereumStateUpdate) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // This method maintains its own dedicated WebSocket connection for
        // subscriptions. We keep it separate from the shared query connection
        // because:
        // 1. Subscriptions are long-lived and stream events continuously
        // 2. Isolates subscription failures from query failures
        // 3. Simplifies reconnection logic (no need to re-establish subscriptions)
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

        // Fetch the current Starknet state from Ethereum
        let state_update = self.get_starknet_state(address).await?;
        let _ = callback(state_update).await;

        // Create the StarknetCoreContract instance
        let core_address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(core_address, provider.clone());

        // Listen for state update events
        let filter = core_contract.LogStateUpdate_filter().filter;
        let mut state_updates = provider.subscribe_logs(&filter).await?;

        // Poll regularly for finalized block number
        let provider_clone = provider.clone();
        let (finalized_block_tx, mut finalized_block_rx) =
            tokio::sync::mpsc::channel::<L1BlockNumber>(1);

        util::task::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;

                match provider_clone
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await
                {
                    Ok(Some(finalized_block)) => {
                        let block_number =
                            L1BlockNumber::new_or_panic(finalized_block.header.number);
                        if finalized_block_tx.send(block_number).await.is_err() {
                            tracing::debug!("L1 finalized block channel closed");
                            return;
                        }
                    }
                    Ok(None) => {
                        tracing::error!("No L1 finalized block found");
                    }
                    Err(e) => {
                        tracing::error!(error=%e, "Error fetching L1 finalized block");
                        return;
                    }
                }
            }
        });

        // Process incoming events
        loop {
            select! {
                maybe_state_update = state_updates.recv() => {
                    match maybe_state_update {
                        Ok(state_update) => {
                            tracing::trace!(?state_update, "Processing LogStateUpdate event");
                            // one would expect this to always be true, but in fact it isn't...
                            if filter.address.matches(&state_update.inner.address) {
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
                                    };
                                    self.pending_state_updates.insert(eth_block, state_update);
                                } else {
                                    self.pending_state_updates.remove(&eth_block);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error=%e, "LogStateUpdate stream ended, re-subscribing");
                            state_updates = provider.subscribe_logs(&filter).await?;
                        }
                    }
                }
                maybe_block_number = finalized_block_rx.recv() => {
                    match maybe_block_number {
                        Some(block_number) => {
                            tracing::trace!(%block_number, "Processing L1 finalized block");
                            // Collect all state updates up to (and including) the finalized block
                            let pending_state_updates: Vec<EthereumStateUpdate> = self.pending_state_updates
                                .range(..=block_number)
                                .map(|(_, &update)| update)
                                .collect();
                            // Remove emitted updates from the map
                            self.pending_state_updates.retain(|&k, _| k > block_number);
                            // Emit the state updates
                            for state_update in pending_state_updates {
                                let _ = callback(state_update).await;
                            }
                        }
                        None => {
                            tracing::debug!("L1 finalized block channel closed");
                            anyhow::bail!("L1 finalized block channel closed");
                        }
                    }
                }
            }
        }
    }

    pub async fn get_l1_handler_txs(
        &self,
        address: &H160,
        tx_hash: &L1TransactionHash,
    ) -> anyhow::Result<Vec<L1HandlerTransaction>> {
        let provider = self.provider().await?;

        let core_address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(core_address, provider.clone());
        let filter = FilteredParams::new(Some(core_contract.LogMessageToL2_filter().filter));

        let tx_hash = TxHash::from_slice(tx_hash.as_bytes());
        if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
            let logs: Vec<Log<StarknetCoreContract::LogMessageToL2>> = receipt
                .inner
                .logs()
                .iter()
                .filter(|log| {
                    filter.filter_address(&log.address()) && filter.filter_topics(log.topics())
                })
                .filter_map(|log| {
                    log.log_decode::<StarknetCoreContract::LogMessageToL2>()
                        .ok()
                })
                .collect();

            let mut l1_handler_txs = Vec::new();
            for log in logs {
                let nonce: [u8; 32] = log.inner.nonce.to_be_bytes();
                let to_addr: [u8; 32] = log.inner.toAddress.to_be_bytes();
                let from_addr: [u8; 20] = log.inner.fromAddress.0.into();
                let selector: [u8; 32] = log.inner.selector.to_be_bytes();

                let felt_nonce = Felt::from(nonce);
                let felt_to_addr = Felt::from(to_addr);
                let felt_from_addr = Felt::from_be_slice(&from_addr)?;
                let felt_selector = Felt::from(selector);

                let payload: Vec<CallParam> = log
                    .inner
                    .payload
                    .iter()
                    .map(|p| p.to_be_bytes::<32>())
                    .map(Felt::from)
                    .map(CallParam)
                    .collect();

                let mut call_data: Vec<CallParam> = vec![CallParam(felt_from_addr)];
                call_data.extend(payload);

                // Create the L1HandlerTransaction
                let tx = L1HandlerTransaction {
                    contract_address: ContractAddress(felt_to_addr),
                    entry_point_selector: EntryPoint(felt_selector),
                    nonce: TransactionNonce(felt_nonce),
                    calldata: call_data,
                };
                l1_handler_txs.push(tx);
            }

            Ok(l1_handler_txs)
        } else {
            Err(anyhow::anyhow!("Transaction not found"))
        }
    }

    /// Get the Starknet state
    pub async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate> {
        let provider = self.provider().await?;

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
            state_root: get_state_root(state_root),
            block_hash: get_block_hash(block_hash),
            block_number: get_block_number(block_number),
        })
    }

    /// Get the Ethereum chain
    pub async fn get_chain(&self) -> anyhow::Result<EthereumChain> {
        let provider = self.provider().await?;
        let chain_id = provider.get_chain_id().await?;
        let chain_id = U256::from(chain_id);

        // Map the chain ID to the corresponding Ethereum chain
        Ok(match chain_id {
            x if x == U256::from(1u32) => EthereumChain::Mainnet,
            x if x == U256::from(11155111u32) => EthereumChain::Sepolia,
            x => EthereumChain::Other(x),
        })
    }
}
