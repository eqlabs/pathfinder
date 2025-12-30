use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use alloy::eips::eip4844::BLOB_TX_MIN_BLOB_GASPRICE;
use alloy::eips::{eip4844, BlockId, BlockNumberOrTag};
use alloy::primitives::{Address, TxHash};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::{FilteredParams, Log};
use anyhow::Context;
use pathfinder_common::prelude::*;
use pathfinder_common::transaction::L1HandlerTransaction;
use pathfinder_common::{
    EthereumChain,
    L1BlockHash,
    L1BlockHeader,
    L1BlockNumber,
    L1TransactionHash,
};
use pathfinder_crypto::Felt;
use primitive_types::{H160, U256};
use reqwest::{IntoUrl, Url};
use starknet::StarknetCoreContract;
use tokio::select;
use tokio::time::MissedTickBehavior;

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

/// State update from Ethereum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EthereumStateUpdate {
    pub state_root: StateCommitment,
    pub block_number: BlockNumber,
    pub block_hash: BlockHash,
}

/// Ethereum API trait
pub trait EthereumApi {
    fn get_starknet_state(
        &self,
        address: &H160,
    ) -> impl Future<Output = anyhow::Result<EthereumStateUpdate>>;
    fn get_chain(&self) -> impl Future<Output = anyhow::Result<EthereumChain>>;
    fn get_l1_handler_txs(
        &self,
        address: &H160,
        tx_hash: &L1TransactionHash,
    ) -> impl Future<Output = anyhow::Result<Vec<L1HandlerTransaction>>>;
    fn get_block_header(
        &self,
        block_number: L1BlockNumber,
    ) -> impl Future<Output = anyhow::Result<Option<L1BlockHeader>>>;
    fn get_finalized_block_number(&self) -> impl Future<Output = anyhow::Result<L1BlockNumber>>;
    fn sync_and_listen<F, Fut>(
        &mut self,
        address: &H160,
        poll_interval: Duration,
        callback: F,
    ) -> impl Future<Output = anyhow::Result<()>>
    where
        F: Fn(EthereumStateUpdate) -> Fut + Send + 'static,
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
}

impl EthereumApi for EthereumClient {
    /// Listens for Ethereum events and notifies the caller using the provided
    /// callback. State updates will only be emitted once they belong to a
    /// finalized block.
    async fn sync_and_listen<F, Fut>(
        &mut self,
        address: &H160,
        poll_interval: Duration,
        callback: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(EthereumStateUpdate) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Create a WebSocket connection
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

    async fn get_l1_handler_txs(
        &self,
        address: &H160,
        tx_hash: &L1TransactionHash,
    ) -> anyhow::Result<Vec<L1HandlerTransaction>> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

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
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

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
    async fn get_chain(&self) -> anyhow::Result<EthereumChain> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

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

    /// Fetches an L1 block header with gas price information
    async fn get_block_header(
        &self,
        block_number: L1BlockNumber,
    ) -> anyhow::Result<Option<L1BlockHeader>> {
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .context("Failed to connect to Ethereum RPC")?;

        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number.get()))
            .await
            .context("Failed to fetch block from Ethereum RPC")?;

        let Some(block) = block else {
            return Ok(None);
        };

        let header = &block.header.inner;

        // Extract gas price fields from the inner header
        let base_fee_per_gas = header.base_fee_per_gas.map(|fee| fee as u128).unwrap_or(0);

        // EIP-4844 blob gas price calculation
        let blob_fee = header
            .excess_blob_gas
            .map(eip4844::calc_blob_gasprice)
            .unwrap_or(BLOB_TX_MIN_BLOB_GASPRICE);

        // Convert B256 to L1BlockHash for hash fields
        let hash_bytes: [u8; 32] = block.header.hash.into();
        let parent_hash_bytes: [u8; 32] = header.parent_hash.into();

        Ok(Some(L1BlockHeader {
            number: L1BlockNumber::new_or_panic(header.number),
            timestamp: BlockTimestamp::new_or_panic(header.timestamp),
            hash: L1BlockHash::from_slice(&hash_bytes),
            parent_hash: L1BlockHash::from_slice(&parent_hash_bytes),
            base_fee_per_gas: GasPrice(base_fee_per_gas),
            blob_fee: GasPrice(blob_fee),
        }))
    }

    async fn get_finalized_block_number(&self) -> anyhow::Result<L1BlockNumber> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .context("Failed to connect to Ethereum RPC")?;
        // Fetch the finalized block number
        provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .context("Failed to fetch finalized block")?
            .map(|block| L1BlockNumber::new_or_panic(block.header.number))
            .context("Finalized block not found")
    }
}
