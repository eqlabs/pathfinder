use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use alloy::eips::{BlockId, BlockNumberOrTag, RpcBlockHash};
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Log;
use anyhow::Context;
use futures::StreamExt;
use pathfinder_common::{BlockHash, BlockNumber, EthereumChain, L1ToL2MessageLog, StateCommitment};
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
}

/// Ethereum API trait
#[async_trait::async_trait]
pub trait EthereumApi {
    async fn get_starknet_state(&self, address: &H160) -> anyhow::Result<EthereumStateUpdate>;
    async fn get_chain(&self) -> anyhow::Result<EthereumChain>;
    async fn listen<F, Fut>(
        &mut self,
        address: &H160,
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
    pending_state_updates: BTreeMap<u64, EthereumStateUpdate>,
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

    /// Returns the hash of the last finalized block
    async fn get_finalized_block_hash(&self) -> anyhow::Result<H256> {
        // Create a WebSocket connection
        let ws = WsConnect::new(self.url.clone());
        let provider = ProviderBuilder::new().on_ws(ws).await?;

        // Fetch the finalized block hash
        provider
            .get_block_by_number(BlockNumberOrTag::Finalized, false)
            .await?
            .map(|block| {
                let block_hash: [u8; 32] = block.header.hash.into();
                H256::from(block_hash)
            })
            .context("Failed to fetch finalized block hash")
    }
}

#[async_trait::async_trait]
impl EthereumApi for EthereumClient {
    /// Listens for Ethereum events and notifies the caller using the provided
    /// callback. State updates will only be emitted once they belong to a
    /// finalized block.
    async fn listen<F, Fut>(
        &mut self,
        address: &H160,
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

        // Create the StarknetCoreContract instance
        let address = Address::new((*address).into());
        let core_contract = StarknetCoreContract::new(address, provider.clone());

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
            tokio::sync::mpsc::channel::<BlockNumber>(1);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            loop {
                interval.tick().await;
                if let Ok(Some(finalized_block)) = provider_clone
                    .get_block_by_number(BlockNumberOrTag::Finalized, false)
                    .await
                {
                    let block_number = BlockNumber::new_or_panic(finalized_block.header.number);
                    let _ = finalized_block_tx.send(block_number).await.unwrap();
                }
            }
        });

        // Add the finalized block stream to the select! macro
        loop {
            select! {
                Some(state_update) = state_updates.next() => {
                    // Decode the state update
                    let eth_block = state_update.block_number.expect("missing eth block number");
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
                Some(log) = logs.next() => {
                    // Decode the message
                    let log: Log<StarknetCoreContract::LogMessageToL2> = log.log_decode()?;
                    // Create L1ToL2MessageHash from the log data
                    let msg = L1ToL2MessageLog {
                        message_hash: H256::from(log.inner.message_hash().to_be_bytes()),
                        l1_tx_hash: log.transaction_hash.map(|hash| H256::from(hash.0)).unwrap_or_default(),
                    };
                    // Emit the message log
                    callback(EthereumEvent::MessageLog(msg)).await;
                }
                Some(block_number) = finalized_block_rx.recv() => {
                    // Collect all state updates up to (and including) the finalized block
                    let pending_state_updates: Vec<EthereumStateUpdate> = self.pending_state_updates
                        .range(..=block_number.get())
                        .map(|(_, &update)| update)
                        .collect();
                    // Remove emitted updates from the map
                    self.pending_state_updates.retain(|&k, _| k > block_number.get());
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
        let finalized_block_hash = self.get_finalized_block_hash().await?;
        let block_hash = B256::from(finalized_block_hash.0);
        let block_id = BlockId::Hash(RpcBlockHash::from_hash(block_hash, None));

        // Call the contract methods
        let state_root = contract.stateRoot().block(block_id).call().await?;
        let block_hash = contract.stateBlockHash().block(block_id).call().await?;
        let block_number = contract.stateBlockNumber().block(block_id).call().await?;

        // Return the state update
        Ok(EthereumStateUpdate {
            state_root: get_state_root(state_root._0),
            block_hash: get_block_hash(block_hash._0),
            block_number: get_block_number(block_number._0),
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
}
