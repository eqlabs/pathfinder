#![allow(dead_code, unused)]

use core::panic;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use error::SyncError;
use futures::{pin_mut, Stream, StreamExt};
use p2p::client::peer_agnostic::Client as P2PClient;
use p2p::PeerData;
use pathfinder_common::error::AnyhowExt;
use pathfinder_common::{
    block_hash,
    BlockHash,
    BlockNumber,
    Chain,
    ChainId,
    PublicKey,
    StarknetVersion,
};
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_storage::Transaction;
use primitive_types::H160;
use starknet_gateway_client::{Client as GatewayClient, GatewayApi};
use stream::ProcessStage;
use tokio::sync::watch::{self, Receiver};
use tokio_stream::wrappers::WatchStream;

use crate::state::RESET_DELAY_ON_FAILURE;

mod checkpoint;
mod class_definitions;
mod error;
mod events;
mod headers;
mod state_updates;
mod storage_adapters;
mod stream;
mod track;
mod transactions;

const CHECKPOINT_MARGIN: u64 = 10;

pub struct Sync {
    pub storage: pathfinder_storage::Storage,
    pub p2p: P2PClient,
    pub eth_client: pathfinder_ethereum::EthereumClient,
    pub eth_address: H160,
    pub fgw_client: GatewayClient,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub public_key: PublicKey,
    pub l1_checkpoint_override: Option<EthereumStateUpdate>,
    pub verify_tree_hashes: bool,
}

impl Sync {
    pub async fn run(self) -> anyhow::Result<()> {
        let (next, parent_hash) = self.checkpoint_sync().await?;

        // TODO: depending on how this is implemented, we might want to loop around it.
        self.track_sync(next, parent_hash).await
    }

    async fn handle_recoverable_error(&self, err: &error::SyncError) {
        // TODO
        tracing::debug!(%err, "Log and punish as appropriate");
    }

    /// Retry forever until a valid L1 checkpoint is retrieved
    ///
    /// ### Important
    ///
    /// We assume that the L1 endpoint is configured correctly and any L1 API
    /// errors are transient. We cannot proceed without a checkpoint, so we
    /// retry until we get one.
    async fn get_checkpoint(&self) -> pathfinder_ethereum::EthereumStateUpdate {
        use pathfinder_ethereum::EthereumApi;
        if let Some(forced) = &self.l1_checkpoint_override {
            return *forced;
        }

        loop {
            match self.eth_client.get_starknet_state(&self.eth_address).await {
                Ok(latest) => return latest,
                Err(error) => {
                    tracing::warn!(%error, "Failed to get L1 checkpoint, retrying");
                    tokio::time::sleep(RESET_DELAY_ON_FAILURE);
                }
            }
        }
    }

    /// Run checkpoint sync until it completes successfully, and we are within
    /// some margin of the latest L1 block. Returns the next block number to
    /// sync and its parent hash.
    ///
    /// ### Important
    ///
    /// Sync is restarted on recoverable errors and only fatal errors (e.g.:
    /// database failure, runtime failure, etc.) cause this function to exit
    /// with an error.
    async fn checkpoint_sync(&self) -> anyhow::Result<(BlockNumber, BlockHash)> {
        let mut checkpoint = self.get_checkpoint().await;

        loop {
            let result = checkpoint::Sync {
                storage: self.storage.clone(),
                p2p: self.p2p.clone(),
                eth_client: self.eth_client.clone(),
                eth_address: self.eth_address,
                fgw_client: self.fgw_client.clone(),
                chain: self.chain,
                chain_id: self.chain_id,
                public_key: self.public_key,
                verify_tree_hashes: self.verify_tree_hashes,
                block_hash_db: Some(pathfinder_block_hashes::BlockHashDb::new(self.chain)),
            }
            .run(checkpoint)
            .await;

            // Handle the error
            let continue_from = match result {
                Ok(continue_from) => {
                    tracing::debug!(?continue_from, "Checkpoint sync complete");
                    continue_from
                }
                Err(SyncError::Fatal(mut error)) => {
                    tracing::error!(?error, "Stopping checkpoint sync");
                    return Err(error.take_or_deep_clone());
                }
                Err(error) => {
                    tracing::debug!(?error, "Restarting checkpoint sync");
                    self.handle_recoverable_error(&error).await;
                    continue;
                }
            };

            // Initial sync might take so long that the latest checkpoint is actually far
            // ahead again. Repeat until we are within some margin of L1.
            let latest_checkpoint = self.get_checkpoint().await;
            if checkpoint.block_number + CHECKPOINT_MARGIN < latest_checkpoint.block_number {
                checkpoint = latest_checkpoint;
                tracing::debug!(
                    local_checkpoint=%checkpoint.block_number, latest_checkpoint=%latest_checkpoint.block_number,
                    "Restarting checkpoint sync: L1 checkpoint has advanced"
                );
                continue;
            }

            break Ok(continue_from);
        }
    }

    /// Run the track sync forever, requires the number and parent hash of the
    /// first block to sync.
    ///
    /// ### Important
    ///
    /// Sync is restarted on recoverable errors and only fatal errors (e.g.:
    /// database failure, runtime failure, etc.) cause this function to exit
    /// with an error.
    async fn track_sync(
        &self,
        mut next: BlockNumber,
        mut parent_hash: BlockHash,
    ) -> anyhow::Result<()> {
        loop {
            let mut result = track::Sync {
                latest: LatestStream::spawn(self.fgw_client.clone(), Duration::from_secs(2)),
                p2p: self.p2p.clone(),
                storage: self.storage.clone(),
                chain: self.chain,
                chain_id: self.chain_id,
                public_key: self.public_key,
                block_hash_db: Some(pathfinder_block_hashes::BlockHashDb::new(self.chain)),
                verify_tree_hashes: self.verify_tree_hashes,
            }
            .run(next, parent_hash, self.fgw_client.clone())
            .await;

            match result {
                Ok(_) => tracing::debug!("Restarting track sync: unexpected end of Block stream"),
                Err(SyncError::Fatal(mut error)) => {
                    tracing::error!(?error, "Stopping track sync");
                    use pathfinder_common::error::AnyhowExt;
                    return Err(error.take_or_deep_clone());
                }
                Err(error) => {
                    tracing::debug!(?error, "Restarting track sync");
                    self.handle_recoverable_error(&error).await;
                }
            }
        }
    }
}

struct LatestStream {
    rx: Receiver<(BlockNumber, BlockHash)>,
    stream: WatchStream<(BlockNumber, BlockHash)>,
}

impl Clone for LatestStream {
    fn clone(&self) -> Self {
        tracing::info!("LatestStream: clone()");

        Self {
            // Keep the rx for the next clone
            rx: self.rx.clone(),
            // Create a new stream from the cloned rx, don't yield the initial value
            stream: WatchStream::from_changes(self.rx.clone()),
        }
    }
}

impl Stream for LatestStream {
    type Item = (BlockNumber, BlockHash);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let stream = &mut self.stream;
        pin_mut!(stream);
        stream.poll_next(cx)
    }
}

impl LatestStream {
    fn spawn(fgw: GatewayClient, head_poll_interval: Duration) -> Self {
        tracing::info!("LatestStream: spawn()");
        // No buffer, for backpressure
        let (tx, rx) = watch::channel((BlockNumber::GENESIS, BlockHash::ZERO));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(head_poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;

                let Ok(latest) = fgw
                    .block_header(pathfinder_common::BlockId::Latest)
                    .await
                    .inspect_err(|e| tracing::debug!(error=%e, "Error requesting latest block ID"))
                else {
                    continue;
                };

                tracing::info!(?latest, "LatestStream: block_header()");

                if tx.send(latest).is_err() {
                    tracing::debug!("Channel closed, exiting");
                    break;
                }
            }
        });

        Self {
            rx: rx.clone(),
            stream: WatchStream::from_changes(rx),
        }
    }
}
