#![allow(dead_code, unused)]

use core::panic;
use std::time::Duration;

use anyhow::Context;
use error::SyncError2;
use futures::{pin_mut, Stream, StreamExt};
use p2p::client::peer_agnostic::Client as P2PClient;
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

    async fn handle_error(&self, err: error::SyncError) {
        // TODO
        tracing::debug!(?err, "Log and punish as appropriate");
    }

    async fn get_checkpoint(&self) -> anyhow::Result<pathfinder_ethereum::EthereumStateUpdate> {
        use pathfinder_ethereum::EthereumApi;
        match &self.l1_checkpoint_override {
            Some(checkpoint) => Ok(*checkpoint),
            None => self
                .eth_client
                .get_starknet_state(&self.eth_address)
                .await
                .context("Fetching latest L1 checkpoint"),
        }
    }

    /// Run checkpoint sync until it completes successfully, and we are within
    /// some margin of the latest L1 block. Returns the next block number to
    /// sync and its parent hash.
    async fn checkpoint_sync(&self) -> anyhow::Result<(BlockNumber, BlockHash)> {
        let mut checkpoint = self.get_checkpoint().await?;

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
            }
            .run(checkpoint)
            .await;

            // Handle the error
            if let Err(err) = result {
                self.handle_error(err).await;
                continue;
            }

            // Initial sync might take so long, that the latest checkpoint is actually far
            // ahead again. Repeat until we are within some margin of L1.
            let latest_checkpoint = self.get_checkpoint().await?;
            if checkpoint.block_number + CHECKPOINT_MARGIN < latest_checkpoint.block_number {
                checkpoint = latest_checkpoint;
                continue;
            }

            break;
        }

        Ok((checkpoint.block_number + 1, checkpoint.block_hash))
    }

    /// Run the track sync until it completes successfully, requires the
    /// number and parent hash of the first block to sync
    async fn track_sync(&self, next: BlockNumber, parent_hash: BlockHash) -> anyhow::Result<()> {
        let result = track::Sync {
            latest: LatestStream::spawn(self.fgw_client.clone(), Duration::from_secs(2)),
            p2p: self.p2p.clone(),
            storage: self.storage.clone(),
            chain: self.chain,
            chain_id: self.chain_id,
            public_key: self.public_key,
        }
        .run(next, parent_hash, self.fgw_client.clone())
        .await;

        tracing::info!("Track sync completed: {result:#?}");

        Ok(())
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
