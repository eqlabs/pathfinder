//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{collections::HashSet, sync::Arc, time::Duration};

use libp2p::PeerId;
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use tokio::sync::RwLock;

use crate::{client::peer_aware, peers};

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: String,
    peers_with_sync_capability: Arc<RwLock<HashSet<PeerId>>>,
    last_update: Arc<RwLock<std::time::Instant>>,
    // FIXME
    _peers: Arc<RwLock<peers::Peers>>,
}
// FIXME make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity
impl Client {
    pub fn new(
        inner: peer_aware::Client,
        block_propagation_topic: String,
        peers: Arc<RwLock<peers::Peers>>,
    ) -> Self {
        Self {
            inner,
            block_propagation_topic,
            peers_with_sync_capability: Default::default(),
            last_update: Arc::new(RwLock::new(
                std::time::Instant::now()
                    .checked_sub(Duration::from_secs(55))
                    .unwrap(),
            )),
            _peers: peers,
        }
    }

    // Propagate new L2 head head
    pub async fn propagate_new_head(
        &self,
        block_id: p2p_proto_v1::common::BlockId,
    ) -> anyhow::Result<()> {
        tracing::debug!(number=%block_id.number, hash=%block_id.hash.0, topic=%self.block_propagation_topic,
            "Propagating head"
        );

        self.inner
            .publish(
                &self.block_propagation_topic,
                p2p_proto_v1::block::NewBlock::Id(block_id),
            )
            .await
    }

    async fn get_update_peers_with_sync_capability(&self) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        if self.last_update.read().await.clone().elapsed() > Duration::from_secs(60) {
            let mut peers = self
                .inner
                .get_capability_providers("core/blocks-sync/1")
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(&self.inner.peer_id());
            debug_assert!(_i_should_have_the_capability_too);

            let mut peers_with_sync_capability = self.peers_with_sync_capability.write().await;
            *peers_with_sync_capability = peers;

            let mut last_update = self.last_update.write().await;
            *last_update = std::time::Instant::now();
        }

        let peers_with_sync_capability = self.peers_with_sync_capability.read().await;
        let mut peers = peers_with_sync_capability
            .iter()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    pub async fn block_headers(
        &self,
        start_block: BlockNumber,
        num_blocks: usize,
    ) -> Option<Vec<p2p_proto_v0::common::BlockHeader>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self.inner.send_sync_request(peer, todo!("use v1")).await;

            match response {
                Ok(_) => {
                    todo!("use v1");
                    tracing::debug!(%peer, "Got unexpected response to GetBlockHeaders");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetBlockHeaders failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block, %num_blocks, "No peers with block headers found for");

        None
    }

    pub async fn block_bodies(
        &self,
        start_block_hash: BlockHash, // FIXME, hash to avoid DB lookup
        num_blocks: usize,           // FIXME, use range?
    ) -> Option<Vec<p2p_proto_v0::common::BlockBody>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self.inner.send_sync_request(peer, todo!("use v1")).await;

            match response {
                Ok(_) => {
                    todo!("use v1");
                    tracing::debug!(%peer, "Got unexpected response to GetBlockBodies");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetBlockBodies failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block_hash, %num_blocks, "No peers with block bodies found for");

        None
    }

    pub async fn state_updates(
        &self,
        start_block_hash: BlockHash, // FIXME, hash to avoid DB lookup
        num_blocks: usize,           // FIXME, use range?
    ) -> Option<Vec<p2p_proto_v0::sync::BlockStateUpdateWithHash>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self.inner.send_sync_request(peer, todo!("use v1")).await;
            match response {
                Ok(_) => {
                    todo!("use v1");
                    tracing::debug!(%peer, "Got unexpected response to GetStateDiffs");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetStateDiffs failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block_hash, %num_blocks, "No peers with state updates found for");

        None
    }

    pub async fn contract_classes(
        &self,
        class_hashes: Vec<ClassHash>,
    ) -> Option<p2p_proto_v0::sync::Classes> {
        if class_hashes.is_empty() {
            return Some(p2p_proto_v0::sync::Classes {
                classes: Vec::new(),
            });
        }

        let class_hashes = class_hashes.into_iter().map(|x| x.0).collect::<Vec<_>>();

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self.inner.send_sync_request(peer, todo!("use v1")).await;
            match response {
                Ok(_) => {
                    todo!("use v1");
                    tracing::debug!(%peer, "Got unexpected response to GetClasses");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetStateDiffs failed");
                    continue;
                }
            }
        }

        tracing::debug!(?class_hashes, "No peers with classes found for");

        None
    }
}
