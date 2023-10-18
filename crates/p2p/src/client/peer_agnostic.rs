//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId;
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use tokio::sync::RwLock;

use crate::sync::protocol;
use crate::{client::peer_aware, peers};

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: String,
    peers_with_capability: Arc<RwLock<PeersWithCapability>>,
    // FIXME
    _peers: Arc<RwLock<peers::Peers>>,
}

// TODO Rework the API!
// I.e. make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity.
impl Client {
    pub fn new(
        inner: peer_aware::Client,
        block_propagation_topic: String,
        peers: Arc<RwLock<peers::Peers>>,
    ) -> Self {
        Self {
            inner,
            block_propagation_topic,
            peers_with_capability: Default::default(),
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

    async fn get_update_peers_with_sync_capability(&self, capability: &[u8]) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        let r = self.peers_with_capability.read().await;
        let mut peers = if let Some(peers) = r.get(capability) {
            peers.into_iter().copied().collect::<Vec<_>>()
        } else {
            // Avoid deadlock
            drop(r);

            let mut peers = self
                .inner
                .get_capability_providers(std::str::from_utf8(capability).expect("valid UTF-8"))
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(&self.inner.peer_id());
            debug_assert!(_i_should_have_the_capability_too);

            let peers_vec = peers.iter().copied().collect::<Vec<_>>();

            let mut w = self.peers_with_capability.write().await;
            w.update(capability, peers);
            peers_vec
        };
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

        for peer in self
            .get_update_peers_with_sync_capability(protocol::Headers::NAME)
            .await
        {
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
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> Option<Vec<p2p_proto_v0::common::BlockBody>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let limit: u64 = num_blocks.try_into().ok()?;

        for peer in self
            .get_update_peers_with_sync_capability(protocol::Bodies::NAME)
            .await
        {
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

        for peer in self
            .get_update_peers_with_sync_capability(todo!("use v1"))
            .await
        {
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

        for peer in self
            .get_update_peers_with_sync_capability(todo!("use v1"))
            .await
        {
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

#[derive(Clone, Debug)]
struct PeersWithCapability {
    set: HashMap<Vec<u8>, HashSet<PeerId>>,
    last_update: std::time::Instant,
    timeout: Duration,
}

impl PeersWithCapability {
    pub fn new(timeout: Duration) -> Self {
        Self {
            set: Default::default(),
            last_update: std::time::Instant::now(),
            timeout,
        }
    }

    /// Does not clear if elapsed, instead the caller is expected to call [`Self::update`]
    pub fn get(&self, capability: &[u8]) -> Option<&HashSet<PeerId>> {
        if self.last_update.elapsed() > self.timeout {
            None
        } else {
            self.set.get(capability)
        }
    }

    pub fn update(&mut self, capability: &[u8], peers: HashSet<PeerId>) {
        self.last_update = std::time::Instant::now();
        self.set.insert(capability.to_owned(), peers);
    }
}

impl Default for PeersWithCapability {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}
