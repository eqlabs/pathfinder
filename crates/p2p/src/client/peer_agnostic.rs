//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use libp2p::PeerId;
use p2p_proto_v1::block::{BlockBodiesRequest, BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto_v1::common::{Direction, Iteration};
use p2p_proto_v1::receipt::{Receipt, ReceiptsRequest};
use p2p_proto_v1::transaction::TransactionsRequest;
use pathfinder_common::{transaction::TransactionVariant, BlockHash, BlockNumber};
use tokio::sync::RwLock;

use crate::sync::protocol;
use crate::{
    client::{
        peer_aware,
        types::{BlockHeader, StateUpdateWithDefs},
    },
    peers,
};

mod parse;

use parse::ParserState;

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
    ) -> anyhow::Result<Vec<BlockHeader>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        for peer in self
            .get_update_peers_with_sync_capability(protocol::Headers::NAME)
            .await
        {
            let request = BlockHeadersRequest {
                iteration: Iteration {
                    start: start_block.get().into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = todo!("fixme");

            match response {
                Ok(BlockHeadersResponse { parts }) => {
                    let mut state = parse::block_header::State::Uninitialized;
                    for part in parts {
                        if let Err(error) = state.advance(part) {
                            tracing::debug!(from=%peer, %error, "headers response parsing");
                            // Try the next peer
                            break;
                        }
                    }

                    if let Some(headers) = state.take_parsed() {
                        // Success
                        return Ok(headers);
                    } else {
                        // Try the next peer
                        tracing::debug!(from=%peer, "unexpected end of part");
                        break;
                    }
                }
                // Try the next peer
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "headers request failed");
                }
            }
        }

        anyhow::bail!("No valid responses to headers request: start {start_block}, n {num_blocks}")
    }

    /// Including new class definitions
    pub async fn state_updates(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<Vec<StateUpdateWithDefs>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Bodies::NAME)
            .await;
        for peer in peers {
            let request = BlockBodiesRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };

            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = Ok(vec![]); // FIXME

            match response {
                Ok(body_responses) => {
                    let mut state = parse::state_update::State::Uninitialized;
                    for body_response in body_responses {
                        if let Err(error) = state.advance(body_response) {
                            tracing::debug!(from=%peer, %error, "body responses parsing");
                            break;
                        }
                    }

                    if let Some(headers) = state.take_parsed() {
                        // Success
                        return Ok(headers);
                    } else {
                        // Try the next peer
                        tracing::debug!(from=%peer, "empty response or unexpected end of response");
                        break;
                    }
                }
                // Try the next peer instead
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "bodies request failed");
                }
            }
        }

        anyhow::bail!(
            "No valid responses to bodies request: start {start_block_hash}, n {num_blocks}"
        )
    }

    pub async fn transactions(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<HashMap<BlockHash, Vec<TransactionVariant>>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Transactions::NAME)
            .await;
        for peer in peers {
            let request = TransactionsRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = Ok(vec![]); // FIXME

            match response {
                Ok(responses) => {
                    let mut state = parse::transactions::State::Uninitialized;
                    for response in responses {
                        if let Err(error) = state.advance(response) {
                            tracing::debug!(from=%peer, %error, "transaction responses parsing");
                            break;
                        }
                    }

                    if let Some(transactions) = state.take_parsed() {
                        // Success
                        return Ok(transactions);
                    } else {
                        // Try the next peer
                        tracing::debug!(from=%peer, "empty response or unexpected end of response");
                        break;
                    }
                }
                // Try the next peer
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "transactions request failed");
                }
            }
        }

        anyhow::bail!(
            "No valid responses to transactions request: start {start_block_hash}, n {num_blocks}"
        )
    }

    pub async fn receipts(
        &self,
        start_block_hash: BlockHash,
        num_blocks: usize,
    ) -> anyhow::Result<HashMap<BlockHash, Vec<Receipt>>> {
        anyhow::ensure!(num_blocks > 0, "0 blocks requested");

        let limit: u64 = num_blocks.try_into()?;

        // If at some point, mid-way a peer suddenly replies not according to the spec we just
        // dump everything from this peer and try with the next peer.
        // We're not permissive when it comes to following the spec.
        let peers = self
            .get_update_peers_with_sync_capability(protocol::Receipts::NAME)
            .await;
        for peer in peers {
            let request = ReceiptsRequest {
                iteration: Iteration {
                    start: start_block_hash.0.into(),
                    direction: Direction::Forward,
                    limit,
                    step: 1.into(),
                },
            };
            let response = self.inner.send_sync_request(peer, todo!("fixme")).await;
            let response: anyhow::Result<_> = Ok(vec![]); // FIXME

            match response {
                Ok(responses) => {
                    let mut state = parse::receipts::State::Uninitialized;
                    for response in responses {
                        if let Err(error) = state.advance(response) {
                            tracing::debug!(from=%peer, %error, "receipts responses parsing");
                            break;
                        }
                    }

                    if let Some(receipts) = state.take_parsed() {
                        // Success
                        return Ok(receipts);
                    } else {
                        // Try the next peer
                        tracing::debug!(from=%peer, "empty response or unexpected end of response");
                        break;
                    }
                }
                // Try the next peer
                Ok(response) => {
                    tracing::debug!(from=%peer, ?response,"unexpected response to receipts request");
                }
                Err(error) => {
                    tracing::debug!(from=%peer, %error, "receipts request failed");
                }
            }
        }

        anyhow::bail!(
            "No valid responses to transactions request: start {start_block_hash}, n {num_blocks}"
        )
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
