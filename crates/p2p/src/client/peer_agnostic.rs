//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use futures::StreamExt;
use libp2p::PeerId;
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use p2p_proto::{
    common::{Direction, Iteration},
    receipt::{ReceiptsRequest, ReceiptsResponse},
    state::ContractDiff,
};
use p2p_proto::{
    header::{BlockHeadersRequest, BlockHeadersResponse},
    state::ContractStoredValue,
};
use pathfinder_common::{
    state_update::{ContractClassUpdate, ContractUpdates, StateUpdateStats},
    BlockNumber, ClassHash, ContractAddress, ContractNonce, SignedBlockHeader, StorageAddress,
    StorageValue,
};
use smallvec::SmallVec;
use tokio::{sync::RwLock, task::spawn_blocking};

use crate::client::{conv::TryFromDto, peer_aware};
use crate::sync::protocol;

/// Data received from a specific peer.
#[derive(Debug)]
pub struct PeerData<T> {
    pub peer: PeerId,
    pub data: T,
}

impl<T> PeerData<T> {
    pub fn new(peer: PeerId, data: T) -> Self {
        Self { peer, data }
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: String,
    peers_with_capability: Arc<RwLock<PeersWithCapability>>,
}

// TODO Rework the API!
// I.e. make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity.
impl Client {
    pub fn new(inner: peer_aware::Client, block_propagation_topic: String) -> Self {
        Self {
            inner,
            block_propagation_topic,
            peers_with_capability: Default::default(),
        }
    }

    // Propagate new L2 head head
    pub async fn propagate_new_head(
        &self,
        block_id: p2p_proto::common::BlockId,
    ) -> anyhow::Result<()> {
        tracing::debug!(number=%block_id.number, hash=%block_id.hash.0, topic=%self.block_propagation_topic,
            "Propagating head"
        );

        self.inner
            .publish(
                &self.block_propagation_topic,
                p2p_proto::header::NewBlock::Id(block_id),
            )
            .await
    }

    async fn get_update_peers_with_sync_capability(&self, capability: &str) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        let r = self.peers_with_capability.read().await;
        let mut peers = if let Some(peers) = r.get(capability) {
            peers.iter().copied().collect::<Vec<_>>()
        } else {
            // Avoid deadlock
            drop(r);

            let mut peers = self
                .inner
                .get_capability_providers(capability)
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(self.inner.peer_id());
            debug_assert!(_i_should_have_the_capability_too);

            let peers_vec = peers.iter().copied().collect::<Vec<_>>();

            let mut w = self.peers_with_capability.write().await;
            w.update(capability, peers);
            peers_vec
        };
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    pub async fn get_update_peers_with_transaction_sync_capability(&self) -> Vec<PeerId> {
        self.get_update_peers_with_sync_capability(protocol::Transactions::NAME)
            .await
    }

    pub async fn get_update_peers_with_receipt_sync_capability(&self) -> Vec<PeerId> {
        self.get_update_peers_with_sync_capability(protocol::Receipts::NAME)
            .await
    }

    pub fn header_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        reverse: bool,
    ) -> impl futures::Stream<Item = PeerData<SignedBlockHeader>> {
        let (mut start, stop, direction) = match reverse {
            true => (stop, start, Direction::Backward),
            false => (start, stop, Direction::Forward),
        };

        async_stream::stream! {
            // Loop which refreshes peer set once we exhaust it.
            loop {
                let peers = self
                    .get_update_peers_with_sync_capability(protocol::Headers::NAME)
                    .await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let limit = start.get().max(stop.get()) - start.get().min(stop.get());

                    let request = BlockHeadersRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses = match self.inner.send_headers_sync_request(peer, request).await
                    {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "Headers request failed");
                            continue 'next_peer;
                        }
                    };

                    while let Some(signed_header) = responses.next().await {
                        let signed_header = match signed_header {
                            BlockHeadersResponse::Header(hdr) =>
                            match SignedBlockHeader::try_from_dto(*hdr) {
                                Ok(hdr) => hdr,
                                Err(error) => {
                                    tracing::debug!(%peer, %error, "Header stream failed");
                                    continue 'next_peer;
                                },
                            },
                            BlockHeadersResponse::Fin => {
                                tracing::debug!(%peer, "Header stream Fin");
                                continue 'next_peer;
                            }
                        };

                        start = match direction {
                            Direction::Forward => start + 1,
                            // unwrap_or_default is safe as this is the genesis edge case,
                            // at which point the loop will complete at the end of this iteration.
                            Direction::Backward => start.parent().unwrap_or_default(),
                        };

                        yield PeerData::new(peer, signed_header);
                    }

                    // TODO: track how much and how fast this peer responded with i.e. don't let them drip feed us etc.
                }
            }
        }
    }

    pub async fn send_transactions_sync_request(
        &self,
        peer: PeerId,
        request: TransactionsRequest,
    ) -> anyhow::Result<futures::channel::mpsc::Receiver<TransactionsResponse>> {
        self.inner
            .send_transactions_sync_request(peer, request)
            .await
    }

    pub async fn send_receipts_sync_request(
        &self,
        peer: PeerId,
        request: ReceiptsRequest,
    ) -> anyhow::Result<futures::channel::mpsc::Receiver<ReceiptsResponse>> {
        self.inner.send_receipts_sync_request(peer, request).await
    }

    /// ### Important
    ///
    /// Caller must guarantee that `start <= stop_inclusive`
    pub fn contract_updates_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        getter: Arc<
            impl Fn(
                    BlockNumber,
                    NonZeroUsize,
                ) -> anyhow::Result<Option<SmallVec<[StateUpdateStats; 10]>>>
                + Send
                + Sync
                + 'static,
        >,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<(BlockNumber, ContractUpdates)>>> {
        debug_assert!(start <= stop_inclusive);

        async_stream::try_stream! {

            let mut stats = Default::default();

            // Loop which refreshes peer set once we exhaust it.
            loop {
                let peers = self
                    .get_update_peers_with_sync_capability(protocol::StateDiffs::NAME)
                    .await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let limit = stop_inclusive.get() - start.get() + 1;

                    let request = StateDiffsRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses = match self
                        .inner
                        .send_state_diffs_sync_request(peer, request)
                        .await
                    {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "State diffs request failed");
                            continue 'next_peer;
                        }
                    };

                    // Get state update numbers for this block
                    let mut current = self.state_update_nums_for_next_block(start, stop_inclusive, &mut stats, getter.clone()).await?;

                    let mut contract_updates = ContractUpdates::default();

                    while let Some(contract_diff) = responses.next().await {
                        match contract_diff {
                            StateDiffsResponse::ContractDiff(ContractDiff { address, nonce, class_hash, is_replaced, values, domain: _ }) => {
                                let address = ContractAddress(address.0);
                                let num_values = u64::try_from(values.len()).expect("ptr size is 64 bits");
                                match current.num_storage_diffs.checked_sub(num_values) {
                                    Some(x) => current.num_storage_diffs = x,
                                    None => {
                                        tracing::debug!(%peer, "Too many storage diffs: {num_values} > {}", current.num_storage_diffs);
                                        // TODO punish the peer
                                        continue 'next_peer;
                                    }
                                }

                                if address == ContractAddress::ONE {
                                    let storage = &mut contract_updates.system.entry(address).or_default().storage;
                                    values.into_iter().for_each(|ContractStoredValue { key, value }| {
                                        storage.insert(StorageAddress(key), StorageValue(value));
                                    });
                                } else {
                                    let update = &mut contract_updates.regular.entry(address).or_default();
                                    values.into_iter().for_each(|ContractStoredValue { key, value }| {
                                        update.storage.insert(StorageAddress(key), StorageValue(value));
                                    });

                                    if let Some(nonce) = nonce {
                                        match current.num_nonce_updates.checked_sub(1) {
                                            Some(x) => current.num_nonce_updates = x,
                                            None => {
                                                tracing::debug!(%peer, "Too many nonce updates");
                                                // TODO punish the peer
                                                continue 'next_peer;
                                            }
                                        }

                                        update.nonce = Some(ContractNonce(nonce));
                                    }

                                    if let Some(class_hash) = class_hash.map(|x| ClassHash(x)) {
                                        match current.num_deployed_contracts.checked_sub(1) {
                                            Some(x) => current.num_deployed_contracts = x,
                                            None => {
                                                tracing::debug!(%peer, "Too many deployed contracts");
                                                // TODO punish the peer
                                                continue 'next_peer;
                                            }
                                        }

                                        if is_replaced.unwrap_or_default() {
                                            update.class = Some(ContractClassUpdate::Replace(class_hash));
                                        } else {
                                            update.class = Some(ContractClassUpdate::Deploy(class_hash));
                                        }
                                    }
                                }
                            },
                            StateDiffsResponse::Fin => {
                                tracing::debug!(%peer, "State diff stream Fin");
                                continue 'next_peer;
                            }
                        };

                        // All the counters for this block have been exhausted which means
                        // that the state update for this block is complete.
                        if current.num_storage_diffs == 0 && current.num_nonce_updates == 0 && current.num_deployed_contracts == 0 {
                            yield PeerData::new(peer, (start, std::mem::take(&mut contract_updates)));
                            // Move to the next block
                            start = start + 1;
                            current = self.state_update_nums_for_next_block(start, stop_inclusive, &mut stats, getter.clone()).await?;
                        }
                    }
                }
            }
        }
    }

    async fn state_update_nums_for_next_block(
        &self,
        start: BlockNumber,
        stop_inclusive: BlockNumber,
        stats: &mut SmallVec<[StateUpdateStats; 10]>,
        getter: Arc<
            impl Fn(
                    BlockNumber,
                    NonZeroUsize,
                ) -> anyhow::Result<Option<SmallVec<[StateUpdateStats; 10]>>>
                + Send
                + Sync
                + 'static,
        >,
    ) -> anyhow::Result<StateUpdateStats> {
        // size_of(StateUpdateStats) == 32B
        // 30k x 32B == 960kB
        let limit: usize = 30_000
            .min(stop_inclusive.get() - start.get() + 1)
            .try_into()
            .expect("pts size is 64 bits");
        let limit = NonZeroUsize::new(limit).expect("limit > 0");
        let next = stats.pop();
        match next {
            Some(x) => Ok(x),
            None => {
                let new_stats = spawn_blocking(move || getter(start, limit))
                    .await
                    .context("Joining blocking task")?
                    .context("Getting state update stats")?
                    .ok_or(anyhow::anyhow!("No stats for this range"))?;
                *stats = new_stats;
                Ok(stats.pop().expect("vector is not empty"))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct PeersWithCapability {
    set: HashMap<String, HashSet<PeerId>>,
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
    pub fn get(&self, capability: &str) -> Option<&HashSet<PeerId>> {
        if self.last_update.elapsed() > self.timeout {
            None
        } else {
            self.set.get(capability)
        }
    }

    pub fn update(&mut self, capability: &str, peers: HashSet<PeerId>) {
        self.last_update = std::time::Instant::now();
        self.set.insert(capability.to_owned(), peers);
    }
}

impl Default for PeersWithCapability {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}
