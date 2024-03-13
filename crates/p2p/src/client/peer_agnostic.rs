//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use futures::{pin_mut, StreamExt};
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::common::{Direction, Iteration};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::state::{ContractDiff, ContractStoredValue, StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::{
    state_update::{ContractClassUpdate, ContractUpdateCounts, ContractUpdates},
    SierraHash,
};
use pathfinder_common::{
    BlockNumber, ClassHash, ContractAddress, ContractNonce, SignedBlockHeader, StorageAddress,
    StorageValue,
};
use tokio::sync::RwLock;

use crate::client::conv::{CairoDefinition, SierraDefinition, TryFromDto};
use crate::client::peer_aware;
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
pub enum Class {
    Cairo {
        block_number: BlockNumber,
        hash: ClassHash,
        definition: Vec<u8>,
    },
    Sierra {
        block_number: BlockNumber,
        sierra_hash: SierraHash,
        sierra_definition: Vec<u8>,
        casm_definition: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: String,
    peers_with_capability: Arc<RwLock<PeersWithCapability>>,
}

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

    pub fn contract_updates_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        contract_update_counts_stream: impl futures::Stream<Item = anyhow::Result<ContractUpdateCounts>>,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<(BlockNumber, ContractUpdates)>>> {
        async_stream::try_stream! {
        pin_mut!(contract_update_counts_stream);

        if start <= stop_inclusive {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
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

                    // Get contract update counts for this block
                    let mut current = contract_update_counts_stream.next().await
                        .ok_or_else(|| anyhow::anyhow!("Contract update counts stream terminated prematurely at block {start}"))??;

                    let mut contract_updates = ContractUpdates::default();

                    while let Some(contract_diff) = responses.next().await {
                        match contract_diff {
                            StateDiffsResponse::ContractDiff(ContractDiff {
                                address,
                                nonce,
                                class_hash,
                                is_replaced,
                                values,
                                domain: _,
                            }) => {
                                let address = ContractAddress(address.0);
                                let num_values =
                                    u64::try_from(values.len()).expect("ptr size is 64 bits");
                                match current.storage_diffs.checked_sub(num_values) {
                                    Some(x) => current.storage_diffs = x,
                                    None => {
                                        tracing::debug!(%peer, "Too many storage diffs: {num_values} > {}", current.storage_diffs);
                                        // TODO punish the peer
                                        continue 'next_peer;
                                    }
                                }

                                if address == ContractAddress::ONE {
                                    let storage = &mut contract_updates
                                        .system
                                        .entry(address)
                                        .or_default()
                                        .storage;
                                    values.into_iter().for_each(
                                        |ContractStoredValue { key, value }| {
                                            storage
                                                .insert(StorageAddress(key), StorageValue(value));
                                        },
                                    );
                                } else {
                                    let update =
                                        &mut contract_updates.regular.entry(address).or_default();
                                    values.into_iter().for_each(
                                        |ContractStoredValue { key, value }| {
                                            update
                                                .storage
                                                .insert(StorageAddress(key), StorageValue(value));
                                        },
                                    );

                                    if let Some(nonce) = nonce {
                                        match current.nonce_updates.checked_sub(1) {
                                            Some(x) => current.nonce_updates = x,
                                            None => {
                                                tracing::debug!(%peer, "Too many nonce updates");
                                                // TODO punish the peer
                                                continue 'next_peer;
                                            }
                                        }

                                        update.nonce = Some(ContractNonce(nonce));
                                    }

                                    if let Some(class_hash) = class_hash.map(ClassHash) {
                                        match current.deployed_contracts.checked_sub(1) {
                                            Some(x) => current.deployed_contracts = x,
                                            None => {
                                                tracing::debug!(%peer, "Too many deployed contracts");
                                                // TODO punish the peer
                                                continue 'next_peer;
                                            }
                                        }

                                        if is_replaced.unwrap_or_default() {
                                            update.class =
                                                Some(ContractClassUpdate::Replace(class_hash));
                                        } else {
                                            update.class =
                                                Some(ContractClassUpdate::Deploy(class_hash));
                                        }
                                    }
                                }
                            }
                            StateDiffsResponse::Fin => {
                                if current.storage_diffs == 0
                                    && current.nonce_updates == 0
                                    && current.deployed_contracts == 0
                                {
                                    // All the counters for this block have been exhausted which means
                                    // that the state update for this block is complete.
                                    yield PeerData::new(
                                        peer,
                                        (start, std::mem::take(&mut contract_updates)),
                                    );

                                    if start < stop_inclusive {
                                        // Move to the next block
                                        start += 1;
                                        current = contract_update_counts_stream.next().await
                                            .ok_or_else(|| anyhow::anyhow!("Contract update counts stream terminated prematurely at block {start}"))??;
                                        tracing::debug!(%peer, "State diff stream Fin");
                                    } else {
                                        // We're done, terminate the stream
                                        break 'outer;
                                    }
                                } else {
                                    tracing::debug!(%peer, "Premature state diff stream Fin");
                                    // TODO punish the peer
                                    continue 'next_peer;
                                }
                            }
                        };
                    }
                }
            }
        }
        }
    }

    pub fn class_definitions_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        declared_class_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<Class>>> {
        async_stream::try_stream! {
        pin_mut!(declared_class_counts_stream);

        if start <= stop_inclusive {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = self
                    .get_update_peers_with_sync_capability(protocol::Classes::NAME)
                    .await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let limit = stop_inclusive.get() - start.get() + 1;

                    let request = ClassesRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses = match self
                        .inner
                        .send_classes_sync_request(peer, request)
                        .await
                    {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "Classes request failed");
                            continue 'next_peer;
                        }
                    };

                    // Get number of declared classes for this block
                    let mut current = declared_class_counts_stream.next().await
                        .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))??;

                    while let Some(contract_diff) = responses.next().await {
                        match contract_diff {
                            ClassesResponse::Class(p2p_proto::class::Class::Cairo0 { class, domain: _ , class_hash }) => {
                                yield PeerData::new(peer, Class::Cairo {
                                    block_number: start,
                                    hash: ClassHash(class_hash.0),
                                    definition: CairoDefinition::try_from_dto(class)?.0,
                                });
                            },
                            ClassesResponse::Class(p2p_proto::class::Class::Cairo1 { class, domain: _, class_hash }) => {
                                let definition = SierraDefinition::try_from_dto(class)?;
                                yield PeerData::new(peer, Class::Sierra {
                                    block_number: start,
                                    sierra_hash: SierraHash(class_hash.0),
                                    sierra_definition: definition.sierra,
                                    casm_definition: definition.casm,
                                });
                            },
                            ClassesResponse::Fin => {
                                if current == 0
                                {
                                    // All the counters for this block have been exhausted which means
                                    // that this block is complete.
                                    if start < stop_inclusive {
                                        // Move to the next block
                                        start += 1;
                                        current = declared_class_counts_stream.next().await
                                            .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))??;
                                        tracing::debug!(%peer, "Class definition stream Fin");
                                    } else {
                                        // We're done, terminate the stream
                                        break 'outer;
                                    }
                                } else {
                                    tracing::debug!(%peer, "Premature class definition stream Fin");
                                    // TODO punish the peer
                                    continue 'next_peer;
                                }
                            }
                        };
                    }
                }
            }
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
