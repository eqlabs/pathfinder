//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use fake::Dummy;
use futures::{pin_mut, StreamExt};
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::common::{Direction, Iteration};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{ContractDiff, ContractStoredValue, StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::event::Event;
use pathfinder_common::state_update::{ContractClassUpdate, ContractUpdateCounts, ContractUpdates};
use pathfinder_common::{
    BlockNumber,
    ClassHash,
    ContractAddress,
    ContractNonce,
    SierraHash,
    SignedBlockHeader,
    StorageAddress,
    StorageValue,
    TransactionHash,
};
use tokio::sync::RwLock;

use crate::client::conv::{CairoDefinition, FromDto, SierraDefinition, TryFromDto};
use crate::client::peer_aware;
use crate::sync::protocol;

/// Data received from a specific peer.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerData<T> {
    pub peer: PeerId,
    pub data: T,
}

impl<T> PeerData<T> {
    pub fn new(peer: PeerId, data: T) -> Self {
        Self { peer, data }
    }

    pub fn from_result<E>(peer: PeerId, result: Result<T, E>) -> Result<PeerData<T>, PeerData<E>> {
        result
            .map(|x| Self::new(peer, x))
            .map_err(|e| PeerData::<E>::new(peer, e))
    }

    pub fn for_tests(data: T) -> Self {
        Self {
            peer: PeerId::random(),
            data,
        }
    }
}

impl<T, U: Dummy<T>> Dummy<T> for PeerData<U> {
    fn dummy_with_rng<R: rand::prelude::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
        let digest = rng.gen::<[u8; 32]>();
        let multihash = libp2p::multihash::Multihash::wrap(0x0, &digest)
            .expect("The digest size is never too large");

        PeerData {
            peer: PeerId::from_multihash(multihash).expect("Valid multihash"),
            data: U::dummy_with_rng(config, rng),
        }
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

impl Class {
    pub fn block_number(&self) -> BlockNumber {
        match self {
            Self::Cairo { block_number, .. } => *block_number,
            Self::Sierra { block_number, .. } => *block_number,
        }
    }

    pub fn hash(&self) -> ClassHash {
        match self {
            Self::Cairo { hash, .. } => *hash,
            Self::Sierra { sierra_hash, .. } => ClassHash(sierra_hash.0),
        }
    }

    /// Return Cairo or Sierra class definition depending on the variant.
    pub fn class_definition(&self) -> Vec<u8> {
        match self {
            Self::Cairo { definition, .. } => definition.clone(),
            Self::Sierra {
                sierra_definition, ..
            } => sierra_definition.clone(),
        }
    }

    /// Return Casm definition for Sierra variant, otherwise None.
    pub fn casm_definition(&self) -> Option<Vec<u8>> {
        match self {
            Self::Cairo { .. } => None,
            Self::Sierra {
                casm_definition, ..
            } => Some(casm_definition.clone()),
        }
    }
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

                    let mut responses =
                        match self.inner.send_headers_sync_request(peer, request).await {
                            Ok(x) => x,
                            Err(error) => {
                                // Failed to establish connection, try next peer.
                                tracing::debug!(%peer, reason=%error, "Headers request failed");
                                continue 'next_peer;
                            }
                        };

                    while let Some(signed_header) = responses.next().await {
                        let signed_header = match signed_header {
                            BlockHeadersResponse::Header(hdr) => {
                                match SignedBlockHeader::try_from_dto(*hdr) {
                                    Ok(hdr) => hdr,
                                    Err(error) => {
                                        tracing::debug!(%peer, %error, "Header stream failed");
                                        continue 'next_peer;
                                    }
                                }
                            }
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

    pub fn contract_updates_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        contract_update_counts_stream: impl futures::Stream<Item = anyhow::Result<ContractUpdateCounts>>,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<(BlockNumber, ContractUpdates)>>> {
        async_stream::try_stream! {
            pin_mut!(contract_update_counts_stream);

            let mut current_counts_outer = None;

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

                        let mut current_counts = match current_counts_outer {
                            // Still the same block
                            Some(backup) => backup,
                            // Move to the next block
                            None => {
                                let x = contract_update_counts_stream.next().await
                                        .ok_or_else(|| anyhow::anyhow!("Contract update counts stream terminated prematurely at block {start}"))??;
                                current_counts_outer = Some(x);
                                x
                            }
                        };

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
                                    match current_counts.storage_diffs.checked_sub(num_values) {
                                        Some(x) => current_counts.storage_diffs = x,
                                        None => {
                                            tracing::debug!(%peer, "Too many storage diffs: {num_values} > {}", current_counts.storage_diffs);
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
                                                storage.insert(
                                                    StorageAddress(key),
                                                    StorageValue(value),
                                                );
                                            },
                                        );
                                    } else {
                                        let update = &mut contract_updates
                                            .regular
                                            .entry(address)
                                            .or_default();
                                        values.into_iter().for_each(
                                            |ContractStoredValue { key, value }| {
                                                update.storage.insert(
                                                    StorageAddress(key),
                                                    StorageValue(value),
                                                );
                                            },
                                        );

                                        if let Some(nonce) = nonce {
                                            match current_counts.nonce_updates.checked_sub(1) {
                                                Some(x) => current_counts.nonce_updates = x,
                                                None => {
                                                    tracing::debug!(%peer, "Too many nonce updates");
                                                    // TODO punish the peer
                                                    continue 'next_peer;
                                                }
                                            }

                                            update.nonce = Some(ContractNonce(nonce));
                                        }

                                        if let Some(class_hash) = class_hash.map(ClassHash) {
                                            match current_counts.deployed_contracts.checked_sub(1) {
                                                Some(x) => current_counts.deployed_contracts = x,
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
                                    if current_counts.storage_diffs == 0
                                        && current_counts.nonce_updates == 0
                                        && current_counts.deployed_contracts == 0
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
                                            current_counts = contract_update_counts_stream.next().await
                                                    .ok_or_else(|| anyhow::anyhow!("Contract update counts stream terminated prematurely at block {start}"))??;
                                            current_counts_outer = Some(current_counts);
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

            let mut current_count_outer = None;

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

                        let mut responses =
                            match self.inner.send_classes_sync_request(peer, request).await {
                                Ok(x) => x,
                                Err(error) => {
                                    // Failed to establish connection, try next peer.
                                    tracing::debug!(%peer, reason=%error, "Classes request failed");
                                    continue 'next_peer;
                                }
                            };

                        let mut current_count = match current_count_outer {
                            // Still the same block
                            Some(backup) => backup,
                            // Move to the next block
                            None => {
                                let x = declared_class_counts_stream.next().await
                                    .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))??;
                                current_count_outer = Some(x);
                                x
                            }
                        };

                        while let Some(contract_diff) = responses.next().await {
                            match contract_diff {
                                ClassesResponse::Class(p2p_proto::class::Class::Cairo0 {
                                    class,
                                    domain: _,
                                    class_hash,
                                }) => {
                                    let CairoDefinition(definition) =
                                        CairoDefinition::try_from_dto(class)?;
                                    match current_count.checked_sub(1) {
                                        Some(x) => current_count = x,
                                        None => {
                                            tracing::debug!(%peer, "Too many classes");
                                            // TODO punish the peer
                                            continue 'next_peer;
                                        }
                                    }
                                    yield PeerData::new(
                                        peer,
                                        Class::Cairo {
                                            block_number: start,
                                            hash: ClassHash(class_hash.0),
                                            definition,
                                        },
                                    );
                                }
                                ClassesResponse::Class(p2p_proto::class::Class::Cairo1 {
                                    class,
                                    domain: _,
                                    class_hash,
                                }) => {
                                    let definition = SierraDefinition::try_from_dto(class)?;
                                    match current_count.checked_sub(1) {
                                        Some(x) => current_count = x,
                                        None => {
                                            tracing::debug!(%peer, "Too many classes");
                                            // TODO punish the peer
                                            continue 'next_peer;
                                        }
                                    }
                                    yield PeerData::new(
                                        peer,
                                        Class::Sierra {
                                            block_number: start,
                                            sierra_hash: SierraHash(class_hash.0),
                                            sierra_definition: definition.sierra,
                                            casm_definition: definition.casm,
                                        },
                                    );
                                }
                                ClassesResponse::Fin => {
                                    if current_count == 0 {
                                        // The counter for this block has been exhausted which means
                                        // that this block is complete.
                                        if start < stop_inclusive {
                                            // Move to the next block
                                            start += 1;
                                            current_count = declared_class_counts_stream.next().await
                                                .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))??;
                                            current_count_outer = Some(current_count);
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

    pub async fn events_for_block(
        self,
        block: BlockNumber,
    ) -> Option<(
        PeerId,
        impl futures::Stream<Item = (TransactionHash, Event)>,
    )> {
        let request = EventsRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self
            .get_update_peers_with_sync_capability(protocol::Events::NAME)
            .await;

        for peer in peers {
            let Ok(stream) = self
                .inner
                .send_events_sync_request(peer, request)
                .await
                .inspect_err(|error| tracing::debug!(%peer, %error, "Events request failed"))
            else {
                continue;
            };

            let stream = stream
                .take_while(|x| std::future::ready(!matches!(x, &EventsResponse::Fin)))
                .map(|x| match x {
                    EventsResponse::Fin => unreachable!("Already handled Fin above"),
                    EventsResponse::Event(event) => (
                        TransactionHash(event.transaction_hash.0),
                        Event::from_dto(event),
                    ),
                });

            return Some((peer, stream));
        }

        None
    }

    /// ### Important
    ///
    /// Events are grouped by block and by transaction. The order of flattened
    /// events in a block is guaranteed to be correct because the event
    /// commitment is part of block hash. However the number of events per
    /// transaction for __pre 0.13.2__ Starknet blocks is __TRUSTED__
    /// because neither signature nor block hash contain this information.
    pub fn events_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        event_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<EventsForBlockByTransaction>>> {
        async_stream::try_stream! {
            pin_mut!(event_counts_stream);

            let mut current_count_outer = None;

            if start <= stop_inclusive {
                // Loop which refreshes peer set once we exhaust it.
                'outer: loop {
                    let peers = self
                        .get_update_peers_with_sync_capability(protocol::Events::NAME)
                        .await;

                    // Attempt each peer.
                    'next_peer: for peer in peers {
                        let limit = stop_inclusive.get() - start.get() + 1;

                        let request = EventsRequest {
                            iteration: Iteration {
                                start: start.get().into(),
                                direction: Direction::Forward,
                                limit,
                                step: 1.into(),
                            },
                        };

                        let mut responses =
                            match self.inner.send_events_sync_request(peer, request).await {
                                Ok(x) => x,
                                Err(error) => {
                                    // Failed to establish connection, try next peer.
                                    tracing::debug!(%peer, reason=%error, "Events request failed");
                                    continue 'next_peer;
                                }
                            };

                        // Maintain the current transaction hash to group events by transaction
                        // This grouping is TRUSTED for pre 0.13.2 Starknet blocks.
                        let mut current_txn_hash = None;
                        let mut current_count = match current_count_outer {
                            // Still the same block
                            Some(backup) => backup,
                            // Move to the next block
                            None => {
                                let x = event_counts_stream.next().await
                                    .ok_or_else(|| anyhow::anyhow!("Event counts stream terminated prematurely at block {start}"))??;
                                current_count_outer = Some(x);
                                x
                            }
                        };

                        let mut events = Vec::new();

                        while let Some(contract_diff) = responses.next().await {
                            match contract_diff {
                                EventsResponse::Event(event) => {
                                    let txn_hash = TransactionHash(event.transaction_hash.0);
                                    let event = Event::try_from_dto(event)?;

                                    match current_txn_hash {
                                        Some(x) if x != txn_hash => {
                                            // New transaction
                                            events.push(vec![event]);
                                            current_txn_hash = Some(txn_hash);
                                        }
                                        _ => {
                                            // Same transaction
                                            events.last_mut().expect("not empty").push(event);
                                        }
                                    }

                                    match current_count.checked_sub(1) {
                                        Some(x) => current_count = x,
                                        None => {
                                            tracing::debug!(%peer, "Too many events");
                                            // TODO punish the peer
                                            continue 'next_peer;
                                        }
                                    }
                                }
                                EventsResponse::Fin => {
                                    if current_count == 0 {
                                        // All the counters for this block have been exhausted which means
                                        // that this block is complete.
                                        yield PeerData::new(
                                            peer,
                                            (start, std::mem::take(&mut events)),
                                        );

                                        if start < stop_inclusive {
                                            // Move to the next block
                                            start += 1;
                                            current_count = event_counts_stream.next().await
                                                .ok_or_else(|| anyhow::anyhow!("Event counts stream terminated prematurely at block {start}"))??;
                                            current_count_outer = Some(current_count);
                                            tracing::debug!(%peer, "Event stream Fin");
                                        } else {
                                            // We're done, terminate the stream
                                            break 'outer;
                                        }
                                    } else {
                                        tracing::debug!(%peer, "Premature event stream Fin");
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

    /// Does not clear if elapsed, instead the caller is expected to call
    /// [`Self::update`]
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

pub type EventsForBlockByTransaction = (BlockNumber, Vec<Vec<Event>>);
