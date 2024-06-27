//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fake::Dummy;
use futures::{pin_mut, StreamExt};
use libp2p::PeerId;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::common::{Direction, Iteration};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{
    ContractDiff,
    ContractStoredValue,
    DeclaredClass,
    StateDiffsRequest,
    StateDiffsResponse,
};
use p2p_proto::transaction::{TransactionWithReceipt, TransactionsRequest, TransactionsResponse};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::{ExecutionResources, ExecutionStatus, L2ToL1Message};
use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{
    BlockCommitmentSignature,
    BlockCommitmentSignatureElem,
    BlockHash,
    BlockNumber,
    BlockTimestamp,
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    EventCommitment,
    Fee,
    GasPrice,
    L1DataAvailabilityMode,
    SequencerAddress,
    SierraHash,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StorageAddress,
    StorageValue,
    TransactionCommitment,
    TransactionHash,
    TransactionIndex,
};
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;
use tokio::sync::RwLock;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

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

    pub fn map<U, F>(self, f: F) -> PeerData<U>
    where
        F: FnOnce(T) -> U,
    {
        PeerData {
            peer: self.peer,
            data: f(self.data),
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

#[derive(Clone, PartialEq, Dummy, TaggedDebug)]
pub enum ClassDefinition {
    Cairo {
        block_number: BlockNumber,
        definition: Vec<u8>,
    },
    Sierra {
        block_number: BlockNumber,
        sierra_definition: Vec<u8>,
    },
}

impl ClassDefinition {
    /// Return Cairo or Sierra class definition depending on the variant.
    pub fn class_definition(&self) -> Vec<u8> {
        match self {
            Self::Cairo { definition, .. } => definition.clone(),
            Self::Sierra {
                sierra_definition, ..
            } => sierra_definition.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: Arc<String>,
    peers_with_capability: Arc<RwLock<PeersWithCapability>>,
}

impl Client {
    pub fn new(inner: peer_aware::Client, block_propagation_topic: String) -> Self {
        Self {
            inner,
            block_propagation_topic: Arc::new(block_propagation_topic),
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

        tracing::trace!(?start, ?stop, ?direction, "Streaming headers");

        async_stream::stream! {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = self
                    .get_update_peers_with_sync_capability(protocol::Headers::NAME)
                    .await;

                // Attempt each peer.
                'next_peer: for peer in peers {

                    match direction {
                        Direction::Forward => {
                            if start >= stop {
                                break 'outer;
                            }
                        }
                        Direction::Backward => {
                            if start <= stop {
                                break 'outer;
                            }
                        }
                    }

                    let limit = start.get().max(stop.get()) - start.get().min(stop.get()) + 1;

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
                                match SignedBlockHeader::try_from(*hdr) {
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

    pub fn transaction_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        transaction_counts_and_commitments_stream: impl futures::Stream<
            Item = anyhow::Result<(usize, TransactionCommitment)>,
        >,
    ) -> impl futures::Stream<
        Item = Result<PeerData<(UnverifiedTransactionData, BlockNumber)>, PeerData<anyhow::Error>>,
    > {
        let inner = self.inner.clone();
        let outer = self;
        make_transaction_stream(
            start,
            stop,
            transaction_counts_and_commitments_stream,
            move || {
                let outer = outer.clone();
                async move {
                    outer
                        .get_update_peers_with_transaction_sync_capability()
                        .await
                }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_transactions_sync_request(peer, request).await }
            },
        )
    }

    /// ### Important
    ///
    /// Contract class updates are by default set to
    /// `ContractClassUpdate::Deploy` but __the caller is responsible for
    /// determining if the class was really deployed or replaced__.
    pub fn state_diff_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        state_diff_length_and_commitment_stream: impl futures::Stream<
            Item = anyhow::Result<(usize, StateDiffCommitment)>,
        >,
    ) -> impl futures::Stream<
        Item = Result<PeerData<(UnverifiedStateUpdateData, BlockNumber)>, PeerData<anyhow::Error>>,
    > {
        let inner = self.inner.clone();
        let outer = self;
        make_state_diff_stream(
            start,
            stop,
            state_diff_length_and_commitment_stream,
            move || {
                let outer = outer.clone();
                async move {
                    outer
                        .get_update_peers_with_sync_capability(protocol::StateDiffs::NAME)
                        .await
                }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_state_diffs_sync_request(peer, request).await }
            },
        )
    }

    pub fn class_definition_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        declared_class_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<Item = Result<PeerData<ClassDefinition>, PeerData<anyhow::Error>>>
    {
        let inner = self.inner.clone();
        let outer = self;
        make_class_definition_stream(
            start,
            stop,
            declared_class_counts_stream,
            move || {
                let outer = outer.clone();
                async move {
                    outer
                        .get_update_peers_with_sync_capability(protocol::Classes::NAME)
                        .await
                }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_classes_sync_request(peer, request).await }
            },
        )
    }

    /// ### Important
    ///
    /// Events are grouped by block and by transaction. The order of flattened
    /// events in a block is guaranteed to be correct because the event
    /// commitment is part of block hash. However the number of events per
    /// transaction for __pre 0.13.2__ Starknet blocks is __TRUSTED__
    /// because neither signature nor block hash contain this information.
    pub fn event_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        event_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<
        Item = Result<PeerData<EventsForBlockByTransaction>, PeerData<anyhow::Error>>,
    > {
        let inner = self.inner.clone();
        let outer = self;
        make_event_stream(
            start,
            stop,
            event_counts_stream,
            move || {
                let outer = outer.clone();
                async move {
                    outer
                        .get_update_peers_with_sync_capability(protocol::Events::NAME)
                        .await
                }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_events_sync_request(peer, request).await }
            },
        )
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

    pub async fn transactions_for_block(
        self,
        block: BlockNumber,
    ) -> Option<(
        PeerId,
        impl futures::Stream<Item = anyhow::Result<(TransactionVariant, Receipt)>>,
    )> {
        let request = TransactionsRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self
            .get_update_peers_with_sync_capability(protocol::Transactions::NAME)
            .await;

        for peer in peers {
            let Ok(stream) = self
                .inner
                .send_transactions_sync_request(peer, request)
                .await
                .inspect_err(|error| tracing::debug!(%peer, %error, "Transactions request failed"))
            else {
                continue;
            };

            let stream = stream
                .take_while(|x| std::future::ready(!matches!(x, &TransactionsResponse::Fin)))
                .enumerate()
                .map(|(i, x)| -> anyhow::Result<_> {
                    match x {
                        TransactionsResponse::Fin => unreachable!("Already handled Fin above"),
                        TransactionsResponse::TransactionWithReceipt(tx_with_receipt) => Ok((
                            TransactionVariant::try_from_dto(tx_with_receipt.transaction)?,
                            Receipt::try_from((
                                tx_with_receipt.receipt,
                                TransactionIndex::new(i.try_into().unwrap())
                                    .ok_or_else(|| anyhow::anyhow!("Invalid transaction index"))?,
                            ))?,
                        )),
                    }
                });

            return Some((peer, stream));
        }

        None
    }

    pub async fn state_diff_for_block(
        self,
        block: BlockNumber,
        state_diff_length: u64,
    ) -> Result<Option<(PeerId, StateUpdateData)>, IncorrectStateDiffCount> {
        let request = StateDiffsRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self
            .get_update_peers_with_sync_capability(protocol::StateDiffs::NAME)
            .await;

        for peer in peers {
            let Ok(mut stream) = self
                .inner
                .send_state_diffs_sync_request(peer, request)
                .await
                .inspect_err(|error| tracing::debug!(%peer, %error, "State diffs request failed"))
            else {
                continue;
            };

            let mut current_count = state_diff_length;
            let mut state_diff = StateUpdateData::default();

            while let Some(resp) = stream.next().await {
                match resp {
                    StateDiffsResponse::ContractDiff(ContractDiff {
                        address,
                        nonce,
                        class_hash,
                        values,
                        domain: _,
                    }) => {
                        match current_count.checked_sub(values.len().try_into().unwrap()) {
                            Some(x) => current_count = x,
                            None => {
                                tracing::debug!(%peer, "Too many storage diffs: {} > {}", values.len(), current_count);
                                return Err(IncorrectStateDiffCount(peer));
                            }
                        }
                        let address = ContractAddress(address.0);
                        if address == ContractAddress::ONE {
                            let storage = &mut state_diff
                                .system_contract_updates
                                .entry(address)
                                .or_default()
                                .storage;
                            values
                                .into_iter()
                                .for_each(|ContractStoredValue { key, value }| {
                                    storage.insert(StorageAddress(key), StorageValue(value));
                                });
                        } else {
                            let update =
                                &mut state_diff.contract_updates.entry(address).or_default();
                            values
                                .into_iter()
                                .for_each(|ContractStoredValue { key, value }| {
                                    update
                                        .storage
                                        .insert(StorageAddress(key), StorageValue(value));
                                });

                            if let Some(nonce) = nonce {
                                match current_count.checked_sub(1) {
                                    Some(x) => current_count = x,
                                    None => {
                                        tracing::debug!(%peer, "Too many nonce updates");
                                        return Err(IncorrectStateDiffCount(peer));
                                    }
                                }
                                update.nonce = Some(ContractNonce(nonce));
                            }

                            if let Some(class_hash) = class_hash.map(|x| ClassHash(x.0)) {
                                match current_count.checked_sub(1) {
                                    Some(x) => current_count = x,
                                    None => {
                                        tracing::debug!(%peer, "Too many deployed contracts");
                                        return Err(IncorrectStateDiffCount(peer));
                                    }
                                }
                                update.class = Some(ContractClassUpdate::Deploy(class_hash));
                            }
                        }
                    }
                    StateDiffsResponse::DeclaredClass(DeclaredClass {
                        class_hash,
                        compiled_class_hash,
                    }) => {
                        match current_count.checked_sub(1) {
                            Some(x) => current_count = x,
                            None => {
                                tracing::debug!(%peer, "Too many declared classes");
                                return Err(IncorrectStateDiffCount(peer));
                            }
                        }
                        if let Some(compiled_class_hash) = compiled_class_hash {
                            state_diff
                                .declared_sierra_classes
                                .insert(SierraHash(class_hash.0), CasmHash(compiled_class_hash.0));
                        } else {
                            state_diff
                                .declared_cairo_classes
                                .insert(ClassHash(class_hash.0));
                        }
                    }
                    StateDiffsResponse::Fin => {
                        if current_count != 0 {
                            tracing::debug!(%peer, "Too few storage diffs");
                            return Err(IncorrectStateDiffCount(peer));
                        }
                        return Ok(Some((peer, state_diff)));
                    }
                }
            }
        }

        Ok(None)
    }

    pub async fn class_definitions_for_block(
        self,
        block: BlockNumber,
        declared_classes_count: u64,
    ) -> Result<Option<(PeerId, Vec<ClassDefinition>)>, ClassDefinitionsError> {
        let request = ClassesRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self
            .get_update_peers_with_sync_capability(protocol::Classes::NAME)
            .await;

        for peer in peers {
            let Ok(mut stream) = self
                .inner
                .send_classes_sync_request(peer, request)
                .await
                .inspect_err(|error| tracing::debug!(%peer, %error, "State diffs request failed"))
            else {
                continue;
            };

            let mut current_count = declared_classes_count;
            let mut class_definitions = Vec::new();

            while let Some(resp) = stream.next().await {
                match resp {
                    ClassesResponse::Class(p2p_proto::class::Class::Cairo0 {
                        class,
                        domain: _,
                    }) => {
                        let definition = CairoDefinition::try_from_dto(class)
                            .map_err(|_| ClassDefinitionsError::CairoDefinitionError(peer))?;
                        class_definitions.push(ClassDefinition::Cairo {
                            block_number: block,
                            definition: definition.0,
                        });
                    }
                    ClassesResponse::Class(p2p_proto::class::Class::Cairo1 {
                        class,
                        domain: _,
                    }) => {
                        let definition = SierraDefinition::try_from_dto(class)
                            .map_err(|_| ClassDefinitionsError::SierraDefinitionError(peer))?;
                        class_definitions.push(ClassDefinition::Sierra {
                            block_number: block,
                            sierra_definition: definition.0,
                        });
                    }
                    ClassesResponse::Fin => {
                        tracing::debug!(%peer, "Received FIN in class definitions source");
                        break;
                    }
                }

                current_count = match current_count.checked_sub(1) {
                    Some(x) => x,
                    None => {
                        tracing::debug!(%peer, "Too many class definitions");
                        return Err(ClassDefinitionsError::IncorrectClassDefinitionCount(peer));
                    }
                };
            }

            if current_count != 0 {
                tracing::debug!(%peer, "Too few class definitions");
                return Err(ClassDefinitionsError::IncorrectClassDefinitionCount(peer));
            }

            return Ok(Some((peer, class_definitions)));
        }

        Ok(None)
    }
}

pub fn make_transaction_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    transaction_counts_and_commitments_stream: impl futures::Stream<
        Item = anyhow::Result<(usize, TransactionCommitment)>,
    >,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, TransactionsRequest) -> RF,
) -> impl futures::Stream<
    Item = Result<PeerData<UnverifiedTransactionDataWithBlockNumber>, PeerData<anyhow::Error>>,
>
where
    PF: std::future::Future<Output = Vec<PeerId>>,
    RF: std::future::Future<
        Output = anyhow::Result<futures::channel::mpsc::Receiver<TransactionsResponse>>,
    >,
{
    tracing::trace!(?start, ?stop, "Streaming Transactions");

    async_stream::try_stream! {
        pin_mut!(transaction_counts_and_commitments_stream);

        let mut current_count_outer = None;
        let mut current_commitment = Default::default();

        if start <= stop {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = get_peers().await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
                    let limit = stop.get() - start.get() + 1;

                    let request = TransactionsRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses = match send_request(peer, request).await
                    {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "Transactions request failed");
                            continue 'next_peer;
                        }
                    };

                    let mut current_count = match current_count_outer {
                        // Still the same block
                        Some(backup) => backup,
                        // Move to the next block
                        None => {
                            let (count, commitment) = transaction_counts_and_commitments_stream
                                .next()
                                .await
                                .with_context(|| {
                                    format!(
                                        "Transaction counts and commitments stream terminated \
                                        prematurely at block {}",
                                        start
                                    )
                                })
                                .map_err(peer_err)?
                                .map_err(peer_err)?;

                            current_count_outer = Some(count);
                            current_commitment = commitment;
                            count
                        }
                    };

                    tracing::trace!(number=%current_count, "Expecting transaction responses");

                    let mut transactions = Vec::new();

                    while let Some(response) = responses.next().await {
                        match response {
                            TransactionsResponse::TransactionWithReceipt(
                                TransactionWithReceipt {
                                    transaction,
                                    receipt,
                                },
                            ) => {
                                // FIXME
                                // These conversions should all be infallible OR
                                // we should move to the next peer when failure occurs
                                let t = TransactionVariant::try_from_dto(transaction)
                                    .map_err(peer_err)?;
                                let r = Receipt::try_from((
                                    receipt,
                                    TransactionIndex::new_or_panic(
                                        transactions.len().try_into().expect("ptr size is 64bits"),
                                    ),
                                ))
                                .map_err(peer_err)?;

                                match current_count.checked_sub(1) {
                                    Some(x) => {
                                        current_count = x;
                                        transactions.push((t, r));
                                    }
                                    None => {
                                        tracing::debug!(%peer, %start, %stop, "Too many transactions");
                                        // TODO punish the peer

                                        // We can only get here in case of the last block, which means that the stream should be terminated
                                        debug_assert!(start == stop);
                                        break 'outer;
                                    }
                                }
                            }
                            TransactionsResponse::Fin => {
                                if current_count == 0 {
                                    if start == stop {
                                        // We're done, terminate the stream
                                        break 'outer;
                                    }
                                } else {
                                    tracing::debug!(%peer, "Premature transaction stream Fin");
                                    // TODO punish the peer
                                    continue 'next_peer;
                                }
                            }
                        };

                        if current_count == 0 {
                            // The counter for this block has been exhausted which means
                            // that this block is complete.
                            tracing::trace!(block_number=%start, "All transactions received for block");

                            yield PeerData::new(
                                peer,
                                (UnverifiedTransactionData {
                                    expected_commitment: std::mem::take(
                                        &mut current_commitment
                                    ),
                                    transactions: std::mem::take(&mut transactions),
                                }, start)
                            );

                            if start < stop {
                                // Move to the next block
                                start += 1;
                                tracing::trace!(next_block=%start, "Moving to next block");
                                let (count, commitment) = transaction_counts_and_commitments_stream
                                .next()
                                .await
                                .with_context(|| {
                                    format!(
                                        "Transaction counts and commitments stream terminated \
                                        prematurely at block {}",
                                        start
                                    )
                                })
                                .map_err(peer_err)?
                                .map_err(peer_err)?;

                                current_count = count;
                                current_count_outer = Some(current_count);
                                current_commitment = commitment;
                            }
                        }
                    }

                    // TODO punish the peer
                    // If we reach here, the peer did not send a Fin, so the counter for the current block should be reset
                    // and we should start from the current block again but from the next peer.
                    //
                    // The problem here is that the count stream was already consumed, so we assume that the full blocks that were already
                    // processed are correct.

                    tracing::debug!(%peer, "Fin missing");
                }
            }
        }
    }
}

pub fn make_state_diff_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    state_diff_length_and_commitment_stream: impl futures::Stream<
        Item = anyhow::Result<(usize, StateDiffCommitment)>,
    >,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, StateDiffsRequest) -> RF,
) -> impl futures::Stream<
    Item = Result<PeerData<(UnverifiedStateUpdateData, BlockNumber)>, PeerData<anyhow::Error>>,
>
where
    PF: std::future::Future<Output = Vec<PeerId>>,
    RF: std::future::Future<
        Output = anyhow::Result<futures::channel::mpsc::Receiver<StateDiffsResponse>>,
    >,
{
    tracing::trace!(?start, ?stop, "Streaming state diffs");

    async_stream::try_stream! {
        pin_mut!(state_diff_length_and_commitment_stream);

        let mut current_count_outer = None;
        let mut current_commitment = Default::default();

        if start <= stop {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = get_peers().await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
                    let limit = stop.get() - start.get() + 1;

                    let request = StateDiffsRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses = match send_request(peer, request).await
                    {
                        Ok(x) => x,
                        Err(error) => {
                            // Failed to establish connection, try next peer.
                            tracing::debug!(%peer, reason=%error, "State diffs request failed");
                            continue 'next_peer;
                        }
                    };

                    let mut current_count = match current_count_outer {
                        // Still the same block
                        Some(backup) => backup,
                        // Move to the next block
                        None => {
                            let (count, commitment) = state_diff_length_and_commitment_stream
                                .next()
                                .await
                                .with_context(|| {
                                    format!("Stream terminated prematurely at block {start}")
                                })
                                .map_err(peer_err)?
                                .map_err(peer_err)?;
                            current_count_outer = Some(count);
                            current_commitment = commitment;
                            count
                        }
                    };

                    tracing::trace!(block_number=%start, expected_responses=%current_count, "Expecting state diff responses");

                    let mut state_diff = StateUpdateData::default();

                    while let Some(state_diff_response) = responses.next().await {
                        tracing::trace!(?state_diff_response, "Received response");

                        match state_diff_response {
                            StateDiffsResponse::ContractDiff(ContractDiff {
                                address,
                                nonce,
                                class_hash,
                                values,
                                domain: _,
                            }) => {
                                let address = ContractAddress(address.0);

                                match current_count.checked_sub(values.len()) {
                                    Some(x) => current_count = x,
                                    None => {
                                        tracing::debug!(%peer, %start, "Too many storage diffs: {} > {}", values.len(), current_count);
                                        // TODO punish the peer

                                        // We can only get here in case of the last block, which means that the stream should be terminated
                                        debug_assert!(start == stop);
                                        break 'outer;
                                    }
                                }

                                if address == ContractAddress::ONE {
                                    let storage = &mut state_diff
                                        .system_contract_updates
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
                                    let update = &mut state_diff
                                        .contract_updates
                                        .entry(address)
                                        .or_default();
                                    values.into_iter().for_each(
                                        |ContractStoredValue { key, value }| {
                                            update
                                                .storage
                                                .insert(StorageAddress(key), StorageValue(value));
                                        },
                                    );

                                    if let Some(nonce) = nonce {
                                        match current_count.checked_sub(1) {
                                            Some(x) => current_count = x,
                                            None => {
                                                tracing::debug!(%peer, %start, "Too many nonce updates");
                                                // TODO punish the peer

                                                // We can only get here in case of the last block, which means that the stream should be terminated
                                                debug_assert!(start == stop);
                                                break 'outer;
                                            }
                                        }

                                        update.nonce = Some(ContractNonce(nonce));
                                    }

                                    if let Some(class_hash) = class_hash.map(|x| ClassHash(x.0)) {
                                        match current_count.checked_sub(1) {
                                            Some(x) => current_count = x,
                                            None => {
                                                tracing::debug!(%peer, %start, "Too many deployed contracts");
                                                // TODO punish the peer

                                                // We can only get here in case of the last block, which means that the stream should be terminated
                                                debug_assert!(start == stop);
                                                break 'outer;
                                            }
                                        }

                                        update.class =
                                            Some(ContractClassUpdate::Deploy(class_hash));
                                    }
                                }
                            }
                            StateDiffsResponse::DeclaredClass(DeclaredClass {
                                class_hash,
                                compiled_class_hash,
                            }) => {
                                if let Some(compiled_class_hash) = compiled_class_hash {
                                    state_diff.declared_sierra_classes.insert(
                                        SierraHash(class_hash.0),
                                        CasmHash(compiled_class_hash.0),
                                    );
                                } else {
                                    state_diff
                                        .declared_cairo_classes
                                        .insert(ClassHash(class_hash.0));
                                }

                                match current_count.checked_sub(1) {
                                    Some(x) => current_count = x,
                                    None => {
                                        tracing::debug!(%peer, %start, "Too many declared classes");
                                        // TODO punish the peer

                                        // We can only get here in case of the last block, which means that the stream should be terminated
                                        debug_assert!(start == stop);
                                        break 'outer;
                                    }
                                }
                            }
                            StateDiffsResponse::Fin => {
                                if current_count == 0 {
                                    if start == stop {
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

                        if current_count == 0 {
                            // All the counters for this block have been exhausted which means
                            // that the state update for this block is complete.
                            tracing::trace!(block_number=%start, "State diff received for block");

                            yield PeerData::new(
                                peer,
                                (
                                    UnverifiedStateUpdateData {
                                        expected_commitment: std::mem::take(&mut current_commitment),
                                        state_diff: std::mem::take(&mut state_diff),
                                    },
                                    start
                                )
                            );

                            if start < stop {
                                // Move to the next block
                                start += 1;
                                tracing::trace!(next_block=%start, "Moving to next block");
                                let (count, commitment) = state_diff_length_and_commitment_stream.next().await
                                    .ok_or_else(|| anyhow::anyhow!("Contract update counts stream terminated prematurely at block {start}"))
                                    .map_err(peer_err)?
                                    .map_err(peer_err)?;
                                current_count = count;
                                current_count_outer = Some(current_count);
                                current_commitment = commitment;

                                tracing::trace!(number=%current_count, "Expecting state diff responses");
                            }
                        }
                    }

                    // TODO punish the peer
                    // If we reach here, the peer did not send a Fin, so the counter for the current block should be reset
                    // and we should start from the current block again but from the next peer.
                    tracing::debug!(%peer, "Fin missing");
                }
            }
        }
    }
}

pub fn make_class_definition_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    declared_class_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, ClassesRequest) -> RF,
) -> impl futures::Stream<Item = Result<PeerData<ClassDefinition>, PeerData<anyhow::Error>>>
where
    PF: std::future::Future<Output = Vec<PeerId>>,
    RF: std::future::Future<
        Output = anyhow::Result<futures::channel::mpsc::Receiver<ClassesResponse>>,
    >,
{
    tracing::trace!(?start, ?stop, "Streaming classes");

    async_stream::try_stream! {
        pin_mut!(declared_class_counts_stream);

        let mut current_count_outer = None;

        if start <= stop {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = get_peers().await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
                    let limit = stop.get() - start.get() + 1;

                    let request = ClassesRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses =
                        match send_request(peer, request).await {
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
                                .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))
                                .map_err(peer_err)?
                                .map_err(peer_err)?;
                            current_count_outer = Some(x);
                            x
                        }
                    };

                    while start <= stop {
                        tracing::trace!(block_number=%start, expected_classes=%current_count, "Expecting class definition responses");

                        let mut class_definitions = Vec::new();

                        while current_count > 0 {
                            if let Some(class_definition) = responses.next().await {
                                match class_definition {
                                    ClassesResponse::Class(p2p_proto::class::Class::Cairo0 {
                                        class,
                                        domain: _,
                                    }) => {
                                        let CairoDefinition(definition) =
                                            CairoDefinition::try_from_dto(class).map_err(peer_err)?;
                                        class_definitions.push(ClassDefinition::Cairo {
                                            block_number: start,
                                            definition,
                                        });
                                    }
                                    ClassesResponse::Class(p2p_proto::class::Class::Cairo1 {
                                        class,
                                        domain: _,
                                    }) => {
                                        let definition = SierraDefinition::try_from_dto(class).map_err(peer_err)?;
                                        class_definitions.push(ClassDefinition::Sierra {
                                            block_number: start,
                                            sierra_definition: definition.0,
                                        });
                                    }
                                    ClassesResponse::Fin => {
                                        tracing::debug!(%peer, "Received FIN, continuing with next peer");
                                        continue 'next_peer;
                                    }
                                }

                                current_count -= 1;
                            } else {
                                // Stream closed before receiving all expected classes
                                tracing::debug!(%peer, "Premature class definition stream termination");
                                // TODO punish the peer
                                continue 'next_peer;
                            }
                        }

                        tracing::trace!(block_number=%start, "All classes received for block");

                        for class_definition in class_definitions {
                            yield PeerData::new(
                                peer,
                                class_definition,
                            );
                        }

                        if start == stop {
                            break 'outer;
                        }

                        start += 1;
                        current_count = declared_class_counts_stream.next().await
                            .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))
                            .map_err(peer_err)?
                            .map_err(peer_err)?;
                        current_count_outer = Some(current_count);

                        tracing::trace!(block_number=%start, expected_classes=%current_count, "Expecting class definition responses");
                    }

                    break 'outer;
                }
            }
        }
    }
}

pub fn make_event_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    event_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, EventsRequest) -> RF,
) -> impl futures::Stream<Item = Result<PeerData<EventsForBlockByTransaction>, PeerData<anyhow::Error>>>
where
    PF: std::future::Future<Output = Vec<PeerId>>,
    RF: std::future::Future<
        Output = anyhow::Result<futures::channel::mpsc::Receiver<EventsResponse>>,
    >,
{
    tracing::trace!(?start, ?stop, "Streaming events");

    async_stream::try_stream! {
        pin_mut!(event_counts_stream);

        let mut current_count_outer = None;

        if start <= stop {
            // Loop which refreshes peer set once we exhaust it.
            'outer: loop {
                let peers = get_peers().await;

                // Attempt each peer.
                'next_peer: for peer in peers {
                    let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
                    let limit = stop.get() - start.get() + 1;

                    let request = EventsRequest {
                        iteration: Iteration {
                            start: start.get().into(),
                            direction: Direction::Forward,
                            limit,
                            step: 1.into(),
                        },
                    };

                    let mut responses =
                        match send_request(peer, request).await {
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
                                .ok_or_else(|| anyhow::anyhow!("Event counts stream terminated prematurely at block {start}"))
                                .map_err(peer_err)?
                                .map_err(peer_err)?;
                            current_count_outer = Some(x);
                            x
                        }
                    };

                    while start <= stop {
                        tracing::trace!(block_number=%start, expected_responses=%current_count, "Expecting event responses");

                        let mut events: Vec<(TransactionHash, Vec<Event>)> = Vec::new();

                        while current_count > 0 {
                            if let Some(response) = responses.next().await {
                                match response {
                                    EventsResponse::Event(event) => {
                                        let txn_hash = TransactionHash(event.transaction_hash.0);
                                        let event = Event::try_from_dto(event).map_err(peer_err)?;

                                        match current_txn_hash {
                                            Some(x) if x == txn_hash => {
                                                // Same transaction
                                                events.last_mut().expect("not empty").1.push(event);
                                            }
                                            None | Some(_) => {
                                                // New transaction
                                                events.push((txn_hash, vec![event]));
                                                current_txn_hash = Some(txn_hash);
                                            }
                                        }
                                    }
                                    EventsResponse::Fin => {
                                        tracing::debug!(%peer, "Received FIN, continuing with next peer");
                                        continue 'next_peer;
                                    }
                                };

                                current_count -= 1;
                            } else {
                                // Stream closed before receiving all expected events for this block
                                tracing::debug!(%peer, block_number=%start, "Premature event stream termination");
                                // TODO punish the peer
                                continue 'next_peer;
                            }
                        }

                        tracing::trace!(block_number=%start, "All events received for block");

                        yield PeerData::new(
                            peer,
                            (start, std::mem::take(&mut events)),
                        );

                        if start == stop {
                            break 'outer;
                        }

                        start += 1;
                        current_count = event_counts_stream.next().await
                            .ok_or_else(|| anyhow::anyhow!("Event counts stream terminated prematurely at block {start}"))
                            .map_err(peer_err)?
                            .map_err(peer_err)?;
                        current_count_outer = Some(current_count);

                        tracing::trace!(next_block=%start, expected_responses=%current_count, "Moving to next block");
                    }

                    break 'outer;
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Dummy)]
pub struct Receipt {
    pub actual_fee: Fee,
    pub execution_resources: ExecutionResources,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_index: TransactionIndex,
}

impl From<pathfinder_common::receipt::Receipt> for Receipt {
    fn from(receipt: pathfinder_common::receipt::Receipt) -> Self {
        Self {
            actual_fee: receipt.actual_fee,
            execution_resources: receipt.execution_resources,
            l2_to_l1_messages: receipt.l2_to_l1_messages,
            execution_status: receipt.execution_status,
            transaction_index: receipt.transaction_index,
        }
    }
}

/// For a single block
#[derive(Clone, Debug, PartialEq)]
pub struct UnverifiedTransactionData {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(TransactionVariant, Receipt)>,
}

pub type UnverifiedTransactionDataWithBlockNumber = (UnverifiedTransactionData, BlockNumber);

/// For a single block
#[derive(Clone, PartialEq, Dummy, TaggedDebug)]
pub struct UnverifiedStateUpdateData {
    pub expected_commitment: StateDiffCommitment,
    pub state_diff: StateUpdateData,
}

pub type UnverifiedStateUpdateWithBlockNumber = (UnverifiedStateUpdateData, BlockNumber);

pub type EventsForBlockByTransaction = (BlockNumber, Vec<(TransactionHash, Vec<Event>)>);

#[derive(Debug, Clone, PartialEq, Eq, Default, Dummy)]
pub struct BlockHeader {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub eth_l1_gas_price: GasPrice,
    pub strk_l1_gas_price: GasPrice,
    pub eth_l1_data_gas_price: GasPrice,
    pub strk_l1_data_gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub event_commitment: EventCommitment,
    pub state_commitment: StateCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: usize,
    pub event_count: usize,
    pub l1_da_mode: L1DataAvailabilityMode,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: BlockCommitmentSignature,
    pub state_diff_commitment: StateDiffCommitment,
    pub state_diff_length: u64,
}

impl From<pathfinder_common::SignedBlockHeader> for SignedBlockHeader {
    fn from(h: pathfinder_common::SignedBlockHeader) -> Self {
        Self {
            header: h.header.into(),
            signature: h.signature,
            state_diff_commitment: h.state_diff_commitment,
            state_diff_length: h.state_diff_length,
        }
    }
}

impl From<pathfinder_common::BlockHeader> for BlockHeader {
    fn from(h: pathfinder_common::BlockHeader) -> Self {
        Self {
            hash: h.hash,
            parent_hash: h.parent_hash,
            number: h.number,
            timestamp: h.timestamp,
            eth_l1_gas_price: h.eth_l1_gas_price,
            strk_l1_gas_price: h.strk_l1_gas_price,
            eth_l1_data_gas_price: h.eth_l1_data_gas_price,
            strk_l1_data_gas_price: h.strk_l1_data_gas_price,
            sequencer_address: h.sequencer_address,
            starknet_version: h.starknet_version,
            event_commitment: h.event_commitment,
            state_commitment: h.state_commitment,
            transaction_commitment: h.transaction_commitment,
            transaction_count: h.transaction_count,
            event_count: h.event_count,
            l1_da_mode: h.l1_da_mode,
        }
    }
}

impl TryFrom<p2p_proto::header::SignedBlockHeader> for SignedBlockHeader {
    type Error = anyhow::Error;

    fn try_from(dto: p2p_proto::header::SignedBlockHeader) -> anyhow::Result<Self> {
        anyhow::ensure!(dto.signatures.len() == 1, "expected exactly one signature");
        let signature = dto
            .signatures
            .into_iter()
            .map(|sig| BlockCommitmentSignature {
                r: BlockCommitmentSignatureElem(sig.r),
                s: BlockCommitmentSignatureElem(sig.s),
            })
            .next()
            .expect("exactly one element");
        Ok(SignedBlockHeader {
            header: BlockHeader {
                hash: BlockHash(dto.block_hash.0),
                parent_hash: BlockHash(dto.parent_hash.0),
                number: BlockNumber::new(dto.number).context("block number > i64::MAX")?,
                timestamp: BlockTimestamp::new(dto.time).context("block timestamp > i64::MAX")?,
                eth_l1_gas_price: GasPrice(dto.gas_price_wei),
                strk_l1_gas_price: GasPrice(dto.gas_price_fri),
                eth_l1_data_gas_price: GasPrice(dto.data_gas_price_wei),
                strk_l1_data_gas_price: GasPrice(dto.data_gas_price_fri),
                sequencer_address: SequencerAddress(dto.sequencer_address.0),
                starknet_version: dto.protocol_version.parse()?,
                event_commitment: EventCommitment(dto.events.root.0),
                state_commitment: StateCommitment(dto.state_root.0),
                transaction_commitment: TransactionCommitment(dto.transactions.root.0),
                transaction_count: dto.transactions.n_leaves.try_into()?,
                event_count: dto.events.n_leaves.try_into()?,
                l1_da_mode: TryFromDto::try_from_dto(dto.l1_data_availability_mode)?,
            },
            signature,
            state_diff_commitment: StateDiffCommitment(dto.state_diff_commitment.root.0),
            state_diff_length: dto.state_diff_commitment.state_diff_length,
        })
    }
}

#[derive(Debug)]
pub struct IncorrectStateDiffCount(pub PeerId);

impl std::fmt::Display for IncorrectStateDiffCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Incorrect state diff count from peer {}", self.0)
    }
}

#[derive(Debug)]
pub enum ClassDefinitionsError {
    IncorrectClassDefinitionCount(PeerId),
    CairoDefinitionError(PeerId),
    SierraDefinitionError(PeerId),
}

impl std::fmt::Display for ClassDefinitionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassDefinitionsError::IncorrectClassDefinitionCount(peer) => {
                write!(f, "Incorrect class definition count from peer {}", peer)
            }
            ClassDefinitionsError::CairoDefinitionError(peer) => {
                write!(f, "Cairo class definition error from peer {}", peer)
            }
            ClassDefinitionsError::SierraDefinitionError(peer) => {
                write!(f, "Sierra class definition error from peer {}", peer)
            }
        }
    }
}
