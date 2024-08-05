//! _High level_ client for p2p interaction.
//! Frees the caller from managing peers manually.
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use futures::channel::mpsc as fmpsc;
use futures::{pin_mut, Stream, StreamExt};
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
use pathfinder_common::state_update::{ContractClassUpdate, StateUpdateData};
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{
    BlockNumber,
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    SierraHash,
    SignedBlockHeader,
    StateDiffCommitment,
    StorageAddress,
    StorageValue,
    TransactionCommitment,
    TransactionHash,
    TransactionIndex,
};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;
pub mod traits;

use traits::{
    BlockClient,
    ClassStream,
    EventStream,
    HeaderStream,
    StateDiffStream,
    TransactionStream,
};

use crate::client::conv::{CairoDefinition, FromDto, SierraDefinition, TryFromDto};
use crate::client::peer_aware;
use crate::client::types::{
    ClassDefinition,
    ClassDefinitionsError,
    EventsForBlockByTransaction,
    IncorrectStateDiffCount,
    Receipt,
    UnverifiedStateUpdateData,
    UnverifiedTransactionData,
    UnverifiedTransactionDataWithBlockNumber,
};
use crate::peer_data::PeerData;

#[derive(Clone, Debug)]
pub struct Client {
    inner: peer_aware::Client,
    block_propagation_topic: Arc<String>,
    peers: Arc<RwLock<Decaying<HashSet<PeerId>>>>,
}

impl Client {
    pub fn new(inner: peer_aware::Client, block_propagation_topic: String) -> Self {
        Self {
            inner,
            block_propagation_topic: Arc::new(block_propagation_topic),
            peers: Default::default(),
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

    async fn get_random_peers(&self) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        let r = self.peers.read().await;
        let mut peers = if let Some(peers) = r.get() {
            peers.iter().copied().collect::<Vec<_>>()
        } else {
            // Avoid deadlock
            drop(r);
            let mut w = self.peers.write().await;
            // Check again because the previous lock in the queue might have been a write
            // lock that has already updated the peers.
            if let Some(peers) = w.get() {
                return peers.iter().copied().collect::<Vec<_>>();
            }

            let mut peers = self
                .inner
                .get_closest_peers(PeerId::random())
                .await
                .unwrap_or_default();

            // We could be on the list
            peers.remove(self.inner.peer_id());

            let peers_vec = peers.iter().copied().collect::<Vec<_>>();

            w.update(peers);
            peers_vec
        };
        peers.shuffle(&mut rand::thread_rng());
        peers
    }
}

impl HeaderStream for Client {
    fn header_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        reverse: bool,
    ) -> impl Stream<Item = PeerData<SignedBlockHeader>> {
        let inner = self.inner.clone();
        let outer = self;
        make_header_stream(
            start,
            stop,
            reverse,
            move || {
                let outer = outer.clone();
                async move { outer.get_random_peers().await }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_headers_sync_request(peer, request).await }
            },
        )
    }
}

impl TransactionStream for Client {
    fn transaction_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        transaction_counts_and_commitments_stream: impl Stream<Item = anyhow::Result<(usize, TransactionCommitment)>>
            + Send
            + 'static,
    ) -> impl Stream<Item = PeerData<(UnverifiedTransactionData, BlockNumber)>> {
        let inner = self.inner.clone();
        let outer = self;
        make_transaction_stream(
            start,
            stop,
            transaction_counts_and_commitments_stream,
            move || {
                let outer = outer.clone();
                async move { outer.get_random_peers().await }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_transactions_sync_request(peer, request).await }
            },
        )
    }
}

impl StateDiffStream for Client {
    /// ### Important
    ///
    /// Contract class updates are by default set to
    /// `ContractClassUpdate::Deploy` but __the caller is responsible for
    /// determining if the class was really deployed or replaced__.
    fn state_diff_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        state_diff_length_and_commitment_stream: impl Stream<
            Item = anyhow::Result<(usize, StateDiffCommitment)>,
        >,
    ) -> impl Stream<
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
                async move { outer.get_random_peers().await }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_state_diffs_sync_request(peer, request).await }
            },
        )
    }
}

impl ClassStream for Client {
    fn class_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        declared_class_counts_stream: impl Stream<Item = anyhow::Result<usize>>,
    ) -> impl Stream<Item = Result<PeerData<ClassDefinition>, PeerData<anyhow::Error>>> {
        let inner = self.inner.clone();
        let outer = self;
        make_class_definition_stream(
            start,
            stop,
            declared_class_counts_stream,
            move || {
                let outer = outer.clone();
                async move { outer.get_random_peers().await }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_classes_sync_request(peer, request).await }
            },
        )
    }
}

impl EventStream for Client {
    /// ### Important
    ///
    /// Events are grouped by block and by transaction. The order of flattened
    /// events in a block is guaranteed to be correct because the event
    /// commitment is part of block hash. However the number of events per
    /// transaction for __pre 0.13.2__ Starknet blocks is __TRUSTED__
    /// because neither signature nor block hash contain this information.
    fn event_stream(
        self,
        start: BlockNumber,
        stop: BlockNumber,
        event_counts_stream: impl Stream<Item = anyhow::Result<usize>>,
    ) -> impl Stream<Item = Result<PeerData<EventsForBlockByTransaction>, PeerData<anyhow::Error>>>
    {
        let inner = self.inner.clone();
        let outer = self;
        make_event_stream(
            start,
            stop,
            event_counts_stream,
            move || {
                let outer = outer.clone();
                async move { outer.get_random_peers().await }
            },
            move |peer, request| {
                let inner = inner.clone();
                async move { inner.send_events_sync_request(peer, request).await }
            },
        )
    }
}

impl BlockClient for Client {
    async fn transactions_for_block(
        self,
        block: BlockNumber,
    ) -> Option<(
        PeerId,
        impl Stream<Item = anyhow::Result<(TransactionVariant, Receipt)>>,
    )> {
        let request = TransactionsRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self.get_random_peers().await;

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

    async fn state_diff_for_block(
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

        let peers = self.get_random_peers().await;

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

    async fn class_definitions_for_block(
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

        let peers = self.get_random_peers().await;

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

    async fn events_for_block(
        self,
        block: BlockNumber,
    ) -> Option<(PeerId, impl Stream<Item = (TransactionHash, Event)>)> {
        let request = EventsRequest {
            iteration: Iteration {
                start: block.get().into(),
                direction: Direction::Forward,
                limit: 1,
                step: 1.into(),
            },
        };

        let peers = self.get_random_peers().await;

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
}

pub fn make_header_stream<PF, RF>(
    start: BlockNumber,
    stop: BlockNumber,
    reverse: bool,
    get_peers: impl Fn() -> PF + Send + 'static,
    send_request: impl Fn(PeerId, BlockHeadersRequest) -> RF + Send + 'static,
) -> impl Stream<Item = PeerData<SignedBlockHeader>>
where
    PF: Future<Output = Vec<PeerId>> + Send,
    RF: Future<Output = anyhow::Result<fmpsc::Receiver<BlockHeadersResponse>>> + Send,
{
    let start: i64 = start.get().try_into().expect("block number <= i64::MAX");
    let stop: i64 = stop.get().try_into().expect("block number <= i64::MAX");

    let (mut start, stop, direction) = match reverse {
        true => (stop, start, Direction::Backward),
        false => (start, stop, Direction::Forward),
    };

    tracing::trace!(?start, ?stop, ?direction, "Streaming headers");

    fn done(direction: Direction, start: i64, stop: i64) -> bool {
        match direction {
            Direction::Forward => start > stop,
            Direction::Backward => start < stop,
        }
    }

    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        // Loop which refreshes peer set once we exhaust it.
        'outer: loop {
            let peers = get_peers().await;

            // Attempt each peer.
            'next_peer: for peer in peers {
                let limit = start.max(stop) - start.min(stop) + 1;

                let request = BlockHeadersRequest {
                    iteration: Iteration {
                        start: u64::try_from(start).expect("start >= 0").into(),
                        direction,
                        limit: limit.try_into().expect("limit >= 0"),
                        step: 1.into(),
                    },
                };

                let mut responses = match send_request(peer, request).await {
                    Ok(x) => x,
                    Err(error) => {
                        // Failed to establish connection, try next peer.
                        tracing::debug!(%peer, reason=%error, "Headers request failed");
                        continue 'next_peer;
                    }
                };

                while let Some(signed_header) = responses.next().await {
                    // It can be a finishing FIN or an extra header or even a malformed message
                    // but we ignore it regardless because we have all the data we need

                    match signed_header {
                        BlockHeadersResponse::Header(hdr) => {
                            match SignedBlockHeader::try_from_dto(*hdr) {
                                Ok(hdr) => {
                                    if done(direction, start, stop) {
                                        tracing::debug!(%peer, "Header stream Fin missing, got extra header instead");
                                        break 'outer;
                                    }

                                    _ = tx.send(PeerData::new(peer, hdr)).await;

                                    start = match direction {
                                        Direction::Forward => start + 1,
                                        Direction::Backward => start - 1,
                                    };
                                }
                                Err(error) => {
                                    tracing::debug!(%peer, %error, "Header stream failed");
                                    if done(direction, start, stop) {
                                        break 'outer;
                                    }
                                    continue 'next_peer;
                                }
                            }
                        }
                        BlockHeadersResponse::Fin => {
                            tracing::debug!(%peer, "Header stream Fin");
                            if done(direction, start, stop) {
                                break 'outer;
                            }
                            continue 'next_peer;
                        }
                    };
                }

                // Stream ended without FIN but we could already have all the responses we need
                if done(direction, start, stop) {
                    break 'outer;
                }

                // TODO: track how much and how fast this peer responded with
                // i.e. don't let them drip feed us etc.
            }
        }
    });

    ReceiverStream::new(rx)
}

/// Caller must guarantee `start <= stop`
pub fn make_transaction_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    transaction_counts_and_commitments_stream: impl Stream<Item = anyhow::Result<(usize, TransactionCommitment)>>
        + Send
        + 'static,
    get_peers: impl Fn() -> PF + Send + 'static,
    send_request: impl Fn(PeerId, TransactionsRequest) -> RF + Send + 'static,
) -> impl Stream<Item = PeerData<UnverifiedTransactionDataWithBlockNumber>>
where
    PF: Future<Output = Vec<PeerId>> + Send,
    RF: Future<Output = anyhow::Result<fmpsc::Receiver<TransactionsResponse>>> + Send,
{
    tracing::trace!(?start, ?stop, "Streaming Transactions");

    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        pin_mut!(transaction_counts_and_commitments_stream);

        let Some(Ok(mut current_outer)) = transaction_counts_and_commitments_stream.next().await
        else {
            tracing::debug!("Transaction counts and commitments stream terminated prematurely");
            return;
        };

        // Loop which refreshes peer set once we exhaust it.
        'outer: loop {
            'next_peer: for peer in get_peers().await {
                let request = TransactionsRequest {
                    iteration: Iteration {
                        start: start.get().into(),
                        direction: Direction::Forward,
                        limit: stop.get() - start.get() + 1,
                        step: 1.into(),
                    },
                };

                let mut responses = match send_request(peer, request).await {
                    Ok(x) => x,
                    Err(error) => {
                        tracing::debug!(%peer, reason=%error, "Transactions request failed");
                        continue 'next_peer;
                    }
                };

                let mut transactions = Vec::new();
                let mut current = current_outer;
                tracing::trace!(number=%current.0, "Expecting transaction responses");

                while let Some(response) = responses.next().await {
                    match response {
                        TransactionsResponse::TransactionWithReceipt(TransactionWithReceipt {
                            transaction,
                            receipt,
                        }) => {
                            let (Ok(t), Ok(r)) = (
                                TransactionVariant::try_from_dto(transaction),
                                Receipt::try_from((
                                    receipt,
                                    TransactionIndex::new_or_panic(
                                        transactions.len().try_into().expect("ptr size is 64bits"),
                                    ),
                                )),
                            ) else {
                                // TODO punish the peer
                                tracing::debug!(%peer, "Transaction or receipt failed to parse");
                                continue 'next_peer;
                            };

                            match current.0.checked_sub(1) {
                                Some(x) => {
                                    current.0 = x;
                                    transactions.push((t, r));
                                }
                                None => {
                                    // TODO punish the peer
                                    tracing::debug!(%peer, %start, %stop, "Too many transactions");
                                    // We can only get here in case of the last block, which means
                                    // that the stream should be terminated
                                    debug_assert!(start == stop);
                                    break 'outer;
                                }
                            }
                        }
                        TransactionsResponse::Fin => {
                            if current.0 > 0 {
                                // TODO punish the peer
                                tracing::debug!(%peer, "Premature transaction stream Fin");
                                continue 'next_peer;
                            }

                            if start == stop {
                                // We're done, terminate the stream
                                break 'outer;
                            }
                        }
                    };

                    if current.0 == 0 {
                        // The counter for this block has been exhausted which means that this block
                        // is complete.
                        tracing::trace!(block_number=%start, "All transactions received for block");

                        _ = tx
                            .send(PeerData::new(
                                peer,
                                (
                                    UnverifiedTransactionData {
                                        expected_commitment: std::mem::take(&mut current.1),
                                        transactions: std::mem::take(&mut transactions),
                                    },
                                    start,
                                ),
                            ))
                            .await;

                        if start < stop {
                            // Move to the next block
                            start += 1;
                            tracing::trace!(next_block=%start, "Moving to next block");

                            if let Some(Ok(x)) =
                                transaction_counts_and_commitments_stream.next().await
                            {
                                current_outer = x;
                                current = x;
                            } else {
                                tracing::debug!(%peer, "Transaction counts and commitments stream terminated prematurely");
                                break 'outer;
                            };
                        }
                    }
                }

                // TODO punish the peer
                tracing::debug!(%peer, "Fin missing");
                // The above situation can also happen when we've received all the data we need
                // but the last peer has not sent a Fin.
                if current.0 == 0 && start == stop {
                    // We're done, terminate the stream
                    break 'outer;
                }
            }
        }
    });

    ReceiverStream::new(rx)
}

pub fn make_state_diff_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    state_diff_length_and_commitment_stream: impl Stream<
        Item = anyhow::Result<(usize, StateDiffCommitment)>,
    >,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, StateDiffsRequest) -> RF,
) -> impl Stream<
    Item = Result<PeerData<(UnverifiedStateUpdateData, BlockNumber)>, PeerData<anyhow::Error>>,
>
where
    PF: Future<Output = Vec<PeerId>>,
    RF: Future<Output = anyhow::Result<fmpsc::Receiver<StateDiffsResponse>>>,
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

                    // The above situation can also happen when we've received all the data we need
                    // but the last peer has not sent a Fin.
                    if current_count == 0 && start == stop {
                        // We're done, terminate the stream
                        break 'outer;
                    }
                }
            }
        }
    }
}

pub fn make_class_definition_stream<PF, RF>(
    mut start: BlockNumber,
    stop: BlockNumber,
    declared_class_counts_stream: impl Stream<Item = anyhow::Result<usize>>,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, ClassesRequest) -> RF,
) -> impl Stream<Item = Result<PeerData<ClassDefinition>, PeerData<anyhow::Error>>>
where
    PF: Future<Output = Vec<PeerId>>,
    RF: Future<Output = anyhow::Result<fmpsc::Receiver<ClassesResponse>>>,
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
    event_counts_stream: impl Stream<Item = anyhow::Result<usize>>,
    get_peers: impl Fn() -> PF,
    send_request: impl Fn(PeerId, EventsRequest) -> RF,
) -> impl Stream<Item = Result<PeerData<EventsForBlockByTransaction>, PeerData<anyhow::Error>>>
where
    PF: Future<Output = Vec<PeerId>>,
    RF: Future<Output = anyhow::Result<fmpsc::Receiver<EventsResponse>>>,
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
struct Decaying<T> {
    data: T,
    last_update: Instant,
    timeout: Duration,
}

impl<T: Default> Decaying<T> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            data: Default::default(),
            last_update: Instant::now(),
            timeout,
        }
    }

    /// Does not clear if elapsed, instead the caller is expected to call
    /// [`Self::update`]
    pub fn get(&self) -> Option<&T> {
        if self.last_update.elapsed() > self.timeout {
            None
        } else {
            Some(&self.data)
        }
    }

    pub fn update(&mut self, data: T) {
        self.last_update = Instant::now();
        self.data = data;
    }
}

impl<T: Default> Default for Decaying<T> {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}
