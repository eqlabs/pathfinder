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

/// Receipt data as received via p2p which is missing some data in order
/// to make it equivalent to a proper [receipt](pathfinder_common::Receipt).
///
/// Provide the missing data via [PartialReceipt::complete] to unlock the full
/// receipt.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct PartialReceipt(pathfinder_common::receipt::Receipt);

impl PartialReceipt {
    /// This transformation is probably only useful in test scenarios.
    pub fn new(receipt: pathfinder_common::receipt::Receipt) -> Self {
        Self(receipt)
    }

    /// Fill in the missing receipt data, unlocking the full receipt.
    pub fn complete(
        self,
        hash: TransactionHash,
        index: TransactionIndex,
    ) -> pathfinder_common::receipt::Receipt {
        pathfinder_common::receipt::Receipt {
            transaction_hash: hash,
            transaction_index: index,
            ..self.0
        }
    }
}

impl TryFromDto<p2p_proto::receipt::Receipt> for PartialReceipt {
    fn try_from_dto(dto: p2p_proto::receipt::Receipt) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        use p2p_proto::receipt::Receipt as ProtoReceipt;
        let common = match dto {
            ProtoReceipt::Invoke(x) => x.common,
            ProtoReceipt::Declare(x) => x.common,
            ProtoReceipt::Deploy(x) => x.common,
            ProtoReceipt::DeployAccount(x) => x.common,
            ProtoReceipt::L1Handler(x) => x.common,
        };

        Ok(Self(pathfinder_common::receipt::Receipt {
            actual_fee: Fee(common.actual_fee),
            execution_resources: ExecutionResources {
                builtins: pathfinder_common::receipt::BuiltinCounters {
                    output: common.execution_resources.builtins.output.into(),
                    pedersen: common.execution_resources.builtins.pedersen.into(),
                    range_check: common.execution_resources.builtins.range_check.into(),
                    ecdsa: common.execution_resources.builtins.ecdsa.into(),
                    bitwise: common.execution_resources.builtins.bitwise.into(),
                    ec_op: common.execution_resources.builtins.ec_op.into(),
                    keccak: common.execution_resources.builtins.keccak.into(),
                    poseidon: common.execution_resources.builtins.poseidon.into(),
                    segment_arena: 0,
                },
                n_steps: common.execution_resources.steps.into(),
                n_memory_holes: common.execution_resources.memory_holes.into(),
                data_availability: pathfinder_common::receipt::ExecutionDataAvailability {
                    l1_gas: GasPrice::try_from(common.execution_resources.l1_gas)?.0,
                    l1_data_gas: GasPrice::try_from(common.execution_resources.l1_data_gas)?.0,
                },
            },
            l2_to_l1_messages: common
                .messages_sent
                .into_iter()
                .map(|x| L2ToL1Message {
                    from_address: ContractAddress(x.from_address),
                    payload: x
                        .payload
                        .into_iter()
                        .map(pathfinder_common::L2ToL1MessagePayloadElem)
                        .collect(),
                    to_address: ContractAddress::new_or_panic(
                        pathfinder_crypto::Felt::from_be_slice(x.to_address.0.as_bytes())
                            .expect("H160 should always fix in Felt"),
                    ),
                })
                .collect(),
            execution_status: match common.revert_reason {
                Some(reason) => ExecutionStatus::Reverted { reason },
                None => ExecutionStatus::Succeeded,
            },
            transaction_index: Default::default(),
            transaction_hash: Default::default(),
        }))
    }
}

#[derive(Clone, Debug)]
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

    pub async fn transactions_stream2(
        self,
        start: BlockNumber,
        stop_inclusive: BlockNumber,
    ) -> (
        PeerId,
        impl futures::Stream<Item = anyhow::Result<(TransactionVariant, PartialReceipt)>>,
    ) {
        let stream_request = TransactionsRequest {
            iteration: Iteration {
                start: start.get().into(),
                direction: Direction::Forward,
                limit: stop_inclusive.get() - start.get() + 1,
                step: 1.into(),
            },
        };

        // Select a random peer stream. The API from the p2p client isn't quite
        // ergonomic for this. It would be nice if the API was literally just
        // give me a random peer and stream that works.
        let (peer, stream) = 'stream_select: loop {
            let peers = self
                .get_update_peers_with_transaction_sync_capability()
                .await;

            for peer in peers {
                match self
                    .inner
                    .send_transactions_sync_request(peer, stream_request)
                    .await
                {
                    Ok(stream) => {
                        break 'stream_select (peer, stream);
                    }
                    Err(error) => {
                        tracing::debug!(%peer, reason=%error, "Transactions stream request failed");
                    }
                }
            }
        };

        // Parse and transform stream into something useable by sync.
        let stream = stream
            // We're technically ignoring a stream error from the peer by assumming the stream
            // ends after Fin is sent. We could in theory stream until Fin, and then ensure that
            // the stream is complete, if not punish the peer. However this is quite cumbersome.
            .take_while(|item| std::future::ready(!matches!(item, TransactionsResponse::Fin)))
            .map(|x| {
                let x = match x {
                    TransactionsResponse::TransactionWithReceipt(x) => x,
                    TransactionsResponse::Fin => unreachable!("Fin is skipped already"),
                };

                let TransactionWithReceipt {
                    transaction,
                    receipt,
                } = x;

                let transaction = TransactionVariant::try_from_dto(transaction)?;
                // We could actually already fill in the transaction hash here if we wished,
                // it just means the try_from_dto isn't quite as straight-forward.
                let receipt = PartialReceipt::try_from_dto(receipt)?;

                Ok((transaction, receipt))
            });

        (peer, stream)
    }

    pub fn transactions_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        transaction_counts_and_commitments_stream: impl futures::Stream<
            Item = anyhow::Result<(usize, TransactionCommitment)>,
        >,
    ) -> impl futures::Stream<Item = Result<PeerData<UnverifiedTransactionData>, PeerData<anyhow::Error>>>
    {
        async_stream::try_stream! {
            pin_mut!(transaction_counts_and_commitments_stream);

            let mut current_count_outer = None;
            let mut current_commitment = Default::default();

            if start <= stop_inclusive {
                // Loop which refreshes peer set once we exhaust it.
                'outer: loop {
                    let peers = self
                        .get_update_peers_with_sync_capability(protocol::Transactions::NAME)
                        .await;

                    // Attempt each peer.
                    'next_peer: for peer in peers {
                        let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
                        let limit = stop_inclusive.get() - start.get() + 1;

                        let request = TransactionsRequest {
                            iteration: Iteration {
                                start: start.get().into(),
                                direction: Direction::Forward,
                                limit,
                                step: 1.into(),
                            },
                        };

                        let mut responses = match self
                            .inner
                            .send_transactions_sync_request(peer, request)
                            .await
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
                                        Some(x) => current_count = x,
                                        None => {
                                            tracing::debug!(%peer, %start, "Too many transactions");
                                            // TODO punish the peer
                                            continue 'next_peer;
                                        }
                                    }

                                    transactions.push((t, r));
                                }
                                TransactionsResponse::Fin => {
                                    if transactions.is_empty() {
                                        if start == stop_inclusive {
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
                                    UnverifiedTransactionData {
                                        expected_commitment: std::mem::take(
                                            &mut current_commitment
                                        ),
                                        transactions: std::mem::take(&mut transactions),
                                    },
                                );

                                if start < stop_inclusive {
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
                    }
                }
            }
        }
    }

    /// ### Important
    ///
    /// Contract class updates are by default set to
    /// `ContractClassUpdate::Deploy` but __the caller is responsible for
    /// determining if the class was really deployed or replaced__.
    pub fn state_diff_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        state_diff_length_and_commitment_stream: impl futures::Stream<
            Item = anyhow::Result<(usize, StateDiffCommitment)>,
        >,
    ) -> impl futures::Stream<Item = Result<PeerData<UnverifiedStateUpdateData>, PeerData<anyhow::Error>>>
    {
        async_stream::try_stream! {
            tracing::trace!(?start, ?stop_inclusive, "Streaming state diffs");

            pin_mut!(state_diff_length_and_commitment_stream);

            let mut current_count_outer = None;
            let mut current_commitment = Default::default();

            if start <= stop_inclusive {
                // Loop which refreshes peer set once we exhaust it.
                'outer: loop {
                    let peers = self
                        .get_update_peers_with_sync_capability(protocol::StateDiffs::NAME)
                        .await;

                    // Attempt each peer.
                    'next_peer: for peer in peers {
                        let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
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
                                            continue 'next_peer;
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
                                                    continue 'next_peer;
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
                                                    continue 'next_peer;
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
                                            continue 'next_peer;
                                        }
                                    }
                                }
                                StateDiffsResponse::Fin => {
                                    if state_diff.is_empty() {
                                        if start == stop_inclusive {
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
                                    UnverifiedStateUpdateData {
                                        expected_commitment: std::mem::take(&mut current_commitment),
                                        state_diff: std::mem::take(&mut state_diff),
                                    },
                                );

                                if start < stop_inclusive {
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
                    }
                }
            }
        }
    }

    pub fn class_definition_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        declared_class_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<Item = Result<PeerData<ClassDefinition>, PeerData<anyhow::Error>>>
    {
        async_stream::try_stream! {
            tracing::trace!(?start, ?stop_inclusive, "Streaming classes");

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
                        let peer_err = |e: anyhow::Error| PeerData::new(peer, e);
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
                                    .ok_or_else(|| anyhow::anyhow!("Declared class counts stream terminated prematurely at block {start}"))
                                    .map_err(peer_err)?
                                    .map_err(peer_err)?;
                                current_count_outer = Some(x);
                                x
                            }
                        };

                        while start <= stop_inclusive {
                            tracing::trace!(block_number=%start, expected_classes=%current_count, "Expecting class definition responses");

                            let mut class_definitions = Vec::new();

                            while current_count > 0 {
                                if let Some(contract_diff) = responses.next().await {
                                    match contract_diff {
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
                                    };

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

                            if start == stop_inclusive {
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
    ) -> Option<(PeerId, StateUpdateData)> {
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

        'next_peer: for peer in peers {
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
                                // TODO punish the peer
                                continue 'next_peer;
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
                                        // TODO punish the peer
                                        continue 'next_peer;
                                    }
                                }
                                update.nonce = Some(ContractNonce(nonce));
                            }

                            if let Some(class_hash) = class_hash.map(|x| ClassHash(x.0)) {
                                match current_count.checked_sub(1) {
                                    Some(x) => current_count = x,
                                    None => {
                                        tracing::debug!(%peer, "Too many deployed contracts");
                                        // TODO punish the peer
                                        continue 'next_peer;
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
                                // TODO punish the peer
                                continue 'next_peer;
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
                            // TODO punish the peer
                            continue 'next_peer;
                        }
                        return Some((peer, state_diff));
                    }
                }
            }
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
    pub fn event_stream(
        self,
        mut start: BlockNumber,
        stop_inclusive: BlockNumber,
        event_counts_stream: impl futures::Stream<Item = anyhow::Result<usize>>,
    ) -> impl futures::Stream<Item = anyhow::Result<PeerData<EventsForBlockByTransaction>>> {
        tracing::trace!(?start, ?stop_inclusive, "Streaming events");

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

                        while start <= stop_inclusive {
                            tracing::trace!(block_number=%start, expected_responses=%current_count, "Expecting event responses");

                            let mut events: Vec<Vec<Event>> = Vec::new();

                            while current_count > 0 {
                                if let Some(response) = responses.next().await {
                                    match response {
                                        EventsResponse::Event(event) => {
                                            let txn_hash = TransactionHash(event.transaction_hash.0);
                                            let event = Event::try_from_dto(event)?;

                                            match current_txn_hash {
                                                Some(x) if x == txn_hash => {
                                                    // Same transaction
                                                    events.last_mut().expect("not empty").push(event);
                                                }
                                                None | Some(_) => {
                                                    // New transaction
                                                    events.push(vec![event]);
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

                            if start == stop_inclusive {
                                break 'outer;
                            }

                            start += 1;
                            current_count = event_counts_stream.next().await
                                .ok_or_else(|| anyhow::anyhow!("Event counts stream terminated prematurely at block {start}"))??;
                            current_count_outer = Some(current_count);

                            tracing::trace!(next_block=%start, expected_responses=%current_count, "Moving to next block");
                        }

                        break 'outer;
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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug)]
pub struct UnverifiedTransactionData {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(TransactionVariant, Receipt)>,
}

/// For a single block
#[derive(Clone, Debug)]
pub struct UnverifiedStateUpdateData {
    pub expected_commitment: StateDiffCommitment,
    pub state_diff: StateUpdateData,
}

pub type EventsForBlockByTransaction = (BlockNumber, Vec<Vec<Event>>);

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
