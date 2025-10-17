use std::collections::{HashMap, HashSet};
use std::pin;

use anyhow::Context;
use futures::stream::BoxStream;
use futures::{pin_mut, Stream, StreamExt, TryStreamExt};
use p2p::libp2p::PeerId;
use p2p::sync::client::peer_agnostic::traits::{BlockClient, HeaderStream};
use p2p::sync::client::peer_agnostic::Client as P2PClient;
use p2p::sync::client::types::{
    ClassDefinition as P2PClassDefinition,
    ClassDefinitionsError,
    EventsResponseStreamFailure,
    StateDiffsError,
    TransactionData,
};
use p2p::PeerData;
use pathfinder_block_hashes::BlockHashDb;
use pathfinder_common::event::Event;
use pathfinder_common::prelude::*;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::{DeclaredClasses, StateUpdateData};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::ConsensusInfo;
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_merkle_tree::starknet_state::update_starknet_state;
use pathfinder_storage::Storage;
use primitive_types::H160;
use starknet_gateway_client::GatewayApi;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use util::error::AnyhowExt;

use super::class_definitions::CompiledClass;
use super::{state_updates, transactions};
use crate::sync::class_definitions::{self, ClassWithLayout};
use crate::sync::error::SyncError;
use crate::sync::stream::{ProcessStage, SyncReceiver, SyncResult};
use crate::sync::{events, headers};

type EventsWithCommitment = (
    EventCommitment,
    Vec<TransactionHash>,
    HashMap<TransactionHash, Vec<Event>>,
    StarknetVersion,
);

#[allow(clippy::too_many_arguments)]
pub fn spawn(
    storage: pathfinder_storage::Storage,
    p2p_sync_client: p2p::sync::client::peer_agnostic::Client,
    mut catch_up_start: watch::Receiver<Option<u64>>,
    mut consensus_info_rx: watch::Receiver<Option<ConsensusInfo>>,
    store_block_tx: mpsc::Sender<BlockData>,
    fgw_client: starknet_gateway_client::Client,
    eth_client: pathfinder_ethereum::EthereumClient,
    eth_address: H160,
    chain_id: ChainId,
    gateway_public_key: PublicKey,
    l1_checkpoint_override: Option<EthereumStateUpdate>,
    block_hash_db: Option<BlockHashDb>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let task = async move {
        loop {
            // Wait until Consensus notifies us that the node has fallen behind the rest of
            // the network.
            catch_up_start
                .changed()
                .await
                .context("Sender should not be dropped")?;
            let mut next = catch_up_start
                .borrow()
                .map(BlockNumber::new_or_panic)
                // Should start out as `None` then write `Some(height)` when we fall behind at
                // that height.
                .expect("Consensus should not send None");
            let mut parent_hash = {
                let mut db_conn = storage.connection().context("Opening DB connection")?;
                let mut db_tx = db_conn.transaction().context("Starting DB transaction")?;
                db_tx
                    .block_hash(next.into())
                    .context("Querying for block hash")?
                    .unwrap_or(BlockHash::ZERO)
            };

            tracing::info!(start_block=%next, "Starting catch-up sync");

            let mut result = catch_up(
                &mut next,
                &mut parent_hash,
                p2p_sync_client.clone(),
                fgw_client.clone(),
                consensus_info_rx.clone(),
                store_block_tx.clone(),
                storage.clone(),
                chain_id,
                gateway_public_key,
                block_hash_db.clone(),
            )
            .await;

            match result {
                Ok(_) => {
                    tracing::debug!("Catch-up sync complete");
                    return Ok(());
                }
                Err(SyncError::Fatal(mut error)) => {
                    tracing::error!(?error, "Stopping catch-up sync");
                    return Err(error.take_or_deep_clone());
                }
                Err(error) => {
                    tracing::debug!(%error, "Restarting catch-up sync");
                    handle_recoverable_error(&error).await;
                }
            }
        }

        Ok(())
    };

    util::task::spawn(task)
}

/// `next` and `parent_hash` will be advanced each time a block is stored.
#[allow(clippy::too_many_arguments)]
async fn catch_up(
    next: &mut BlockNumber,
    parent_hash: &mut BlockHash,
    p2p_sync_client: p2p::sync::client::peer_agnostic::Client,
    fgw_client: starknet_gateway_client::Client,
    consensus_info_rx: watch::Receiver<Option<ConsensusInfo>>,
    store_block_tx: mpsc::Sender<BlockData>,
    storage: Storage,
    chain_id: ChainId,
    gateway_public_key: PublicKey,
    block_hash_db: Option<pathfinder_block_hashes::BlockHashDb>,
) -> Result<(), SyncError> {
    // TODO: This never happens for a node that joins the network late.
    // Wait for the first consensus height to be available.
    // self.consensus_info_rx
    //     .wait_for(Option::is_some)
    //     .await
    //     .expect("Sender should not be dropped");

    let storage_connection = storage
        .connection()
        .context("Creating database connection")?;

    let mut headers = HeaderSource {
        p2p: p2p_sync_client.clone(),
        consensus_info_rx: consensus_info_rx.clone(),
        start: *next,
    }
    .spawn()
    .pipe(headers::ForwardContinuity::new(*next, *parent_hash), 100)
    .pipe(
        // TODO: Consensus blocks do not have a signature ATM, so this would fail. However, we
        // never even receive requested blocks because `sync_handlers::get_header` only returns
        // headers with valid signatures.
        //
        // https://github.com/eqlabs/pathfinder/issues/2941
        headers::VerifyHashAndSignature::new(chain_id, gateway_public_key, block_hash_db),
        100,
    );

    let HeaderFanout {
        headers,
        events,
        state_diff,
        transactions,
    } = HeaderFanout::from_source(headers, 10);

    let transactions = TransactionSource {
        p2p: p2p_sync_client.clone(),
        headers: transactions,
    }
    .spawn()
    .pipe(transactions::CalculateHashes(chain_id), 10)
    .pipe(transactions::VerifyCommitment, 10);

    let TransactionsFanout {
        transactions,
        events: transactions_for_events,
    } = TransactionsFanout::from_source(transactions, 10);

    let events = EventSource {
        p2p: p2p_sync_client.clone(),
        headers: events,
        transactions: transactions_for_events,
    }
    .spawn()
    .pipe(events::VerifyCommitment, 10);

    let state_diff = StateDiffSource {
        p2p: p2p_sync_client.clone(),
        headers: state_diff,
    }
    .spawn()
    .pipe(state_updates::VerifyCommitment, 10);

    let StateDiffFanout {
        state_diff,
        declarations_1,
        declarations_2,
    } = StateDiffFanout::from_source(state_diff, 10);

    let classes = ClassSource {
        p2p: p2p_sync_client.clone(),
        declarations: declarations_1,
        start: *next,
    }
    .spawn()
    .pipe(class_definitions::VerifyLayout, 10)
    .pipe(class_definitions::VerifyHash, 10)
    .pipe(
        class_definitions::CompileSierraToCasm::new(fgw_client, tokio::runtime::Handle::current()),
        10,
    )
    .pipe(
        class_definitions::VerifyClassHashes {
            declarations: declarations_2,
            tokio_handle: tokio::runtime::Handle::current(),
        },
        10,
    );

    let mut block_stream = BlockStream {
        header: headers,
        events,
        state_diff,
        transactions,
        classes,
    }
    .spawn()
    .into_stream();

    while let Some(result) = block_stream.next().await {
        let PeerData {
            data: block_data, ..
        } = result?;
        // TODO: unwrap
        // let ConsensusInfo {
        //     highest_decided_height,
        //     ..
        // } = self
        //     .coordination_with_consensus
        //     .consensus_info
        //     .borrow()
        //     .unwrap();

        // if stored_block_number >= highest_decided_height {
        //     tracing::info!(
        //         node_latest=%stored_block_number,
        //         decided_height=%highest_decided_height,
        //         "Caught up to consensus"
        //     );
        //     break;
        // }

        // Update the next block and parent hash for the next iteration.
        *next = block_data.header.header.number + 1;
        *parent_hash = block_data.header.header.parent_hash;

        store_block_tx.send(block_data).await.unwrap();
    }

    Ok(())
}

async fn handle_recoverable_error(err: &SyncError) {
    // TODO
    tracing::debug!(%err, "Log and punish as appropriate");
}

struct HeaderSource<P> {
    p2p: P,
    consensus_info_rx: watch::Receiver<Option<ConsensusInfo>>,
    start: BlockNumber,
}

impl<P> HeaderSource<P> {
    fn spawn(self) -> SyncReceiver<SignedBlockHeader>
    where
        P: Clone + HeaderStream + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let Self {
            p2p,
            consensus_info_rx,
            mut start,
        } = self;

        util::task::spawn(async move {
            //loop {
            // TODO: Use `consensus_info` to determine when to stop syncing blocks once the
            // following is fixed - for some reason, a node that joins the consensus network
            // late and is thus behind the latest agreed height, will never set
            // the `consensus_info` watched value to `Some`.
            //
            // let highest_decided_height = consensus_info_rx
            //     .borrow()
            //     .unwrap()
            //     .highest_decided_height;
            let mut headers = Box::pin(p2p.clone().header_stream(start, start + 10, false));

            while let Some(header) = headers.next().await {
                start = header.data.header.number + 1;

                if tx.send(Ok(header)).await.is_err() {
                    return;
                }
            }
            //}
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct HeaderFanout {
    headers: SyncReceiver<SignedBlockHeader>,
    events: BoxStream<'static, BlockHeader>,
    state_diff: BoxStream<'static, SignedBlockHeader>,
    transactions: BoxStream<'static, BlockHeader>,
}

impl HeaderFanout {
    fn from_source(mut source: SyncReceiver<SignedBlockHeader>, buffer: usize) -> Self {
        let (h_tx, h_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(buffer);
        let (t_tx, t_rx) = tokio::sync::mpsc::channel(buffer);

        util::task::spawn(async move {
            while let Some(signed_header) = source.recv().await {
                let is_err = signed_header.is_err();

                if h_tx.send(signed_header.clone()).await.is_err() || is_err {
                    return;
                }

                let signed_header = signed_header.expect("Error case already handled").data;
                let header = signed_header.header.clone();

                if e_tx.send(header.clone()).await.is_err() {
                    return;
                }

                if s_tx.send(signed_header).await.is_err() {
                    return;
                }

                if t_tx.send(header).await.is_err() {
                    return;
                }
            }
        });

        Self {
            headers: SyncReceiver::from_receiver(h_rx),
            events: ReceiverStream::new(e_rx).boxed(),
            state_diff: ReceiverStream::new(s_rx).boxed(),
            transactions: ReceiverStream::new(t_rx).boxed(),
        }
    }
}

struct TransactionSource<P> {
    p2p: P,
    headers: BoxStream<'static, BlockHeader>,
}

impl<P> TransactionSource<P> {
    fn spawn(
        self,
    ) -> SyncReceiver<(
        TransactionData,
        BlockNumber,
        StarknetVersion,
        TransactionCommitment,
    )>
    where
        P: Clone + BlockClient + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        util::task::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, mut transactions) = loop {
                    if let Some(stream) = p2p.clone().transactions_for_block(header.number).await {
                        break stream;
                    }
                };

                let transaction_count = header.transaction_count;
                let mut transactions_vec = Vec::new();

                pin_mut!(transactions);

                // Receive the exact amount of expected events for this block.
                for _ in 0..transaction_count {
                    let (transaction, receipt) = match transactions.next().await {
                        Some(Ok((transaction, receipt))) => (transaction, receipt),
                        Some(Err(_)) => {
                            let _ = tx.send(Err(SyncError::InvalidDto(peer))).await;
                            return;
                        }
                        None => {
                            let _ = tx.send(Err(SyncError::TooFewTransactions(peer))).await;
                            return;
                        }
                    };

                    transactions_vec.push((transaction, receipt));
                }

                // Ensure that the stream is exhausted.
                if transactions.next().await.is_some() {
                    let _ = tx.send(Err(SyncError::TooManyTransactions(peer))).await;
                    return;
                }

                let _ = tx
                    .send(Ok(PeerData::new(
                        peer,
                        (
                            transactions_vec,
                            header.number,
                            header.starknet_version,
                            header.transaction_commitment,
                        ),
                    )))
                    .await;
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct TransactionsFanout {
    transactions: SyncReceiver<Vec<(Transaction, Receipt)>>,
    events: BoxStream<'static, Vec<TransactionHash>>,
}

impl TransactionsFanout {
    fn from_source(mut source: SyncReceiver<Vec<(Transaction, Receipt)>>, buffer: usize) -> Self {
        let (t_tx, t_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);

        util::task::spawn(async move {
            while let Some(transactions) = source.recv().await {
                let is_err = transactions.is_err();

                if t_tx.send(transactions.clone()).await.is_err() || is_err {
                    return;
                }

                let transactions = transactions.expect("Error case already handled").data;

                if e_tx
                    .send(transactions.iter().map(|(tx, _)| tx.hash).collect())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        Self {
            transactions: SyncReceiver::from_receiver(t_rx),
            events: ReceiverStream::new(e_rx).boxed(),
        }
    }
}

struct StateDiffFanout {
    state_diff: SyncReceiver<StateUpdateData>,
    declarations_1: BoxStream<'static, DeclaredClasses>,
    declarations_2: BoxStream<'static, DeclaredClasses>,
}

impl StateDiffFanout {
    fn from_source(
        mut source: SyncReceiver<(StateUpdateData, BlockNumber)>,
        buffer: usize,
    ) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(buffer);
        let (d1_tx, d1_rx) = tokio::sync::mpsc::channel(buffer);
        let (d2_tx, d2_rx) = tokio::sync::mpsc::channel(buffer);

        util::task::spawn(async move {
            while let Some(state_update) = source.recv().await {
                let is_err = state_update.is_err();

                if s_tx
                    .send(state_update.clone().map(|x| x.map(|(sud, _)| sud)))
                    .await
                    .is_err()
                    || is_err
                {
                    return;
                }

                let class_declarations = state_update
                    .expect("Error case already handled")
                    .data
                    .0
                    .declared_classes();

                if d1_tx.send(class_declarations.clone()).await.is_err() {
                    return;
                }

                if d2_tx.send(class_declarations).await.is_err() {
                    return;
                }
            }
        });

        Self {
            state_diff: SyncReceiver::from_receiver(s_rx),
            declarations_1: ReceiverStream::new(d1_rx).boxed(),
            declarations_2: ReceiverStream::new(d2_rx).boxed(),
        }
    }
}

struct EventSource<P> {
    p2p: P,
    headers: BoxStream<'static, BlockHeader>,
    transactions: BoxStream<'static, Vec<TransactionHash>>,
}

impl<P> EventSource<P> {
    fn spawn(self) -> SyncReceiver<EventsWithCommitment>
    where
        P: Clone + BlockClient + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        util::task::spawn(async move {
            let Self {
                p2p,
                mut transactions,
                mut headers,
            } = self;

            while let Some(header) = headers.next().await {
                let Some(block_transactions) = transactions.next().await else {
                    // Expected transactions stream ended prematurely which means there was an error
                    // at the source and track sync should be restarted. We should not signal an
                    // error here as the error has already been indicated at the
                    // transactions source.
                    return;
                };

                let (peer, mut events) = loop {
                    if let Some(stream) = p2p.clone().events_for_block(header.number).await {
                        break stream;
                    }
                };

                let mut block_events: HashMap<_, Vec<Event>> = HashMap::new();
                let event_count = header.event_count;

                pin_mut!(events);

                // Receive the exact amount of expected events for this block.
                for _ in 0..event_count {
                    match events.next().await {
                        Some(Ok((tx_hash, event))) => {
                            block_events.entry(tx_hash).or_default().push(event);
                        }
                        Some(Err(_)) => {
                            let _ = tx.send(Err(SyncError::InvalidDto(peer))).await;
                            return;
                        }
                        None => {
                            let _ = tx.send(Err(SyncError::TooFewEvents(peer))).await;
                            return;
                        }
                    }
                }

                // Ensure that the stream is exhausted.
                if events.next().await.is_some() {
                    let _ = tx.send(Err(SyncError::TooManyEvents(peer))).await;
                    return;
                }

                if tx
                    .send(Ok(PeerData::new(
                        peer,
                        (
                            header.event_commitment,
                            block_transactions,
                            block_events,
                            header.starknet_version,
                        ),
                    )))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct StateDiffSource<P> {
    p2p: P,
    headers: BoxStream<'static, SignedBlockHeader>,
}

impl<P> StateDiffSource<P> {
    fn spawn(self) -> SyncReceiver<(StateUpdateData, BlockNumber, StateDiffCommitment)>
    where
        P: Clone + BlockClient + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        util::task::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, state_diff) = loop {
                    let state_diff = p2p
                        .clone()
                        .state_diff_for_block(header.header.number, header.header.state_diff_length)
                        .await;
                    match state_diff {
                        Ok(Some(state_diff)) => break state_diff,
                        Ok(None) => {}
                        Err(StateDiffsError::IncorrectStateDiffCount(peer)) => {
                            let _ = tx.send(Err(SyncError::IncorrectStateDiffCount(peer))).await;
                            return;
                        }
                        Err(StateDiffsError::ResponseStreamFailure(peer, _)) => {
                            let _ = tx.send(Err(SyncError::InvalidDto(peer))).await;
                            return;
                        }
                    }
                };

                if tx
                    .send(Ok(PeerData::new(
                        peer,
                        (
                            state_diff,
                            header.header.number,
                            header.header.state_diff_commitment,
                        ),
                    )))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct ClassSource<P> {
    p2p: P,
    declarations: BoxStream<'static, DeclaredClasses>,
    start: BlockNumber,
}

impl<P> ClassSource<P> {
    fn spawn(self) -> SyncReceiver<Vec<P2PClassDefinition>>
    where
        P: Clone + BlockClient + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        util::task::spawn(async move {
            let Self {
                p2p,
                mut declarations,
                start: mut block_number,
            } = self;

            while let Some(declared_classes) = declarations.next().await {
                let (peer, class_definitions) = loop {
                    let class_definitions = p2p
                        .clone()
                        .class_definitions_for_block(
                            block_number,
                            declared_classes.len().try_into().unwrap(),
                        )
                        .await;
                    match class_definitions {
                        Ok(Some(class_definitions)) => break class_definitions,
                        Ok(None) => {}
                        Err(err) => {
                            let err = match err {
                                ClassDefinitionsError::IncorrectClassDefinitionCount(peer) => {
                                    SyncError::IncorrectClassDefinitionCount(peer)
                                }
                                ClassDefinitionsError::CairoDefinitionError(peer) => {
                                    SyncError::CairoDefinitionError(peer)
                                }
                                ClassDefinitionsError::SierraDefinitionError(peer) => {
                                    SyncError::SierraDefinitionError(peer)
                                }
                                ClassDefinitionsError::ResponseStreamFailure(peer, _) => {
                                    SyncError::InvalidDto(peer)
                                }
                            };
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    }
                };

                if tx
                    .send(Ok(PeerData::new(peer, class_definitions)))
                    .await
                    .is_err()
                {
                    return;
                }

                block_number += 1;
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct BlockStream {
    header: SyncReceiver<SignedBlockHeader>,
    events: SyncReceiver<HashMap<TransactionHash, Vec<Event>>>,
    state_diff: SyncReceiver<StateUpdateData>,
    transactions: SyncReceiver<Vec<(Transaction, Receipt)>>,
    classes: SyncReceiver<Vec<CompiledClass>>,
}

impl BlockStream {
    fn spawn(mut self) -> SyncReceiver<BlockData> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        util::task::spawn(async move {
            loop {
                let Some(result) = self.next().await else {
                    return;
                };

                let is_err = result.is_err();

                if tx.send(result).await.is_err() || is_err {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }

    async fn next(&mut self) -> Option<SyncResult<BlockData>> {
        let header = self.header.recv().await?;
        let header = match header {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let events = self.events.recv().await?;
        let events = match events {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let state_diff = self.state_diff.recv().await?;
        let state_diff = match state_diff {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let transactions = self.transactions.recv().await?;
        let transactions = match transactions {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let classes = self.classes.recv().await?;
        let classes = match classes {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let data = BlockData {
            header: header.data,
            events: events.data,
            state_diff: state_diff.data,
            transactions: transactions.data,
            classes: classes.data,
        };

        Some(Ok(PeerData::new(header.peer, data)))
    }
}

pub struct BlockData {
    pub header: SignedBlockHeader,
    pub events: HashMap<TransactionHash, Vec<Event>>,
    pub state_diff: StateUpdateData,
    pub transactions: Vec<(Transaction, Receipt)>,
    pub classes: Vec<CompiledClass>,
}

pub fn store_synced_block(
    storage: Storage,
    block_data: BlockData,
    verify_tree_hashes: bool,
) -> anyhow::Result<(BlockNumber, BlockHash)> {
    let BlockData {
        header,
        mut events,
        state_diff,
        transactions,
        classes,
    } = block_data;
    let SignedBlockHeader { header, signature } = header;
    let block_number = header.number;

    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;
    let db_tx = db_conn
        .transaction()
        .context("Creating database transaction")?;

    let header = BlockHeader {
        hash: header.hash,
        parent_hash: header.parent_hash,
        number: header.number,
        timestamp: header.timestamp,
        eth_l1_gas_price: header.eth_l1_gas_price,
        strk_l1_gas_price: header.strk_l1_gas_price,
        eth_l1_data_gas_price: header.eth_l1_data_gas_price,
        strk_l1_data_gas_price: header.strk_l1_data_gas_price,
        eth_l2_gas_price: header.eth_l2_gas_price,
        strk_l2_gas_price: header.strk_l2_gas_price,
        sequencer_address: header.sequencer_address,
        starknet_version: header.starknet_version,
        event_commitment: header.event_commitment,
        state_commitment: header.state_commitment,
        transaction_commitment: header.transaction_commitment,
        transaction_count: header.transaction_count,
        event_count: header.event_count,
        l1_da_mode: header.l1_da_mode,
        receipt_commitment: header.receipt_commitment,
        state_diff_commitment: header.state_diff_commitment,
        state_diff_length: header.state_diff_length,
    };

    db_tx
        .insert_block_header(&header)
        .context("Inserting block header")?;

    db_tx
        .insert_signature(block_number, &signature)
        .context("Inserting signature")?;

    let mut ordered_events = Vec::new();
    transactions.iter().for_each(|(t, _)| {
        // Some transactions can emit no events, in that case we insert an empty vector.
        ordered_events.push(events.remove(&t.hash).unwrap_or_default());
    });

    db_tx
        .insert_transaction_data(block_number, &transactions, Some(&ordered_events))
        .context("Inserting transaction data")?;
    db_tx
        .insert_state_update_data(block_number, &state_diff)
        .context("Inserting state update data")?;

    let (storage_commitment, class_commitment) = update_starknet_state(
        &db_tx,
        (&state_diff).into(),
        verify_tree_hashes,
        block_number,
        storage.clone(),
    )
    .with_context(|| format!("Updating Starknet state, block_number {block_number}"))?;

    // Ensure that roots match.
    let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
    let expected_state_commitment = header.state_commitment;
    if state_commitment != expected_state_commitment {
        tracing::debug!(
                    actual_storage_commitment=%storage_commitment,
                    actual_class_commitment=%class_commitment,
                    actual_state_commitment=%state_commitment,
                    "State root mismatch");
        anyhow::bail!("State commitment mismatch");
    }

    classes.into_iter().try_for_each(|class| {
        let CompiledClass {
            block_number,
            hash,
            definition,
        } = class;

        match definition {
            class_definitions::CompiledClassDefinition::Cairo(cairo) => db_tx
                .update_cairo_class(hash, &cairo)
                .context("Inserting cairo class definition"),
            crate::sync::class_definitions::CompiledClassDefinition::Sierra {
                sierra_definition,
                casm_definition,
            } => {
                let sierra_hash = SierraHash(hash.0);
                let casm_hash = db_tx
                    .casm_hash(hash)
                    .context("Getting casm hash")?
                    .context("Casm not found")?;
                db_tx
                    .update_sierra_class(
                        &sierra_hash,
                        &sierra_definition,
                        &casm_hash,
                        &casm_definition,
                    )
                    .context("Inserting sierra class definition")
            }
        }
    })?;

    let result = db_tx
        .commit()
        .context("Committing transaction")
        .map(|_| (block_number, header.hash));

    tracing::debug!(number=%block_number, "Block stored");

    result
}
