use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt, TryStreamExt};
use p2p::client::peer_agnostic::{
    self,
    BlockHeader as P2PBlockHeader,
    ClassDefinition as P2PClassDefinition,
    ClassDefinitionsError,
    Client as P2PClient,
    IncorrectStateDiffCount,
    SignedBlockHeader as P2PSignedBlockHeader,
    UnverifiedStateUpdateData,
    UnverifiedTransactionData,
};
use p2p::PeerData;
use pathfinder_common::class_definition::ClassDefinition;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::{DeclaredClasses, StateUpdateData};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    Chain,
    ChainId,
    ClassHash,
    EventCommitment,
    PublicKey,
    StarknetVersion,
    StateDiffCommitment,
    StateUpdate,
    TransactionCommitment,
    TransactionHash,
};
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use tokio_stream::wrappers::ReceiverStream;

use super::class_definitions::CompiledClass;
use super::{state_updates, transactions};
use crate::sync::class_definitions::{self, ClassWithLayout};
use crate::sync::error::SyncError2;
use crate::sync::stream::{ProcessStage, SyncReceiver, SyncResult};
use crate::sync::{events, headers};

pub struct Sync<L> {
    latest: L,
    p2p: P2PClient,
    storage: Storage,
    chain: Chain,
    chain_id: ChainId,
    public_key: PublicKey,
}

impl<L> Sync<L>
where
    L: Stream<Item = (BlockNumber, BlockHash)> + Clone + Send + 'static,
{
    pub async fn run<SequencerClient: GatewayApi + Clone + Send + 'static>(
        self,
        next: BlockNumber,
        parent_hash: BlockHash,
        chain_id: ChainId,
        fgw: SequencerClient,
    ) -> Result<(), PeerData<SyncError2>> {
        let storage_connection = self
            .storage
            .connection()
            .context("Creating database connection")
            // FIXME: PeerData should allow for None peers.
            .map_err(|e| PeerData {
                peer: p2p::libp2p::PeerId::random(),
                data: SyncError2::from(e),
            })?;

        let mut headers = HeaderSource {
            p2p: self.p2p.clone(),
            latest_onchain: self.latest.clone(),
            start: next,
        }
        .spawn()
        .pipe(headers::ForwardContinuity::new(next, parent_hash), 100)
        .pipe(
            headers::VerifyHashAndSignature::new(self.chain, self.chain_id, self.public_key),
            100,
        );

        let HeaderFanout {
            headers,
            events,
            state_diff,
            transactions,
        } = HeaderFanout::from_source(headers, 10);

        let transactions = TransactionSource {
            p2p: self.p2p.clone(),
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
            p2p: self.p2p.clone(),
            headers: events,
            transactions: transactions_for_events,
        }
        .spawn()
        .pipe(events::VerifyCommitment, 10);
        let state_diff = StateDiffSource {
            p2p: self.p2p.clone(),
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
            p2p: self.p2p.clone(),
            declarations: declarations_1,
            start: next,
        }
        .spawn()
        .pipe_each(class_definitions::VerifyLayout, 10)
        .pipe_each(class_definitions::ComputeHash, 10)
        .pipe_each(
            class_definitions::CompileSierraToCasm::new(fgw, tokio::runtime::Handle::current()),
            10,
        )
        .pipe(
            class_definitions::VerifyClassHashes {
                declarations: declarations_2,
                tokio_handle: tokio::runtime::Handle::current(),
            },
            10,
        );

        BlockStream {
            header: headers,
            events,
            state_diff,
            transactions,
            classes,
        }
        .spawn()
        .pipe(StoreBlock::new(storage_connection), 10)
        .into_stream()
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await
    }
}

struct HeaderSource<L> {
    p2p: P2PClient,
    latest_onchain: L,
    start: BlockNumber,
}

impl<L> HeaderSource<L>
where
    L: Stream<Item = (BlockNumber, BlockHash)> + Send + 'static,
{
    fn spawn(self) -> SyncReceiver<P2PSignedBlockHeader> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let Self {
            p2p,
            latest_onchain,
            mut start,
        } = self;

        tokio::spawn(async move {
            let mut latest_onchain = Box::pin(latest_onchain);
            while let Some(latest_onchain) = latest_onchain.next().await {
                // Ignore reorgs for now. Unsure how to handle this properly.

                // TODO: Probably need a loop here if we don't get enough headers?
                let mut headers =
                    Box::pin(p2p.clone().header_stream(start, latest_onchain.0, false));

                while let Some(header) = headers.next().await {
                    start = header.data.header.number + 1;

                    if tx.send(Ok(header)).await.is_err() {
                        return;
                    }
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct StateDiffFanout {
    state_diff: SyncReceiver<StateUpdateData>,
    declarations_1: BoxStream<'static, DeclaredClasses>,
    declarations_2: BoxStream<'static, DeclaredClasses>,
}

impl StateDiffFanout {
    fn from_source(mut source: SyncReceiver<StateUpdateData>, buffer: usize) -> Self {
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(buffer);
        let (d1_tx, d1_rx) = tokio::sync::mpsc::channel(buffer);
        let (d2_tx, d2_rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            while let Some(state_update) = source.recv().await {
                let is_err = state_update.is_err();

                if s_tx.send(state_update.clone()).await.is_err() || is_err {
                    return;
                }

                let class_declarations = state_update
                    .expect("Error case already handled")
                    .data
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

struct TransactionsFanout {
    transactions: SyncReceiver<Vec<(Transaction, Receipt)>>,
    events: BoxStream<'static, Vec<TransactionHash>>,
}

impl TransactionsFanout {
    fn from_source(mut source: SyncReceiver<Vec<(Transaction, Receipt)>>, buffer: usize) -> Self {
        let (t_tx, t_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
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

struct HeaderFanout {
    headers: SyncReceiver<P2PSignedBlockHeader>,
    events: BoxStream<'static, P2PBlockHeader>,
    state_diff: BoxStream<'static, P2PSignedBlockHeader>,
    transactions: BoxStream<'static, P2PBlockHeader>,
}

impl HeaderFanout {
    fn from_source(mut source: SyncReceiver<P2PSignedBlockHeader>, buffer: usize) -> Self {
        let (h_tx, h_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);
        let (s_tx, s_rx) = tokio::sync::mpsc::channel(buffer);
        let (t_tx, t_rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
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

struct TransactionSource {
    p2p: P2PClient,
    headers: BoxStream<'static, P2PBlockHeader>,
}

impl TransactionSource {
    fn spawn(self) -> SyncReceiver<(UnverifiedTransactionData, StarknetVersion)> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, mut transactions) = loop {
                    if let Some(stream) = p2p.clone().transactions_for_block(header.number).await {
                        break stream;
                    }
                };

                let transaction_count = header.transaction_count;
                let mut transactions_vec = Vec::new();

                // Receive the exact amount of expected events for this block.
                for _ in 0..transaction_count {
                    let (transaction, receipt) = match transactions.next().await {
                        Some(Ok((transaction, receipt))) => (transaction, receipt),
                        Some(Err(_)) => {
                            let err = PeerData::new(peer, SyncError2::InvalidDto);
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                        None => {
                            let err = PeerData::new(peer, SyncError2::TooFewTransactions);
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    };

                    transactions_vec.push((transaction, receipt));
                }

                // Ensure that the stream is exhausted.
                if transactions.next().await.is_some() {
                    let err = PeerData::new(peer, SyncError2::TooManyTransactions);
                    let _ = tx.send(Err(err)).await;
                    return;
                }

                let _ = tx
                    .send(Ok(PeerData::new(
                        peer,
                        (
                            UnverifiedTransactionData {
                                expected_commitment: header.transaction_commitment,
                                transactions: transactions_vec,
                            },
                            header.starknet_version,
                        ),
                    )))
                    .await;
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct EventSource {
    p2p: P2PClient,
    headers: BoxStream<'static, P2PBlockHeader>,
    transactions: BoxStream<'static, Vec<TransactionHash>>,
}

type EventsWithCommitment = (
    EventCommitment,
    Vec<TransactionHash>,
    HashMap<TransactionHash, Vec<Event>>,
    StarknetVersion,
);

impl EventSource {
    fn spawn(self) -> SyncReceiver<EventsWithCommitment> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Self {
                p2p,
                mut transactions,
                mut headers,
            } = self;

            while let Some(header) = headers.next().await {
                let (peer, mut events) = loop {
                    if let Some(stream) = p2p.clone().events_for_block(header.number).await {
                        break stream;
                    }
                };
                let Some(block_transactions) = transactions.next().await else {
                    let err =
                        PeerData::new(peer, SyncError2::Other(anyhow!("No transactions").into()));
                    let _ = tx.send(Err(err)).await;
                    return;
                };

                let mut block_events: HashMap<_, Vec<Event>> = HashMap::new();
                let event_count = header.event_count;

                // Receive the exact amount of expected events for this block.
                for _ in 0..event_count {
                    let Some((tx_hash, event)) = events.next().await else {
                        let err = PeerData::new(peer, SyncError2::TooFewEvents);
                        let _ = tx.send(Err(err)).await;
                        return;
                    };

                    block_events.entry(tx_hash).or_default().push(event);
                }

                // Ensure that the stream is exhausted.
                if events.next().await.is_some() {
                    let err = PeerData::new(peer, SyncError2::TooManyEvents);
                    let _ = tx.send(Err(err)).await;
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

struct StateDiffSource {
    p2p: P2PClient,
    headers: BoxStream<'static, P2PSignedBlockHeader>,
}

impl StateDiffSource {
    fn spawn(self) -> SyncReceiver<(UnverifiedStateUpdateData, StarknetVersion)> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, state_diff) = loop {
                    let state_diff = p2p
                        .clone()
                        .state_diff_for_block(header.header.number, header.state_diff_length)
                        .await;
                    match state_diff {
                        Ok(Some(state_diff)) => break state_diff,
                        Ok(None) => {}
                        Err(IncorrectStateDiffCount(peer)) => {
                            let err = PeerData::new(peer, SyncError2::IncorrectStateDiffCount);
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    }
                };

                if tx
                    .send(Ok(PeerData::new(
                        peer,
                        (
                            UnverifiedStateUpdateData {
                                expected_commitment: header.state_diff_commitment,
                                state_diff,
                            },
                            header.header.starknet_version,
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

struct ClassSource {
    p2p: P2PClient,
    declarations: BoxStream<'static, DeclaredClasses>,
    start: BlockNumber,
}

impl ClassSource {
    fn spawn(self) -> SyncReceiver<Vec<P2PClassDefinition>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
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
                                    PeerData::new(peer, SyncError2::IncorrectClassDefinitionCount)
                                }
                                ClassDefinitionsError::CairoDefinitionError(peer) => {
                                    PeerData::new(peer, SyncError2::CairoDefinitionError)
                                }
                                ClassDefinitionsError::SierraDefinitionError(peer) => {
                                    PeerData::new(peer, SyncError2::SierraDefinitionError)
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
    pub header: SyncReceiver<P2PSignedBlockHeader>,
    pub events: SyncReceiver<HashMap<TransactionHash, Vec<Event>>>,
    pub state_diff: SyncReceiver<StateUpdateData>,
    pub transactions: SyncReceiver<Vec<(Transaction, Receipt)>>,
    pub classes: SyncReceiver<Vec<CompiledClass>>,
}

impl BlockStream {
    fn spawn(mut self) -> SyncReceiver<BlockData> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
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

struct BlockData {
    pub header: P2PSignedBlockHeader,
    pub events: HashMap<TransactionHash, Vec<Event>>,
    pub state_diff: StateUpdateData,
    pub transactions: Vec<(Transaction, Receipt)>,
    pub classes: Vec<CompiledClass>,
}

struct StoreBlock {
    connection: pathfinder_storage::Connection,
}

impl StoreBlock {
    pub fn new(connection: pathfinder_storage::Connection) -> Self {
        Self { connection }
    }
}

impl ProcessStage for StoreBlock {
    const NAME: &'static str = "Blocks::Persist";
    type Input = BlockData;
    type Output = ();

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let BlockData {
            header,
            events,
            state_diff,
            transactions,
            classes,
        } = input;

        let db = self
            .connection
            .transaction()
            .context("Creating database connection")?;

        // TODO: write all the data to storage

        db.commit()
            .context("Committing transaction")
            .map_err(Into::into)
    }
}
