use std::collections::{HashMap, HashSet};
use std::pin;

use anyhow::{anyhow, Context};
use futures::stream::BoxStream;
use futures::{pin_mut, Stream, StreamExt, TryStreamExt};
use p2p::client::peer_agnostic::traits::{BlockClient, HeaderStream};
use p2p::client::peer_agnostic::Client as P2PClient;
use p2p::client::types::{
    ClassDefinition as P2PClassDefinition,
    ClassDefinitionsError,
    IncorrectStateDiffCount,
    TransactionData,
};
use p2p::PeerData;
use pathfinder_common::class_definition::ClassDefinition;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::{DeclaredClasses, StateUpdateData};
use pathfinder_common::transaction::{Transaction, TransactionVariant};
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    Chain,
    ChainId,
    ClassCommitment,
    ClassHash,
    EventCommitment,
    PublicKey,
    ReceiptCommitment,
    SierraHash,
    SignedBlockHeader,
    StarknetVersion,
    StateDiffCommitment,
    StateUpdate,
    StorageCommitment,
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

pub struct Sync<L, P> {
    pub latest: L,
    pub p2p: P,
    pub storage: Storage,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub public_key: PublicKey,
}

impl<L, P> Sync<L, P> {
    pub async fn run<SequencerClient: GatewayApi + Clone + Send + 'static>(
        self,
        next: BlockNumber,
        parent_hash: BlockHash,
        fgw: SequencerClient,
    ) -> Result<(), PeerData<SyncError2>>
    where
        L: Stream<Item = (BlockNumber, BlockHash)> + Clone + Send + 'static,
        P: BlockClient + Clone + HeaderStream + Send + 'static,
    {
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
        .pipe(transactions::CalculateHashes(self.chain_id), 10)
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

struct HeaderSource<L, P> {
    p2p: P,
    latest_onchain: L,
    start: BlockNumber,
}

impl<L, P> HeaderSource<L, P> {
    fn spawn(self) -> SyncReceiver<SignedBlockHeader>
    where
        L: Stream<Item = (BlockNumber, BlockHash)> + Send + 'static,
        P: Clone + HeaderStream + Send + 'static,
    {
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

struct TransactionSource<P> {
    p2p: P,
    headers: BoxStream<'static, BlockHeader>,
}

impl<P> TransactionSource<P> {
    fn spawn(self) -> SyncReceiver<(TransactionData, StarknetVersion, TransactionCommitment)>
    where
        P: Clone + BlockClient + Send + 'static,
    {
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

                pin_mut!(transactions);

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
                            transactions_vec,
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

struct EventSource<P> {
    p2p: P,
    headers: BoxStream<'static, BlockHeader>,
    transactions: BoxStream<'static, Vec<TransactionHash>>,
}

type EventsWithCommitment = (
    EventCommitment,
    Vec<TransactionHash>,
    HashMap<TransactionHash, Vec<Event>>,
    StarknetVersion,
);

impl<P> EventSource<P> {
    fn spawn(self) -> SyncReceiver<EventsWithCommitment>
    where
        P: Clone + BlockClient + Send + 'static,
    {
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

                pin_mut!(events);

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

struct StateDiffSource<P> {
    p2p: P,
    headers: BoxStream<'static, SignedBlockHeader>,
}

impl<P> StateDiffSource<P> {
    fn spawn(self) -> SyncReceiver<(StateUpdateData, StarknetVersion, StateDiffCommitment)>
    where
        P: Clone + BlockClient + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
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
                            state_diff,
                            header.header.starknet_version,
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
    pub header: SyncReceiver<SignedBlockHeader>,
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
    pub header: SignedBlockHeader,
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
            header: SignedBlockHeader { header, signature },
            mut events,
            state_diff,
            transactions,
            classes,
        } = input;

        let block_number = header.number;

        let db = self.connection.transaction().with_context(|| {
            format!("Creating database connection, block_number: {block_number}")
        })?;

        let header = BlockHeader {
            hash: header.hash,
            parent_hash: header.parent_hash,
            number: header.number,
            timestamp: header.timestamp,
            eth_l1_gas_price: header.eth_l1_gas_price,
            strk_l1_gas_price: header.strk_l1_gas_price,
            eth_l1_data_gas_price: header.eth_l1_data_gas_price,
            strk_l1_data_gas_price: header.strk_l1_data_gas_price,
            sequencer_address: header.sequencer_address,
            starknet_version: header.starknet_version,
            class_commitment: ClassCommitment::ZERO, // TODO update class tries
            event_commitment: header.event_commitment,
            state_commitment: header.state_commitment,
            storage_commitment: StorageCommitment::ZERO, // TODO update storage tries
            transaction_commitment: header.transaction_commitment,
            transaction_count: header.transaction_count,
            event_count: header.event_count,
            l1_da_mode: header.l1_da_mode,
            receipt_commitment: header.receipt_commitment,
            state_diff_commitment: header.state_diff_commitment,
            state_diff_length: header.state_diff_length,
        };

        db.insert_block_header(&header)
            .context("Inserting block header")?;

        db.insert_signature(block_number, &signature)
            .context("Inserting signature")?;

        let mut ordered_events = Vec::new();
        transactions.iter().for_each(|(t, _)| {
            // Some transactions can emit no events, in that case we insert an empty vector.
            ordered_events.push(events.remove(&t.hash).unwrap_or_default());
        });

        db.insert_transaction_data(block_number, &transactions, Some(&ordered_events))
            .context("Inserting transaction data")?;

        db.insert_state_update_data(block_number, &state_diff)
            .context("Inserting state update data")?;

        classes.into_iter().try_for_each(
            |CompiledClass {
                 block_number,
                 hash,
                 definition,
             }| {
                match definition {
                    class_definitions::CompiledClassDefinition::Cairo(cairo) => db
                        .update_cairo_class(hash, &cairo)
                        .context("Inserting cairo class definition"),
                    class_definitions::CompiledClassDefinition::Sierra {
                        sierra_definition,
                        casm_definition,
                    } => {
                        let sierra_hash = SierraHash(hash.0);
                        let casm_hash = db
                            .casm_hash(hash)
                            .context("Getting casm hash")?
                            .context("Casm not found")?;
                        db.update_sierra_class(
                            &sierra_hash,
                            &sierra_definition,
                            &casm_hash,
                            &casm_definition,
                        )
                        .context("Inserting sierra class definition")
                    }
                }
            },
        )?;

        let result = db
            .commit()
            .context("Committing transaction")
            .map_err(Into::into);

        tracing::info!(number=%block_number, "Block stored");

        result
    }
}

#[cfg(test)]
mod tests {
    use futures::{stream, Stream, StreamExt};
    use p2p::client::types::{
        ClassDefinition,
        ClassDefinitionsError,
        IncorrectStateDiffCount,
        Receipt as P2PReceipt,
    };
    use p2p::libp2p::PeerId;
    use p2p::PeerData;
    use p2p_proto::common::Hash;
    use pathfinder_common::{BlockHeader, ReceiptCommitment, SignedBlockHeader};
    use pathfinder_storage::fake::init::Config;
    use pathfinder_storage::fake::{self, Block};
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_types::error::SequencerError;

    use super::*;
    use crate::state::block_hash::{
        calculate_event_commitment,
        calculate_receipt_commitment,
        calculate_transaction_commitment,
        compute_final_hash,
        BlockHeaderData,
    };

    #[tokio::test]
    async fn happy_path() {
        const N: usize = 10;
        let blocks = fake::init::with_n_blocks_and_config(
            N,
            Config {
                calculate_block_hash: Box::new(|header: &BlockHeader| {
                    compute_final_hash(&BlockHeaderData::from_header(header))
                }),
                calculate_transaction_commitment: Box::new(calculate_transaction_commitment),
                calculate_receipt_commitment: Box::new(calculate_receipt_commitment),
                calculate_event_commitment: Box::new(calculate_event_commitment),
            },
        );

        let BlockHeader { hash, number, .. } = blocks.last().unwrap().header.header;
        let latest = (number, hash);

        let p2p: FakeP2PClient = FakeP2PClient {
            blocks: blocks.clone(),
        };

        let storage = StorageBuilder::in_memory().unwrap();

        let sync = Sync {
            latest: futures::stream::iter(vec![latest]),
            p2p,
            storage: storage.clone(),
            chain: Chain::SepoliaTestnet,
            chain_id: ChainId::SEPOLIA_TESTNET,
            public_key: PublicKey::default(),
        };

        sync.run(BlockNumber::GENESIS, BlockHash::default(), FakeFgw)
            .await
            .unwrap();

        let mut db = storage.connection().unwrap();
        let db = db.transaction().unwrap();
        for mut expected in blocks {
            // TODO p2p sync does not update class and storage tries yet
            expected.header.header.class_commitment = ClassCommitment::ZERO;
            expected.header.header.storage_commitment = StorageCommitment::ZERO;

            let block_number = expected.header.header.number;
            let block_id = block_number.into();
            let header = db.block_header(block_id).unwrap().unwrap();
            let signature = db.signature(block_id).unwrap().unwrap();
            let transaction_data = db.transaction_data_for_block(block_id).unwrap().unwrap();
            let state_update_data: StateUpdateData =
                db.state_update(block_id).unwrap().unwrap().into();
            let declared = db.declared_classes_at(block_id).unwrap().unwrap();

            let mut cairo_defs = HashMap::new();
            let mut sierra_defs = HashMap::new();

            for class_hash in declared {
                let class = db.class_definition(class_hash).unwrap().unwrap();
                match db.casm_hash(class_hash).unwrap() {
                    Some(casm_hash) => {
                        let casm = db.casm_definition(class_hash).unwrap().unwrap();
                        sierra_defs.insert(SierraHash(class_hash.0), (class, casm));
                    }
                    None => {
                        cairo_defs.insert(class_hash, class);
                    }
                }
            }

            pretty_assertions_sorted::assert_eq!(header, expected.header.header);
            pretty_assertions_sorted::assert_eq!(signature, expected.header.signature);
            pretty_assertions_sorted::assert_eq!(
                header.state_diff_commitment,
                expected.header.header.state_diff_commitment
            );
            pretty_assertions_sorted::assert_eq!(
                header.state_diff_length,
                expected.header.header.state_diff_length
            );
            pretty_assertions_sorted::assert_eq!(transaction_data, expected.transaction_data);
            pretty_assertions_sorted::assert_eq!(state_update_data, expected.state_update.into());
            pretty_assertions_sorted::assert_eq!(
                cairo_defs,
                expected.cairo_defs.into_iter().collect::<HashMap<_, _>>()
            );
            pretty_assertions_sorted::assert_eq!(
                sierra_defs,
                expected
                    .sierra_defs
                    .into_iter()
                    // All sierra fixtures are not compile-able
                    .map(|(h, s, _)| (h, (s, b"I'm from the fgw!".to_vec())))
                    .collect::<HashMap<_, _>>()
            );
        }
    }

    #[derive(Clone)]
    struct FakeP2PClient {
        pub blocks: Vec<Block>,
    }

    impl HeaderStream for FakeP2PClient {
        fn header_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            reverse: bool,
        ) -> impl Stream<Item = PeerData<SignedBlockHeader>> + Send {
            assert!(!reverse);
            assert_eq!(start, self.blocks.first().unwrap().header.header.number);
            assert_eq!(stop, self.blocks.last().unwrap().header.header.number);

            stream::iter(
                self.blocks
                    .into_iter()
                    .map(|block| PeerData::for_tests(block.header)),
            )
        }
    }

    impl BlockClient for FakeP2PClient {
        async fn transactions_for_block(
            self,
            block: BlockNumber,
        ) -> Option<(
            PeerId,
            impl Stream<Item = anyhow::Result<(TransactionVariant, P2PReceipt)>> + Send,
        )> {
            let tr = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .transaction_data
                .iter()
                .map(|(t, r, e)| Ok((t.variant.clone(), P2PReceipt::from(r.clone()))))
                .collect::<Vec<anyhow::Result<(TransactionVariant, P2PReceipt)>>>();

            Some((PeerId::random(), stream::iter(tr)))
        }

        async fn state_diff_for_block(
            self,
            block: BlockNumber,
            state_diff_length: u64,
        ) -> Result<Option<(PeerId, StateUpdateData)>, IncorrectStateDiffCount> {
            let sd: StateUpdateData = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .state_update
                .clone()
                .into();

            assert_eq!(sd.state_diff_length() as u64, state_diff_length);

            Ok(Some((PeerId::random(), sd)))
        }

        async fn class_definitions_for_block(
            self,
            block: BlockNumber,
            declared_classes_count: u64,
        ) -> Result<Option<(PeerId, Vec<ClassDefinition>)>, ClassDefinitionsError> {
            let b = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap();
            let defs = b
                .cairo_defs
                .iter()
                .map(|(_, x)| ClassDefinition::Cairo {
                    block_number: block,
                    definition: x.clone(),
                })
                .chain(
                    b.sierra_defs
                        .iter()
                        .map(|(_, x, _)| ClassDefinition::Sierra {
                            block_number: block,
                            sierra_definition: x.clone(),
                        }),
                )
                .collect::<Vec<ClassDefinition>>();

            Ok(Some((PeerId::random(), defs)))
        }

        async fn events_for_block(
            self,
            block: BlockNumber,
        ) -> Option<(PeerId, impl Stream<Item = (TransactionHash, Event)> + Send)> {
            let e = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .transaction_data
                .iter()
                .flat_map(|(t, _, e)| e.iter().map(move |e| (t.hash, e.clone())))
                .collect::<Vec<_>>();

            Some((PeerId::random(), stream::iter(e)))
        }
    }

    #[derive(Clone)]
    struct FakeFgw;

    #[async_trait::async_trait]
    impl GatewayApi for FakeFgw {
        async fn pending_casm_by_hash(&self, _: ClassHash) -> Result<bytes::Bytes, SequencerError> {
            Ok(bytes::Bytes::from_static(b"I'm from the fgw!"))
        }
    }
}
