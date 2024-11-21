#![allow(dead_code, unused)]

use core::panic;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use error::SyncError;
use futures::{pin_mut, Stream, StreamExt};
use p2p::client::peer_agnostic::traits::{
    BlockClient,
    ClassStream,
    EventStream,
    HeaderStream,
    StateDiffStream,
    StreamItem,
    TransactionStream,
};
use p2p::PeerData;
use pathfinder_common::error::AnyhowExt;
use pathfinder_common::{
    block_hash,
    BlockHash,
    BlockNumber,
    Chain,
    ChainId,
    PublicKey,
    StarknetVersion,
};
use pathfinder_ethereum::EthereumStateUpdate;
use pathfinder_storage::Transaction;
use primitive_types::H160;
use starknet_gateway_client::{Client as GatewayClient, GatewayApi};
use stream::ProcessStage;
use tokio::sync::watch::{self, Receiver};
use tokio_stream::wrappers::WatchStream;

use crate::state::RESET_DELAY_ON_FAILURE;

mod checkpoint;
mod class_definitions;
mod error;
mod events;
mod headers;
mod state_updates;
mod storage_adapters;
mod stream;
mod track;
mod transactions;

const CHECKPOINT_MARGIN: u64 = 10;

pub struct Sync<P> {
    pub storage: pathfinder_storage::Storage,
    pub p2p: P,
    pub eth_client: pathfinder_ethereum::EthereumClient,
    pub eth_address: H160,
    pub fgw_client: GatewayClient,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub public_key: PublicKey,
    pub l1_checkpoint_override: Option<EthereumStateUpdate>,
    pub verify_tree_hashes: bool,
}

impl<P> Sync<P>
where
    P: BlockClient
        + ClassStream
        + EventStream
        + HeaderStream
        + StateDiffStream
        + TransactionStream
        + Clone
        + Send
        + 'static,
{
    pub async fn run(self) -> anyhow::Result<()> {
        let (next, parent_hash) = self.checkpoint_sync().await?;

        // TODO: depending on how this is implemented, we might want to loop around it.
        self.track_sync(next, parent_hash).await
    }

    async fn handle_recoverable_error(&self, err: &error::SyncError) {
        // TODO
        tracing::debug!(%err, "Log and punish as appropriate");
    }

    /// Retry forever until a valid L1 checkpoint is retrieved
    ///
    /// ### Important
    ///
    /// We assume that the L1 endpoint is configured correctly and any L1 API
    /// errors are transient. We cannot proceed without a checkpoint, so we
    /// retry until we get one.
    async fn get_checkpoint(&self) -> pathfinder_ethereum::EthereumStateUpdate {
        use pathfinder_ethereum::EthereumApi;
        if let Some(forced) = &self.l1_checkpoint_override {
            return *forced;
        }

        loop {
            match self.eth_client.get_starknet_state(&self.eth_address).await {
                Ok(latest) => return latest,
                Err(error) => {
                    tracing::warn!(%error, "Failed to get L1 checkpoint, retrying");
                    tokio::time::sleep(RESET_DELAY_ON_FAILURE);
                }
            }
        }
    }

    /// Run checkpoint sync until it completes successfully, and we are within
    /// some margin of the latest L1 block. Returns the next block number to
    /// sync and its parent hash.
    ///
    /// ### Important
    ///
    /// Sync is restarted on recoverable errors and only fatal errors (e.g.:
    /// database failure, runtime failure, etc.) cause this function to exit
    /// with an error.
    async fn checkpoint_sync(&self) -> anyhow::Result<(BlockNumber, BlockHash)> {
        let mut checkpoint = self.get_checkpoint().await;
        let from = (checkpoint.block_number, checkpoint.block_hash);

        tracing::info!(?from, "Checkpoint sync started");

        loop {
            let result = checkpoint::Sync {
                storage: self.storage.clone(),
                p2p: self.p2p.clone(),
                eth_client: self.eth_client.clone(),
                eth_address: self.eth_address,
                fgw_client: self.fgw_client.clone(),
                chain: self.chain,
                chain_id: self.chain_id,
                public_key: self.public_key,
                verify_tree_hashes: self.verify_tree_hashes,
                block_hash_db: Some(pathfinder_block_hashes::BlockHashDb::new(self.chain)),
            }
            .run(checkpoint)
            .await;

            // Handle the error
            let continue_from = match result {
                Ok(continue_from) => {
                    tracing::debug!(?continue_from, "Checkpoint sync complete");
                    continue_from
                }
                Err(SyncError::Fatal(mut error)) => {
                    tracing::error!(%error, "Stopping checkpoint sync");
                    return Err(error.take_or_deep_clone());
                }
                Err(error) => {
                    tracing::debug!(%error, "Restarting checkpoint sync");
                    self.handle_recoverable_error(&error).await;
                    continue;
                }
            };

            // Initial sync might take so long that the latest checkpoint is actually far
            // ahead again. Repeat until we are within some margin of L1.
            let latest_checkpoint = self.get_checkpoint().await;
            if checkpoint.block_number + CHECKPOINT_MARGIN < latest_checkpoint.block_number {
                checkpoint = latest_checkpoint;
                tracing::debug!(
                    local_checkpoint=%checkpoint.block_number, latest_checkpoint=%latest_checkpoint.block_number,
                    "Restarting checkpoint sync: L1 checkpoint has advanced"
                );
                continue;
            }

            break Ok(continue_from);
        }
    }

    /// Run the track sync forever, requires the number and parent hash of the
    /// first block to sync.
    ///
    /// ### Important
    ///
    /// Sync is restarted on recoverable errors and only fatal errors (e.g.:
    /// database failure, runtime failure, etc.) cause this function to exit
    /// with an error.
    async fn track_sync(
        &self,
        mut next: BlockNumber,
        mut parent_hash: BlockHash,
    ) -> anyhow::Result<()> {
        tracing::info!(next_block=%next, "Track sync started");

        loop {
            let mut result = track::Sync {
                latest: LatestStream::spawn(self.fgw_client.clone(), Duration::from_secs(2)),
                p2p: self.p2p.clone(),
                storage: self.storage.clone(),
                chain: self.chain,
                chain_id: self.chain_id,
                public_key: self.public_key,
                block_hash_db: Some(pathfinder_block_hashes::BlockHashDb::new(self.chain)),
                verify_tree_hashes: self.verify_tree_hashes,
            }
            .run(&mut next, &mut parent_hash, self.fgw_client.clone())
            .await;

            match result {
                Ok(_) => tracing::debug!("Restarting track sync: unexpected end of Block stream"),
                Err(SyncError::Fatal(mut error)) => {
                    tracing::error!(%error, "Stopping track sync");
                    use pathfinder_common::error::AnyhowExt;
                    return Err(error.take_or_deep_clone());
                }
                Err(error) => {
                    tracing::debug!(%error, "Restarting track sync");
                    self.handle_recoverable_error(&error).await;
                }
            }
        }
    }
}

struct LatestStream {
    rx: Receiver<(BlockNumber, BlockHash)>,
    stream: WatchStream<(BlockNumber, BlockHash)>,
}

impl Clone for LatestStream {
    fn clone(&self) -> Self {
        Self {
            // Keep the rx for the next clone
            rx: self.rx.clone(),
            // Create a new stream from the cloned rx, don't yield the initial value
            stream: WatchStream::from_changes(self.rx.clone()),
        }
    }
}

impl Stream for LatestStream {
    type Item = (BlockNumber, BlockHash);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let stream = &mut self.stream;
        pin_mut!(stream);
        stream.poll_next(cx)
    }
}

impl LatestStream {
    fn spawn(fgw: GatewayClient, head_poll_interval: Duration) -> Self {
        // No buffer, for backpressure
        let (tx, rx) = watch::channel((BlockNumber::GENESIS, BlockHash::ZERO));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(head_poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                interval.tick().await;

                let Ok(latest) = fgw
                    .block_header(pathfinder_common::BlockId::Latest)
                    .await
                    .inspect_err(|e| tracing::debug!(error=%e, "Error requesting latest block ID"))
                else {
                    continue;
                };

                tracing::trace!(?latest, "LatestStream");

                if tx.is_closed() {
                    tracing::debug!("Channel closed, exiting");
                    break;
                }

                tx.send_if_modified(|current| {
                    // TODO: handle reorgs correctly
                    if *current != latest {
                        tracing::info!(?latest, "LatestStream");
                        *current = latest;
                        true
                    } else {
                        false
                    }
                });
            }
        });

        Self {
            rx: rx.clone(),
            stream: WatchStream::from_changes(rx),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::stream;
    use p2p::client::types::{
        ClassDefinition,
        ClassDefinitionsError,
        EventsForBlockByTransaction,
        EventsResponseStreamFailure,
        Receipt as P2PReceipt,
        StateDiffsError,
    };
    use p2p::libp2p::PeerId;
    use pathfinder_common::event::Event;
    use pathfinder_common::state_update::StateUpdateData;
    use pathfinder_common::transaction::Transaction;
    use pathfinder_common::{BlockId, ClassHash, SignedBlockHeader, TransactionHash};
    use pathfinder_ethereum::EthereumClient;
    use pathfinder_storage::fake::Block;
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_types::error::SequencerError;

    use super::*;

    #[test]
    fn checkpoint_restarts_after_recoverable_error() {
        let s = Sync {
            storage: StorageBuilder::in_tempdir().unwrap(),
            p2p: todo!(),
            eth_client: EthereumClient::new("unused").unwrap(),
            eth_address: H160::zero(), // Unused
            fgw_client: todo!(),
            chain: Chain::SepoliaTestnet,
            chain_id: ChainId::SEPOLIA_TESTNET,
            public_key: PublicKey::ZERO, // TODO
            l1_checkpoint_override: Some(EthereumStateUpdate {
                state_root: todo!(),
                block_number: BlockNumber::new_or_panic(9),
                block_hash: todo!(),
            }),
            verify_tree_hashes: true,
        };

        // TODO
        // 2 cases here:
        // - recoverable error
        // - premature end of "current" stream
    }

    #[test]
    fn track_restarts_after_recoverable_error() {
        // TODO
        // 2 cases here:
        // - recoverable error
        // - premature end of "current" stream

        // Check if tracking has restarted from the last stored block
        // ie if next and parent_hash have advanced
    }

    #[test]
    fn checkpoint_stops_after_fatal_error() {
        // TODO
    }

    #[test]
    fn track_stops_after_fatal_error() {
        // TODO
    }

    #[derive(Clone)]
    struct FakeP2PClient {
        pub blocks: Vec<Block>,
    }

    impl FakeP2PClient {
        fn blocks<T, F>(
            mut self,
            start: BlockNumber,
            stop: BlockNumber,
            reverse: bool,
            map_fn: F,
        ) -> Vec<T>
        where
            F: FnMut(Block) -> T,
        {
            let mut blocks = self
                .blocks
                .into_iter()
                .take_while(move |b| {
                    let n = b.header.header.number;
                    n >= start && n <= stop
                })
                .collect::<Vec<_>>();

            if reverse {
                blocks.reverse();
            }

            blocks.into_iter().map(map_fn).collect()
        }
    }

    impl HeaderStream for FakeP2PClient {
        fn header_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            reverse: bool,
        ) -> impl Stream<Item = PeerData<SignedBlockHeader>> + Send {
            stream::iter(self.blocks(start, stop, reverse, |block| {
                PeerData::for_tests(block.header)
            }))
        }
    }

    impl TransactionStream for FakeP2PClient {
        fn transaction_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            // transaction_count_stream: impl Stream<Item = anyhow::Result<usize>> + Send +
            // 'static,
            _: impl Stream<Item = anyhow::Result<usize>> + Send + 'static,
        ) -> impl Stream<Item = StreamItem<(p2p::client::types::TransactionData, BlockNumber)>> + Send
        {
            stream::iter(self.blocks(start, stop, false, |block| {
                Ok(PeerData::for_tests((
                    block
                        .transaction_data
                        .into_iter()
                        .map(|(t, r, _)| (t, r.into()))
                        .collect(),
                    block.header.header.number,
                )))
            }))
        }
    }

    impl StateDiffStream for FakeP2PClient {
        fn state_diff_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            // state_diff_length_stream: impl Stream<Item = anyhow::Result<usize>> + Send +
            // 'static,
            _: impl Stream<Item = anyhow::Result<usize>> + Send + 'static,
        ) -> impl Stream<Item = StreamItem<(StateUpdateData, BlockNumber)>> + Send {
            stream::iter(self.blocks(start, stop, false, |block| {
                Ok(PeerData::for_tests((
                    block.state_update.unwrap().into(),
                    block.header.header.number,
                )))
            }))
        }
    }

    impl ClassStream for FakeP2PClient {
        fn class_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            // declared_class_count_stream: impl Stream<Item = anyhow::Result<usize>> + Send +
            // 'static,
            _: impl Stream<Item = anyhow::Result<usize>> + Send + 'static,
        ) -> impl Stream<Item = StreamItem<ClassDefinition>> + Send {
            stream::iter(
                self.blocks(start, stop, false, |block| {
                    let block_number = block.header.header.number;
                    block
                        .cairo_defs
                        .into_iter()
                        .map(move |(hash, definition)| {
                            Ok(PeerData::for_tests(ClassDefinition::Cairo {
                                block_number,
                                definition,
                                hash,
                            }))
                        })
                        .chain(block.sierra_defs.into_iter().map(
                            move |(hash, sierra_definition, _)| {
                                Ok(PeerData::for_tests(ClassDefinition::Sierra {
                                    block_number,
                                    sierra_definition,
                                    hash,
                                }))
                            },
                        ))
                })
                .into_iter()
                .flatten(),
            )
        }
    }

    impl EventStream for FakeP2PClient {
        fn event_stream(
            self,
            start: BlockNumber,
            stop: BlockNumber,
            // event_count_stream: impl Stream<Item = anyhow::Result<usize>> + Send + 'static,
            _: impl Stream<Item = anyhow::Result<usize>> + Send + 'static,
        ) -> impl Stream<Item = StreamItem<EventsForBlockByTransaction>> {
            stream::iter(self.blocks(start, stop, false, |block| {
                Ok(PeerData::for_tests((
                    block.header.header.number,
                    block
                        .transaction_data
                        .into_iter()
                        .map(|(t, _, e)| (t.hash, e))
                        .collect(),
                )))
            }))
        }
    }

    impl BlockClient for FakeP2PClient {
        async fn transactions_for_block(
            self,
            block: BlockNumber,
        ) -> Option<(
            PeerId,
            impl Stream<Item = anyhow::Result<(Transaction, P2PReceipt)>> + Send,
        )> {
            let tr = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .transaction_data
                .iter()
                .map(|(t, r, e)| Ok((t.clone(), P2PReceipt::from(r.clone()))))
                .collect::<Vec<anyhow::Result<(Transaction, P2PReceipt)>>>();

            Some((PeerId::random(), stream::iter(tr)))
        }

        async fn state_diff_for_block(
            self,
            block: BlockNumber,
            state_diff_length: u64,
        ) -> Result<Option<(PeerId, StateUpdateData)>, StateDiffsError> {
            let sd: StateUpdateData = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .state_update
                .clone()
                .unwrap()
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
                .map(|(h, x)| ClassDefinition::Cairo {
                    block_number: block,
                    definition: x.clone(),
                    hash: *h,
                })
                .chain(
                    b.sierra_defs
                        .iter()
                        .map(|(h, x, _)| ClassDefinition::Sierra {
                            block_number: block,
                            sierra_definition: x.clone(),
                            hash: *h,
                        }),
                )
                .collect::<Vec<ClassDefinition>>();

            Ok(Some((PeerId::random(), defs)))
        }

        async fn events_for_block(
            self,
            block: BlockNumber,
        ) -> Option<(
            PeerId,
            impl Stream<Item = Result<(TransactionHash, Event), EventsResponseStreamFailure>> + Send,
        )> {
            let e = self
                .blocks
                .iter()
                .find(|b| b.header.header.number == block)
                .unwrap()
                .transaction_data
                .iter()
                .flat_map(|(t, _, e)| e.iter().map(move |e| (t.hash, e.clone())))
                .map(Ok)
                .collect::<Vec<_>>();

            Some((PeerId::random(), stream::iter(e)))
        }
    }

    #[derive(Clone)]
    struct FakeFgw {
        head: (BlockNumber, BlockHash),
    }

    #[async_trait::async_trait]
    impl GatewayApi for FakeFgw {
        async fn pending_casm_by_hash(&self, _: ClassHash) -> Result<bytes::Bytes, SequencerError> {
            Ok(bytes::Bytes::from_static(b"I'm from the fgw!"))
        }

        async fn block_header(
            &self,
            block: BlockId,
        ) -> Result<(BlockNumber, BlockHash), SequencerError> {
            assert_eq!(block, BlockId::Latest);
            Ok(self.head)
        }
    }
}
