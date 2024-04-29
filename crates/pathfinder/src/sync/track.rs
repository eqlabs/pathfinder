use std::collections::HashMap;

use anyhow::Context;
use futures::stream::BoxStream;
use futures::{Stream, StreamExt};
use p2p::client::peer_agnostic::Client as P2PClient;
use p2p::PeerData;
use pathfinder_common::event::Event;
use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, SignedBlockHeader, TransactionHash};
use tokio_stream::wrappers::ReceiverStream;

use crate::sync::error::SyncError2;
use crate::sync::events::{self, BlockEvents};
use crate::sync::headers;
use crate::sync::stream::{SyncResult, SyncStream, SyncStreamExt};

pub struct Sync<L> {
    latest: L,
    p2p: P2PClient,
    storage: pathfinder_storage::Storage,
}

impl<L> Sync<L>
where
    L: Stream<Item = (BlockNumber, BlockHash)> + Clone + Send + 'static,
{
    pub async fn run(self) -> Result<(), SyncError2> {
        let latest_local = tokio::task::spawn_blocking({
            let storage = self.storage.clone();
            move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;

                db.block_id(pathfinder_storage::BlockId::Latest)
            }
        })
        .await
        .context("Joining blocking task")?
        .context("Querying latest local block ID")?;

        let mut headers = HeaderSource {
            p2p: self.p2p.clone(),
            latest_onchain: self.latest.clone(),
            start: latest_local.unwrap_or_default().0,
        }
        .spawn()
        .map_stage(
            headers::ForwardContinuityCheck::new(latest_local.clone()),
            100,
        )
        .map_stage(headers::VerifyHash {}, 100);

        let HeaderFanout { headers, events } = HeaderFanout::from_source(headers, 10);

        let events = EventSource {
            p2p: self.p2p.clone(),
            headers: events,
        }
        .spawn()
        .map_stage(events::VerifyCommitment, 10)
        .boxed();

        let blocks = BlockStream {
            header: headers,
            events,
        }
        .spawn();

        todo!()
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
    fn spawn(self) -> impl SyncStream<SignedBlockHeader> {
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

                let mut headers =
                    Box::pin(p2p.clone().header_stream(start, latest_onchain.0, false));

                while let Some(header) = headers.next().await {
                    start = header.data.header.number + 1;

                    let header = PeerData::new(header.peer, Ok(header.data));
                    if tx.send(header).await.is_err() {
                        return;
                    }
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

struct HeaderFanout {
    headers: BoxStream<'static, PeerData<SyncResult<SignedBlockHeader>>>,
    events: BoxStream<'static, BlockHeader>,
}

impl HeaderFanout {
    fn from_source<S>(source: S, buffer: usize) -> Self
    where
        S: SyncStream<SignedBlockHeader> + Send + 'static,
    {
        let (h_tx, h_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            let mut source = Box::pin(source);
            while let Some(signed_header) = source.next().await {
                let is_err = signed_header.data.is_err();

                if h_tx.send(signed_header.clone()).await.is_err() || is_err {
                    return;
                }

                let header = signed_header
                    .data
                    .expect("Error case already handled")
                    .header;

                if e_tx.send(header).await.is_err() {
                    return;
                }
            }
        });

        Self {
            headers: ReceiverStream::new(h_rx).boxed(),
            events: ReceiverStream::new(e_rx).boxed(),
        }
    }
}

struct EventSource {
    p2p: P2PClient,
    headers: BoxStream<'static, BlockHeader>,
}

impl EventSource {
    fn spawn(self) -> impl SyncStream<BlockEvents> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, mut events) = loop {
                    if let Some(stream) = p2p.clone().events_for_block(header.number).await {
                        break stream;
                    }
                };

                let event_count = header.event_count;
                let mut block_events = BlockEvents {
                    header,
                    events: Default::default(),
                };

                // Receive the exact amount of expected events for this block.
                for _ in 0..event_count {
                    let Some((tx_hash, event)) = events.next().await else {
                        let err = PeerData::new(peer, Err(SyncError2::TooFewEvents));
                        let _ = tx.send(err).await;
                        return;
                    };

                    block_events.events.entry(tx_hash).or_default().push(event);
                }

                // Ensure that the stream is exhausted.
                if events.next().await.is_some() {
                    let err = PeerData::new(peer, Err(SyncError2::TooManyEvents));
                    let _ = tx.send(err).await;
                    return;
                }

                let block_events = PeerData::new(peer, Ok(block_events));
                if tx.send(block_events).await.is_err() {
                    return;
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

struct BlockStream {
    pub header: BoxStream<'static, PeerData<SyncResult<SignedBlockHeader>>>,
    pub events: BoxStream<'static, PeerData<SyncResult<BlockEvents>>>,
}

impl BlockStream {
    fn spawn(mut self) -> impl SyncStream<BlockData> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            loop {
                let Some(data) = self.next().await else {
                    return;
                };

                let is_err = data.data.is_err();

                if tx.send(data).await.is_err() || is_err {
                    return;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    async fn next(&mut self) -> Option<PeerData<SyncResult<BlockData>>> {
        let header = self.header.next().await?;
        let PeerData { peer, data } = header;
        let header = match data {
            Ok(x) => x,
            Err(err) => return Some(PeerData::new(peer, Err(err))),
        };

        let events = self.events.next().await?;
        let PeerData { peer, data } = events;
        let events = match data {
            Ok(x) => x.events,
            Err(err) => return Some(PeerData::new(peer, Err(err))),
        };

        Some(PeerData::new(peer, Ok(BlockData { header, events })))
    }
}

struct BlockData {
    pub header: SignedBlockHeader,
    pub events: HashMap<TransactionHash, Vec<Event>>,
}
