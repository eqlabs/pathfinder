use futures::stream::{BoxStream, FusedStream};
use futures::{Stream, StreamExt};
use p2p::client::peer_agnostic::PartialReceipt;
use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::prelude::*;
use pathfinder_common::transaction::TransactionVariant;

use crate::sync::error::SyncError2;
use crate::sync::stream::SyncReceiver;

type P2PClient = p2p::client::peer_agnostic::Client;

pub struct TransactionSource {
    p2p: P2PClient,
    target: BoxStream<'static, BlockNumber>,
    start: BlockNumber,
    counts: BoxStream<'static, (usize, TransactionCommitment)>,
}

impl TransactionSource {
    pub fn checkpoint(
        p2p: P2PClient,
        start: BlockNumber,
        stop: BlockNumber,
        counts: impl Stream<Item = (usize, TransactionCommitment)> + Send + 'static,
    ) -> Self {
        Self::track(
            p2p,
            start,
            counts,
            futures::stream::once(async move { stop }),
        )
    }

    pub fn track(
        p2p: P2PClient,
        start: BlockNumber,
        counts: impl Stream<Item = (usize, TransactionCommitment)> + Send + 'static,
        target: impl Stream<Item = BlockNumber> + Send + 'static,
    ) -> Self {
        Self {
            p2p,
            start,
            target: target.boxed(),
            counts: counts.boxed(),
        }
    }

    pub fn spawn(
        mut self,
        buffer: usize,
    ) -> SyncReceiver<Vec<(TransactionVariant, PartialReceipt)>> {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            let mut stream = None;

            while let Some(target) = self.target.next().await {
                for block in self.start.get()..=target.get() {
                    let Some((count, commitment)) = self.counts.next().await else {
                        tracing::warn!(%block, %target, "Counts stream ended prematurely");
                        return;
                    };

                    // Keep retrying stream until we succeed.
                    //
                    // If we don't isolate this process we might accidentily skip a count/commitment
                    // in the case where the block doesn't actually complete
                    // succesfully.
                    'block: loop {
                        // Refresh the stream if required. This would occur if the previous stream
                        // ended, either naturally (e.g. peer ran out of relevant data), or because
                        // we encountered an error in the stream.
                        let (peer, ref mut stream) = match &mut stream {
                            None => {
                                let (peer, data) = self
                                    .p2p
                                    .clone()
                                    .transactions_stream2(self.start, target)
                                    .await;

                                tracing::debug!(%peer, "Opened stream");
                                stream = Some((peer, data));
                                continue;
                            }
                            Some(ref mut x) => x,
                        };

                        let mut data = Vec::with_capacity(count);
                        for i in 0..count {
                            let Some(item) = stream.next().await else {
                                // It is legal for a peer to end on a block boundary.
                                if i == 0 {
                                    continue 'block;
                                } else {
                                    // The peer short-changed us.
                                    _ = tx
                                        .send(Err(PeerData::new(
                                            peer.clone(),
                                            SyncError2::TooFewTransactions,
                                        )))
                                        .await;
                                    return;
                                }
                            };

                            match item {
                                Ok(x) => data.push(x),
                                Err(err) => {
                                    _ = tx.send(Err(PeerData::new(peer.clone(), err.into()))).await;
                                    return;
                                }
                            };
                        }

                        if tx
                            .send(Ok(PeerData::new(peer.clone(), data)))
                            .await
                            .is_err()
                        {
                            return;
                        }

                        self.start += 1;
                    }
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}
