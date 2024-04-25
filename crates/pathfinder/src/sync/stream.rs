use futures::{Future, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use p2p::libp2p::PeerId;
use p2p::PeerData;

use super::error::SyncError2;

pub trait SyncStream<T>: Stream<Item = PeerData<SyncResult<T>>> {}
pub type SyncResult<T> = Result<T, SyncError2>;

impl<T, U> SyncStream<T> for U where U: Stream<Item = PeerData<SyncResult<T>>> {}

pub trait MapStage {
    type Input;
    type Output;

    fn map(
        &mut self,
        input: Self::Input,
    ) -> impl Future<Output = Result<Self::Output, SyncError2>> + Send;
}

/// A stage which collects items into buffers before outputting the collection.
///
/// This provides an [N] -> [M] style mapping where N >= M. This can therefore
/// be used to represent operations such as transforming a stream of
/// transactions to a stream of block's of transactions.
pub trait BatchStage {
    type Input;
    /// This will usually be some form of collection over [Self::Input].
    type Output;

    /// Aggregate the incoming item and optional provide an output.
    fn buffer(
        &mut self,
        input: Self::Input,
    ) -> impl Future<Output = Result<Option<Self::Output>, SyncError2>> + Send;

    /// Process and output any remaining items as the pipeline is being shut
    /// down.
    ///
    /// This may also be used to output an error if more items were expected.
    /// Note that this will only be called in the event of a successful end of
    /// stream, so this is not guaranteed to be called.
    fn flush(self) -> impl Future<Output = Result<Option<Self::Output>, SyncError2>> + Send;
}

impl<T, U> SyncStreamExt<T> for U
where
    U: SyncStream<T> + Send + 'static,
    T: Send,
{
}

pub trait SyncStreamExt<T>: SyncStream<T> + Sized + Send + 'static {
    /// Adds a [MapStage] to the stream pipeline spawned as a separate task.
    ///
    /// `buffer` specifies the amount of buffering applied to the output stream.
    fn map_stage<S>(mut self, mut stage: S, buffer: usize) -> impl SyncStream<S::Output>
    where
        S: MapStage<Input = T> + Send + 'static,
        S::Output: Send,
        T: Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            let mut stream = Box::pin(self);
            while let Some(input) = stream.next().await {
                let PeerData { peer, data } = input;
                let result = std::future::ready(data).and_then(|x| stage.map(x)).await;
                let result = PeerData::new(peer, result);

                let is_err = result.data.is_err();
                if tx.send(result).await.is_err() || is_err {
                    return;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    // / Adds a [BatchStage] to the stream pipeline spawned as a separate task.
    // /
    // / `buffer` specifies the amount of buffering applied to the output stream.
    fn stage_batch<S>(mut self, mut stage: S, buffer: usize) -> impl SyncStream<S::Output>
    where
        S: BatchStage<Input = T> + Send + 'static,
        S::Output: Send,
        T: Send,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            let mut stream = Box::pin(self);
            let mut latest_peer = None;
            while let Some(input) = stream.next().await {
                let PeerData { peer, data } = input;
                latest_peer = Some(peer);

                let result = std::future::ready(data)
                    .and_then(|x| stage.buffer(x))
                    .await
                    .transpose();

                let Some(result) = result else {
                    continue;
                };

                let result = PeerData::new(peer, result);
                let is_err = result.data.is_err();

                if tx.send(result).await.is_err() || is_err {
                    return;
                }
            }

            if let Some(output) = stage.flush().await.transpose() {
                let Some(latest_peer) = latest_peer else {
                    tracing::warn!("Flush data without an attached peer");
                    return;
                };

                let output = PeerData::new(latest_peer, output);
                let _ = tx.send(output).await;
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::{SyncStreamExt, *};

    mod map {
        use super::*;

        #[rstest::rstest]
        #[case::all_ok(
            vec![Ok(0), Ok(1), Ok(2)],
            vec![Ok(0), Ok(1), Ok(2)]
        )]
        #[case::short_circuit_on_error(
            vec![Ok(0), Ok(1), Err(SyncError2::BadBlockHash), Ok(2)],
            vec![Ok(0), Ok(1), Err(SyncError2::BadBlockHash)],
        )]
        #[tokio::test]
        async fn input_stream(
            #[case] input: Vec<SyncResult<u8>>,
            #[case] expected: Vec<SyncResult<u8>>,
        ) {
            struct NoOp;
            impl MapStage for NoOp {
                type Input = u8;
                type Output = u8;

                async fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
                    Ok(input)
                }
            }

            let peer = PeerId::random();

            let input = input
                .into_iter()
                .map(|x| PeerData::new(peer, x))
                .collect::<Vec<_>>();
            let expected = expected
                .into_iter()
                .map(|x| PeerData::new(peer, x))
                .collect::<Vec<_>>();

            let stage = NoOp {};

            let output = tokio_stream::iter(input)
                .map_stage(stage, 5)
                .collect::<Vec<_>>()
                .await;

            assert_eq!(output, expected);
        }

        #[tokio::test]
        async fn short_circuit_on_map_error() {
            struct OnlyOnce(u8);

            impl MapStage for OnlyOnce {
                type Input = u8;
                type Output = u8;

                async fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
                    if self.0 == 0 {
                        self.0 = 1;
                        Ok(input)
                    } else {
                        Err(SyncError2::BadBlockHash)
                    }
                }
            }

            let peer = PeerId::random();
            let input = (0..10)
                .map(|x| PeerData { peer, data: Ok(x) })
                .collect::<Vec<_>>();
            let expected = vec![
                PeerData { peer, data: Ok(0) },
                PeerData {
                    peer,
                    data: Err(SyncError2::BadBlockHash),
                },
            ];

            let stage = OnlyOnce(0);
            let result = tokio_stream::iter(input)
                .map_stage(stage, 5)
                .collect::<Vec<_>>()
                .await;

            assert_eq!(result, expected);
        }
    }

    #[rstest::rstest]
    #[case::ok_and_flush(
        vec![Ok(1), Ok(2), Ok(3), Ok(4)],
        vec![Ok(6), Ok(4)]
    )]
    #[case::error_short_circuits(
        vec![Ok(255), Ok(1), Ok(2)],
        vec![Err(SyncError2::BadBlockHash)]
    )]
    #[case::stream_error_short_circuits(
        vec![Ok(1), Err(SyncError2::BadBlockHash), Ok(2), Ok(3)],
        vec![Err(SyncError2::BadBlockHash)]
    )]
    #[tokio::test]
    async fn batch(#[case] input: Vec<SyncResult<u8>>, #[case] expected: Vec<SyncResult<u8>>) {
        /// Sums every 3 elements together. Flushes the sum of any remaining
        /// elements.
        ///
        /// Throws an error on overflow.
        struct Sum3 {
            count: usize,
            total: u8,
        };

        impl BatchStage for Sum3 {
            type Input = u8;
            type Output = u8;

            async fn buffer(
                &mut self,
                input: Self::Input,
            ) -> Result<Option<Self::Output>, SyncError2> {
                self.total = self
                    .total
                    .checked_add(input)
                    .ok_or(SyncError2::BadBlockHash)?;
                self.count += 1;

                if self.count == 3 {
                    self.count = 0;
                    Ok(Some(std::mem::take(&mut self.total)))
                } else {
                    Ok(None)
                }
            }

            async fn flush(self) -> Result<Option<Self::Output>, SyncError2> {
                if self.count > 0 {
                    Ok(Some(self.total))
                } else {
                    Ok(None)
                }
            }
        }

        let stage = Sum3 { count: 0, total: 0 };
        let peer = PeerId::random();

        let input = input
            .into_iter()
            .map(|x| PeerData::new(peer, x))
            .collect::<Vec<_>>();
        let expected = expected
            .into_iter()
            .map(|x| PeerData::new(peer, x))
            .collect::<Vec<_>>();

        let result = tokio_stream::iter(input)
            .stage_batch(stage, 3)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(result, expected);
    }
}
