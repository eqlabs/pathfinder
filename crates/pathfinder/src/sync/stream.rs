use futures::{Future, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use p2p::libp2p::PeerId;
use p2p::PeerData;
use tokio::sync::mpsc::Receiver;
use tokio_stream::wrappers::ReceiverStream;

use crate::sync::error::SyncError2;

pub struct SyncReceiver<T> {
    inner: Receiver<SyncResult<T>>,
}
/// Receives a chunk of `[Vec<T>]` items, created via
/// [SyncReceiver::try_chunks].
pub struct ChunkSyncReceiver<T>(SyncReceiver<Vec<T>>);

pub type SyncResult<T> = Result<PeerData<T>, PeerData<SyncError2>>;

pub trait ProcessStage {
    type Input;
    type Output;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2>;
}

impl<T: Send + 'static> ChunkSyncReceiver<T> {
    /// Adds a [ProcessStage] to the stream pipeline spawned as a separate task.
    ///
    /// `buffer` specifies the amount of buffering applied to the output stream.
    pub fn pipe<S>(self, stage: S, buffer: usize) -> SyncReceiver<S::Output>
    where
        S: ProcessStage<Input = Vec<T>> + Send + 'static,
        S::Output: Send,
    {
        self.0.pipe_impl(stage, buffer)
    }
}

impl<T: Send + 'static> SyncReceiver<T> {
    /// Adds a [ProcessStage] to the stream pipeline spawned as a separate task.
    ///
    /// `buffer` specifies the amount of buffering applied to the output stream.
    pub fn pipe<S>(self, stage: S, buffer: usize) -> SyncReceiver<S::Output>
    where
        S: ProcessStage<Input = T> + Send + 'static,
        S::Output: Send,
    {
        self.pipe_impl(stage, buffer)
    }

    fn pipe_impl<S>(mut self, mut stage: S, buffer: usize) -> SyncReceiver<S::Output>
    where
        S: ProcessStage<Input = T> + Send + 'static,
        S::Output: Send,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        std::thread::spawn(move || {
            while let Some(input) = self.inner.blocking_recv() {
                let result = match input {
                    Ok(PeerData { peer, data }) => stage
                        .map(data)
                        .map(|x| PeerData::new(peer, x))
                        .map_err(|e| PeerData::new(peer, e)),
                    Err(e) => Err(e),
                };

                let is_err = result.is_err();
                if tx.blocking_send(result).is_err() || is_err {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }

    /// Adds a stage which chunks the incoming elements into a vector before
    /// passing it on.
    ///
    /// `capacity` specifies the number of elements, `buffer` specifies the
    /// output buffering.
    pub fn try_chunks(mut self, capacity: usize, buffer: usize) -> ChunkSyncReceiver<T> {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        std::thread::spawn(move || {
            let mut chunk = Vec::with_capacity(capacity);
            let mut peer = PeerId::random();
            let mut err = None;

            while let Some(input) = self.inner.blocking_recv() {
                let input = match input {
                    Ok(x) => x,
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                };

                // 1st element, assign peer ID.
                if chunk.is_empty() {
                    peer = input.peer;
                }

                chunk.push(input.data);

                if chunk.len() == capacity {
                    let data = std::mem::replace(&mut chunk, Vec::with_capacity(capacity));
                    if tx.blocking_send(Ok(PeerData::new(peer, data))).is_err() {
                        break;
                    };
                }
            }

            // Send any remaining elements.
            if !chunk.is_empty() {
                _ = tx.blocking_send(Ok(PeerData::new(peer, chunk)));
            }

            if let Some(err) = err {
                _ = tx.blocking_send(Err(err));
            }
        });

        ChunkSyncReceiver(SyncReceiver::from_receiver(rx))
    }

    pub fn from_receiver(receiver: Receiver<SyncResult<T>>) -> Self
    where
        T: Send,
    {
        Self { inner: receiver }
    }

    #[cfg(test)]
    pub fn iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = SyncResult<T>> + Send + 'static,
        I::IntoIter: Send,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            for value in iter.into_iter() {
                if tx.send(value).await.is_err() {
                    return;
                }
            }
        });
        Self::from_receiver(rx)
    }

    pub fn into_stream(self) -> ReceiverStream<SyncResult<T>> {
        ReceiverStream::new(self.inner)
    }

    pub async fn recv(&mut self) -> Option<SyncResult<T>> {
        self.inner.recv().await
    }
}

/// A [ProcessStage] which buffers `N` elements into a vector before passing it
/// on.
pub struct Buffer(pub usize);

#[cfg(test)]
mod tests {
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
        #[case] input: Vec<Result<u8, SyncError2>>,
        #[case] expected: Vec<Result<u8, SyncError2>>,
    ) {
        struct NoOp;
        impl ProcessStage for NoOp {
            type Input = u8;
            type Output = u8;

            fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
                Ok(input)
            }
        }

        let peer = PeerId::random();

        let input = SyncReceiver::iter(
            input
                .into_iter()
                .map(move |x| PeerData::from_result(peer, x)),
        );
        let expected = expected
            .into_iter()
            .map(|x| PeerData::from_result(peer, x))
            .collect::<Vec<_>>();

        let stage = NoOp {};

        let output = input.pipe(stage, 5).into_stream().collect::<Vec<_>>().await;

        assert_eq!(output, expected);
    }

    #[tokio::test]
    async fn short_circuit_on_map_error() {
        struct OnlyOnce(u8);

        impl ProcessStage for OnlyOnce {
            type Input = u8;
            type Output = u8;

            fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
                if self.0 == 0 {
                    self.0 = 1;
                    Ok(input)
                } else {
                    Err(SyncError2::BadBlockHash)
                }
            }
        }

        let peer = PeerId::random();
        let input = (0..10).map(move |x| PeerData::from_result(peer, Ok(x)));
        let expected = vec![
            Ok(PeerData::new(peer, 0)),
            Err(PeerData::new(peer, SyncError2::BadBlockHash)),
        ];

        let stage = OnlyOnce(0);
        let result = SyncReceiver::iter(input)
            .pipe(stage, 5)
            .into_stream()
            .collect::<Vec<_>>()
            .await;

        assert_eq!(result, expected);
    }
}
