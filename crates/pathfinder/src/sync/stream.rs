use std::time::Duration;

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

    /// Used to identify this stage in metrics and traces.
    const NAME: &'static str;

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
        self.0.pipe_impl(stage, buffer, |x| x.len())
    }
}

/// A [std::fmt::Display] helper struct for logging queue fullness.
struct Fullness(usize, usize);

impl std::fmt::Display for Fullness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:.0}% ({}/{})",
            self.0 as f32 / self.1 as f32 * 100.0,
            self.0,
            self.1
        ))
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
        self.pipe_impl(stage, buffer, |_| 1)
    }

    /// Similar to [SyncReceiver::pipe], but processes each element in the
    /// input individually.
    pub fn pipe_each<S, U>(mut self, mut stage: S, buffer: usize) -> SyncReceiver<Vec<S::Output>>
    where
        T: IntoIterator<Item = U> + Send + 'static,
        S: ProcessStage<Input = U> + Send + 'static,
        S::Output: Send,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        std::thread::spawn(move || {
            let queue_capacity = self.inner.max_capacity();

            while let Some(input) = self.inner.blocking_recv() {
                let result = match input {
                    Ok(PeerData { peer, data }) => {
                        // Stats for tracing and metrics.
                        let t = std::time::Instant::now();

                        // Process the data.
                        let output: Result<Vec<_>, _> = data
                            .into_iter()
                            .map(|data| {
                                stage.map(data).map_err(|e| {
                                    tracing::debug!(error=%e, "Processing item failed");
                                    PeerData::new(peer, e)
                                })
                            })
                            .collect();
                        let output = output.map(|x| PeerData::new(peer, x));

                        // Log trace and metrics.
                        let elements_per_sec = 1.0 / t.elapsed().as_secs_f32();
                        let queue_fullness = queue_capacity - self.inner.capacity();
                        let input_queue = Fullness(queue_fullness, queue_capacity);
                        tracing::debug!(
                            "Stage: {}, queue: {}, {elements_per_sec:.0} items/s",
                            S::NAME,
                            input_queue
                        );

                        output
                    }
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

    /// A private impl which hides the ugly `count_fn` used to differentiate
    /// between processing a single element from [SyncReceiver] and multiple
    /// elements from [ChunkSyncReceiver].
    fn pipe_impl<S, C>(
        mut self,
        mut stage: S,
        buffer: usize,
        count_fn: C,
    ) -> SyncReceiver<S::Output>
    where
        S: ProcessStage<Input = T> + Send + 'static,
        S::Output: Send,
        C: Fn(&T) -> usize + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer);

        std::thread::spawn(move || {
            let queue_capacity = self.inner.max_capacity();

            while let Some(input) = self.inner.blocking_recv() {
                let result = match input {
                    Ok(PeerData { peer, data }) => {
                        // Stats for tracing and metrics.
                        let count = count_fn(&data);
                        let t = std::time::Instant::now();

                        // Process the data.
                        let output = stage
                            .map(data)
                            .map(|x| PeerData::new(peer, x))
                            .map_err(|e| {
                                tracing::debug!(error=%e, "Processing item failed");
                                PeerData::new(peer, e)
                            });

                        // Log trace and metrics.
                        let elements_per_sec = count as f32 / t.elapsed().as_secs_f32();
                        let queue_fullness = queue_capacity - self.inner.capacity();
                        let input_queue = Fullness(queue_fullness, queue_capacity);
                        tracing::trace!(stage=%S::NAME, %input_queue, %elements_per_sec,
                            "Stage metrics"
                        );

                        output
                    }
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

/// A source that can be spawned from an infallible [PeerData] stream.
pub struct InfallibleSource<T, I>(T)
where
    T: Stream<Item = PeerData<I>> + Send + 'static,
    I: Send + 'static;

impl<T, I> InfallibleSource<T, I>
where
    T: Stream<Item = PeerData<I>> + Send + 'static,
    I: Send + 'static,
{
    pub fn from_stream(stream: T) -> Self {
        Self(stream)
    }

    pub fn spawn(self) -> SyncReceiver<I> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            let mut inner_stream = Box::pin(self.0);

            while let Some(item) = inner_stream.next().await {
                if tx.send(Ok(item)).await.is_err() {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

/// A source that can be spawned from a fallible [PeerData] stream.
pub struct Source<T, I>(T)
where
    T: Stream<Item = SyncResult<I>> + Send + 'static,
    I: Send + 'static;

impl<T, I> Source<T, I>
where
    T: Stream<Item = SyncResult<I>> + Send + 'static,
    I: Send + 'static,
{
    pub fn from_stream(stream: T) -> Self {
        Self(stream)
    }

    /// Short circuits on the first error.
    pub fn spawn(self) -> SyncReceiver<I> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            let mut inner_stream = Box::pin(self.0);

            while let Some(item) = inner_stream.next().await {
                let item_is_err = item.is_err();
                if tx.send(item).await.is_err() || item_is_err {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

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
            const NAME: &'static str = "No-op";
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
            const NAME: &'static str = "Once-once";
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

    #[tokio::test]
    async fn short_circuit_on_source_error() {
        let ok = Ok(PeerData::for_tests(0));
        let err = Err(PeerData::for_tests(SyncError2::BadBlockHash));
        let ok_unprocessed = Ok(PeerData::for_tests(1));

        let input = vec![ok.clone(), err.clone(), ok_unprocessed];
        let expected = vec![ok, err];

        let source = Source::from_stream(futures::stream::iter(input));
        let actual = source.spawn().into_stream().collect::<Vec<_>>().await;

        assert_eq!(actual, expected);
    }
}
