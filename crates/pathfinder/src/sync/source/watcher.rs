use tokio::time::Duration;
use tokio_stream::wrappers::WatchStream;

#[async_trait::async_trait]
pub trait WatchSource<T> {
    async fn get(&mut self) -> anyhow::Result<Option<T>>;
}

/// A stream which polls a [WatchSource] and streams only its latest value.
///
/// [Err] and [None] values are ignored and are not streamed.
pub struct PollingWatchStream<T>(WatchStream<T>);

impl<T> PollingWatchStream<T>
where
    T: Default + Clone + Send + Sync + 'static + std::fmt::Debug,
{
    pub fn new<S>(mut source: S, poll_period: Duration) -> Self
    where
        S: WatchSource<T> + Send + Sync + 'static,
    {
        let mut interval = tokio::time::interval(poll_period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let (tx, rx) = tokio::sync::watch::channel(Default::default());
        let rx = WatchStream::from_changes(rx);

        tokio::spawn(async move {
            loop {
                // Don't do extra work if stream is closed.
                tokio::select! {
                    _ = interval.tick() => {},
                    _ = tx.closed() => break,
                }

                // Don't do extra work if stream is closed. This is especially
                // important if source.get() is slow or infinitely long.
                let result = tokio::select! {
                    _ = tx.closed() => break,
                    result = source.get() => result,
                };

                match result {
                    Ok(Some(item)) => {
                        // Channel closure condition is already checked at start of loop.
                        _ = tx.send(item);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(?error, "Source encountered an error");
                    }
                }
            }
        });

        Self(rx)
    }
}

impl<T> futures::Stream for PollingWatchStream<T>
where
    T: Clone + 'static + Send + Sync,
{
    type Item = T;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.0).poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::sync::{mpsc, oneshot};

    use super::*;

    struct TestSource {
        request: mpsc::Sender<oneshot::Sender<anyhow::Result<Option<u32>>>>,
    }
    #[async_trait::async_trait]
    impl WatchSource<u32> for TestSource {
        async fn get(&mut self) -> anyhow::Result<Option<u32>> {
            let (tx, rx) = oneshot::channel();
            self.request.send(tx).await.unwrap();

            let response = rx.await.unwrap();
            response
        }
    }

    impl TestSource {
        fn new() -> (
            Self,
            mpsc::Receiver<oneshot::Sender<anyhow::Result<Option<u32>>>>,
        ) {
            let (tx, rx) = mpsc::channel(1);
            let source = Self { request: tx };

            (source, rx)
        }
    }

    #[tokio::test]
    async fn errors_are_ignored() {
        let (source, mut rx) = TestSource::new();
        let mut stream = PollingWatchStream::new(source, Duration::from_nanos(1));

        let value = 1;
        let error = anyhow::anyhow!("Fire");

        // Send a value followed by an error. Then wait for a third request
        // to ensure the first two have been processed.
        rx.recv().await.unwrap().send(Ok(Some(value))).unwrap();
        rx.recv().await.unwrap().send(Err(error)).unwrap();
        rx.recv().await.unwrap();

        let item = stream.next().await;
        assert_eq!(item, Some(value));
    }

    #[tokio::test]
    async fn none_items_are_ignored() {
        let (source, mut rx) = TestSource::new();
        let mut stream = PollingWatchStream::new(source, Duration::from_nanos(1));

        let value = 1;

        // Send a value followed by None. Then wait for a third request
        // to ensure the first two have been processed.
        rx.recv().await.unwrap().send(Ok(Some(value))).unwrap();
        rx.recv().await.unwrap().send(Ok(None)).unwrap();
        rx.recv().await.unwrap();

        let item = stream.next().await;
        assert_eq!(item, Some(value));
    }

    #[tokio::test]
    async fn only_latest_item_is_streamed() {
        let (source, mut rx) = TestSource::new();
        let mut stream = PollingWatchStream::new(source, Duration::from_nanos(1));

        let stale = 1;
        let fresh = 2;

        // Send two values. Then wait for a third request
        // to ensure the first two have been processed.
        rx.recv().await.unwrap().send(Ok(Some(stale))).unwrap();
        rx.recv().await.unwrap().send(Ok(Some(fresh))).unwrap();
        rx.recv().await.unwrap();

        let item = stream.next().await;
        assert_eq!(item, Some(fresh));
    }

    mod cleanup_on_stream_drop {
        //! [PollingWatchStream] spawns an inner task to poll the source. These tests
        //! ensure that this inner task does not leak or linger when the stream is dropped.

        use super::*;

        use tokio::time::timeout;

        #[tokio::test]
        async fn slow_interval() {
            let (source, mut get) = TestSource::new();

            let stream = PollingWatchStream::new(source, Duration::MAX);
            drop(stream);

            let result = timeout(Duration::from_millis(100), get.recv())
                .await
                .unwrap();
            // This tests makes assumptions on the internal ordering of the poll delay and get call.
            // This check ensures that `get` was never called and that our assumption still holds.
            assert!(result.is_none());
        }

        #[tokio::test]
        async fn slow_source() {
            let (source, mut get) = TestSource::new();

            // Create a stream, wait for source::get to be called, then drop the stream.
            // The stream's inner task should still be killed despite being blocked by
            // the source's get call.
            let stream = PollingWatchStream::new(source, Duration::from_nanos(1));
            get.recv().await.unwrap();
            drop(stream);

            let result = timeout(Duration::from_millis(100), get.recv())
                .await
                .unwrap();
            assert!(result.is_none());
        }
    }
}
