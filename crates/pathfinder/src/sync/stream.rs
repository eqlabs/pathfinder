use futures::{Future, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use p2p::libp2p::PeerId;
use p2p::PeerData;

use crate::sync::error::SyncError2;

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
    fn map_stage<S>(
        mut self,
        mut stage: S,
        buffer: usize,
    ) -> impl SyncStream<S::Output> + Sized + Send + 'static
    where
        S: MapStage<Input = T> + Send + 'static,
        S::Output: Send,
        T: Send,
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
}
