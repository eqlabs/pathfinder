use std::pin::Pin;

use futures::{Stream, StreamExt};
use pathfinder_common::{BlockHash, BlockNumber, StateUpdate};
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use primitive_types::H160;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::{Block, PendingBlock};
use tokio::time::Duration;
use tokio_stream::StreamNotifyClose;

use crate::sync::source::watcher::PollingWatchStream;

mod block;
mod ethereum;
mod head;
mod pending;
mod watcher;

/// Convenience alias for [GatewayApi].
pub trait Gateway: GatewayApi + Send + 'static {}
impl<G> Gateway for G where G: GatewayApi + Send + 'static {}

/// A multistream which allows merges pending, head, ethereum watch streams as well as 
/// block stream. Uses [StreamMap](tokio_stream::StreamMap) to merge streams, and [StreamNotifyClose]
/// to notify when a substream closes.
#[derive(Default)]
pub struct SourceStream {
    inner: tokio_stream::StreamMap<StreamKind, Pin<Box<dyn Stream<Item = Option<StreamItem>>>>>,
}

impl SourceStream {
    /// Adds a substream which polls the pending block.
    pub fn poll_pending(mut self, gateway: impl Gateway, poll_period: Duration) -> Self {
        let source = pending::PendingSource::new(gateway);
        let stream = PollingWatchStream::new(source, poll_period);
        let stream = stream.map(StreamItem::Pending);
        let stream = StreamNotifyClose::new(stream).boxed();

        self.inner.insert(StreamKind::Pending, stream);

        self
    }

    /// Adds a substream which polls the head of the chain.
    pub fn poll_head(mut self, gateway: impl Gateway, poll_period: Duration) -> Self {
        let source = head::HeadSource::new(gateway);
        let stream = PollingWatchStream::new(source, poll_period);
        let stream = stream.map(StreamItem::Head);
        let stream = StreamNotifyClose::new(stream).boxed();
        self.inner.insert(StreamKind::Head, stream);

        self
    }

    /// Adds a substream which polls the latest Ethereum state.
    pub fn poll_ethereum<E>(mut self, client: E, core_address: H160, poll_period: Duration) -> Self
    where
        E: EthereumApi + Sync + Send + 'static,
    {
        let source = ethereum::EthereumSource::new(client, core_address);
        let stream = PollingWatchStream::new(source, poll_period);
        let stream = stream.map(StreamItem::Ethereum);
        let stream = StreamNotifyClose::new(stream).boxed();
        self.inner.insert(StreamKind::Ethereum, stream);

        self
    }

    /// Adds a substream which emits sequential starknet blocks.
    pub fn stream_blocks(
        mut self,
        gateway: impl Gateway,
        start: BlockNumber,
        poll_period: Duration,
    ) -> Self {
        let stream = block::BlockStream::new(gateway, start, poll_period);
        let stream = stream.map(StreamItem::Block);
        let stream = StreamNotifyClose::new(stream).boxed();
        self.inner.insert(StreamKind::Block, stream);

        self
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum StreamKind {
    Head,
    Pending,
    Block,
    Ethereum,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StreamItem {
    Head((BlockNumber, BlockHash)),
    Pending((PendingBlock, StateUpdate)),
    Block((Block, StateUpdate)),
    Ethereum(EthereumStateUpdate),
}

impl Stream for SourceStream {
    type Item = (StreamKind, Option<StreamItem>);

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod stream_kind {
        //! Ensure that each stream is correctly mapped to a stream kind and item.
        use assert_matches::assert_matches;
        use pathfinder_common::{block_hash_bytes, state_commitment_bytes, BlockId};
        use starknet_gateway_types::error::SequencerError;
        use starknet_gateway_types::reply::MaybePendingBlock;

        use super::*;

        struct TestGateway;
        #[async_trait::async_trait]
        impl GatewayApi for TestGateway {
            async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
                Ok((BlockNumber::GENESIS + 1, block_hash_bytes!(b"block hash")))
            }

            async fn state_update_with_block(
                &self,
                block: BlockId,
            ) -> Result<(MaybePendingBlock, StateUpdate), SequencerError> {
                if block == BlockId::Pending {
                    Ok((
                        MaybePendingBlock::Pending(PendingBlock {
                            parent_hash: block_hash_bytes!(b"parent block hash"),
                            ..Default::default()
                        }),
                        StateUpdate::default(),
                    ))
                } else {
                    Ok((
                        MaybePendingBlock::Block(Default::default()),
                        StateUpdate::default(),
                    ))
                }
            }
        }

        #[tokio::test]
        async fn head() {
            let mut stream = SourceStream::default().poll_head(TestGateway, Duration::from_nanos(1));
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Head);
            assert_matches!(item, Some(StreamItem::Head(_)));
        }

        #[tokio::test]
        async fn pending() {
            let mut stream = SourceStream::default().poll_pending(TestGateway, Duration::from_nanos(1));
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Pending);
            assert_matches!(item, Some(StreamItem::Pending(_)));
        }

        #[tokio::test]
        async fn block() {
            let mut stream = SourceStream::default().stream_blocks(
                TestGateway,
                BlockNumber::GENESIS,
                Duration::from_nanos(1),
            );
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Block);
            assert_matches!(item, Some(StreamItem::Block(_)));
        }

        #[tokio::test]
        async fn ethereum() {
            struct TestEthereum;
            #[async_trait::async_trait]
            impl EthereumApi for TestEthereum {
                async fn get_starknet_state(
                    &self,
                    _: &H160,
                ) -> anyhow::Result<EthereumStateUpdate> {
                    Ok(EthereumStateUpdate {
                        block_hash: block_hash_bytes!(b"block hash"),
                        block_number: BlockNumber::GENESIS + 1,
                        state_root: state_commitment_bytes!(b"root"),
                    })
                }

                async fn get_chain(&self) -> anyhow::Result<pathfinder_common::EthereumChain> {
                    unimplemented!();
                }
            }

            let mut stream = SourceStream::default().poll_ethereum(
                TestEthereum,
                H160::default(),
                Duration::from_nanos(1),
            );
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Ethereum);
            assert_matches!(item, Some(StreamItem::Ethereum(_)));
        }
    }

    mod substream_closure {
        //! A closed substream is correctly marked.
        use super::*;

        /// This gateway always panics, which will cause any stream using it to panic and close.
        struct PanicGateway;
        impl GatewayApi for PanicGateway {}

        #[tokio::test]
        async fn head() {
            let mut stream = SourceStream::default().poll_head(PanicGateway, Duration::from_nanos(1));
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Head);
            assert!(item.is_none());
        }

        #[tokio::test]
        async fn pending() {
            let mut stream = SourceStream::default().poll_pending(PanicGateway, Duration::from_nanos(1));
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Pending);
            assert!(item.is_none());
        }

        #[tokio::test]
        async fn block() {
            let mut stream = SourceStream::default().stream_blocks(
                PanicGateway,
                BlockNumber::GENESIS,
                Duration::from_nanos(1),
            );
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Block);
            assert!(item.is_none());
        }

        #[tokio::test]
        async fn ethereum() {
            struct PanicEthereum;
            #[async_trait::async_trait]
            impl EthereumApi for PanicEthereum {
                async fn get_starknet_state(
                    &self,
                    _: &H160,
                ) -> anyhow::Result<EthereumStateUpdate> {
                    unimplemented!();
                }

                async fn get_chain(&self) -> anyhow::Result<pathfinder_common::EthereumChain> {
                    unimplemented!();
                }
            }

            let mut stream = SourceStream::default().poll_ethereum(
                PanicEthereum,
                H160::default(),
                Duration::from_nanos(1),
            );
            let (kind, item) = stream.next().await.unwrap();
            assert_eq!(kind, StreamKind::Ethereum);
            assert!(item.is_none());
        }
    }
}
