use std::pin::Pin;

use futures::Stream;
use pathfinder_common::{BlockNumber, StateUpdate};

use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::{Block, MaybePendingBlock};
use tokio::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

use crate::sync::source::Gateway;

/// Streams sequential blocks from the gateway. Once the tip of chain is reached,
/// it polls at the given period i.e. before the tip it will stream as fast as possible.
pub struct BlockStream(ReceiverStream<(Block, StateUpdate)>);

impl BlockStream {
    /// Creates a [BlockStream] which starts streaming blocks from the given start point. Note
    /// that the start block is included in the stream.
    pub fn new(gateway: impl Gateway, start: BlockNumber, poll_period: Duration) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(2);

        tokio::spawn(async move {
            let mut target = start;

            loop {
                // Track starting time so we can sleep if no new block is produced.
                let t = tokio::time::Instant::now();
                let mut should_sleep = true;

                let result = gateway.state_update_with_block(target.into()).await;

                match result {
                    Ok((MaybePendingBlock::Block(block), state_update)) => {
                        should_sleep = false;
                        target += 1;
                        if tx.send((block, state_update)).await.is_err() {
                            break;
                        }
                    }
                    Ok((MaybePendingBlock::Pending(_), _)) => {
                        tracing::warn!(block=%target, "Gateway returned pending data")
                    }
                    // Don't log block not found errors as these are expected once we exceed the end of the chain.
                    Err(SequencerError::StarknetError(e)) if e.is_block_not_found() => {}
                    Err(error) => {
                        tracing::warn!(?error, block=%target, "Error while streaming blocks")
                    }
                }

                if should_sleep {
                    tokio::time::sleep_until(t + poll_period).await;
                }
            }
        });

        Self(ReceiverStream::new(rx))
    }
}

impl Stream for BlockStream {
    type Item = (Block, StateUpdate);

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().0).poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, VecDeque};

    use pathfinder_common::BlockId;
    use starknet_gateway_client::GatewayApi;
    use starknet_gateway_types::error::{KnownStarknetErrorCode, StarknetError, StarknetErrorCode};
    use starknet_gateway_types::reply::PendingBlock;
    use tokio::sync::Mutex;
    use tokio_stream::StreamExt;

    /// Helper to make test responses more manageable.
    ///
    /// Multiple responses are allowed per block number as the stream may
    /// repeatedly query the same block if its unsuccesful.
    #[derive(Default)]
    struct GatewayResponses(
        HashMap<BlockNumber, VecDeque<Result<(MaybePendingBlock, StateUpdate), SequencerError>>>,
    );

    impl GatewayResponses {
        fn with_error(mut self, number: BlockNumber) -> Self {
            self.0
                .entry(number)
                .or_default()
                .push_back(Err(SequencerError::InvalidStarknetErrorVariant));
            self
        }

        fn with_block(mut self, number: BlockNumber) -> Self {
            let block = Block {
                block_number: number,
                ..Default::default()
            };
            self.0
                .entry(number)
                .or_default()
                .push_back(Ok((block.into(), StateUpdate::default())));
            self
        }

        fn with_pending_block(mut self, number: BlockNumber) -> Self {
            let block = PendingBlock::default();
            self.0
                .entry(number)
                .or_default()
                .push_back(Ok((block.into(), StateUpdate::default())));
            self
        }

        fn pop(
            &mut self,
            number: BlockNumber,
        ) -> Option<Result<(MaybePendingBlock, StateUpdate), SequencerError>> {
            self.0.get_mut(&number).map(|x| x.pop_front()).flatten()
        }
    }

    struct GatewayMock(Mutex<GatewayResponses>);
    impl GatewayMock {
        fn new(responses: GatewayResponses) -> Self {
            Self(Mutex::new(responses))
        }
    }

    #[async_trait::async_trait]
    impl GatewayApi for GatewayMock {
        async fn state_update_with_block(
            &self,
            block: BlockId,
        ) -> Result<(MaybePendingBlock, StateUpdate), SequencerError> {
            let BlockId::Number(block) = block else {
                unimplemented!("Gateway mock only supports block number queries");
            };
            self.0
                .lock()
                .await
                .pop(block)
                .ok_or(SequencerError::StarknetError(StarknetError {
                    code: StarknetErrorCode::Known(KnownStarknetErrorCode::BlockNotFound),
                    message: "Block not found".to_string(),
                }))
                .and_then(|x| x)
        }
    }

    #[tokio::test]
    async fn errors_are_ignored() {
        let responses = GatewayResponses::default()
            .with_error(BlockNumber::GENESIS)
            .with_block(BlockNumber::GENESIS);

        let gateway = GatewayMock::new(responses.into());
        let mut stream = BlockStream::new(gateway, BlockNumber::GENESIS, Duration::from_nanos(1));

        let item = stream.next().await;
        assert!(item.is_some());
    }

    #[tokio::test]
    async fn pending_blocks_are_ignored() {
        let responses = GatewayResponses::default()
            .with_pending_block(BlockNumber::GENESIS)
            .with_block(BlockNumber::GENESIS);

        let gateway = GatewayMock::new(responses.into());
        let mut stream = BlockStream::new(gateway, BlockNumber::GENESIS, Duration::from_nanos(1));

        let item = stream.next().await;
        assert!(item.is_some());
    }

    #[tokio::test]
    async fn blocks_are_sequential() {
        let responses = GatewayResponses::default()
            .with_block(BlockNumber::GENESIS)
            .with_block(BlockNumber::GENESIS + 1)
            .with_block(BlockNumber::GENESIS + 2);

        let gateway = GatewayMock::new(responses.into());
        let stream = BlockStream::new(gateway, BlockNumber::GENESIS, Duration::from_nanos(1));

        let blocks = stream
            .take(3)
            .map(|b| b.0.block_number.get())
            .collect::<Vec<_>>()
            .await;

        assert_eq!(&blocks, &[0, 1, 2]);
    }
}
