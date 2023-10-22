use pathfinder_common::{BlockHash, BlockNumber};

use crate::sync::source::watcher::WatchSource;
use crate::sync::source::Gateway;

/// A [WatchSource] which polls a [gateway](GatewayApi) for the latest pending data.
///
/// Only emits fresh pending data i.e. a new block is emitted iff:
/// - the parent hash has changed, or
/// - the data contains more transactions.
pub struct HeadSource<G: Gateway> {
    gateway: G,
    previous: (BlockNumber, BlockHash),
}

impl<G: Gateway> HeadSource<G> {
    pub fn new(gateway: G) -> Self {
        Self {
            gateway,
            previous: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<G: Gateway> WatchSource<(BlockNumber, BlockHash)> for HeadSource<G> {
    async fn get(&mut self) -> anyhow::Result<Option<(BlockNumber, BlockHash)>> {
        let result = self.gateway.head().await?;

        if result != self.previous {
            self.previous = result;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pathfinder_common::macro_prelude::*;
    use starknet_gateway_client::GatewayApi;
    use starknet_gateway_types::error::SequencerError;
    use tokio::sync::Mutex;

    struct GatewayMock(Mutex<Vec<(BlockNumber, BlockHash)>>);
    impl GatewayMock {
        fn source(mut responses: Vec<(BlockNumber, BlockHash)>) -> HeadSource<Self> {
            // Reverse so that we can use pop and keep the order correct.
            responses.reverse();
            HeadSource::new(Self(Mutex::new(responses)))
        }
    }

    #[async_trait::async_trait]
    impl GatewayApi for GatewayMock {
        async fn head(&self) -> Result<(BlockNumber, BlockHash), SequencerError> {
            let output = self.0.lock().await.pop().expect("Another response");

            Ok(output)
        }
    }

    #[tokio::test]
    async fn duplicates_are_ignored() {
        let item = (BlockNumber::GENESIS + 1, block_hash!("0x123"));
        let items = vec![item, item];

        let mut source = GatewayMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item));

        let result = source.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn hash_change_is_considered_fresh() {
        let item1 = (BlockNumber::GENESIS + 1, block_hash!("0x123"));
        let item2 = (item1.0, block_hash!("0x1234"));
        let items = vec![item1, item2];

        let mut source = GatewayMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item2));
    }

    #[tokio::test]
    async fn number_increment_is_considered_fresh() {
        let item1 = (BlockNumber::GENESIS + 1, block_hash!("0x123"));
        let item2 = (item1.0 + 1, block_hash!("0x123"));
        let items = vec![item1, item2];

        let mut source = GatewayMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item2));
    }

    #[tokio::test]
    async fn number_decrement_is_considered_fresh() {
        let item1 = (BlockNumber::GENESIS + 1, block_hash!("0x123"));
        let item2 = (item1.0 - 1, block_hash!("0x123"));
        let items = vec![item1, item2];

        let mut source = GatewayMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item2));
    }
}
