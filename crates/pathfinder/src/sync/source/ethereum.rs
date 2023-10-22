use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use primitive_types::H160;

use crate::sync::source::watcher::WatchSource;

/// A [WatchSource] which polls the core contract on Ethereum for the latest L1 starknet state.
pub struct EthereumSource<E> {
    client: E,
    core_address: H160,
    previous: EthereumStateUpdate,
}

impl<E> EthereumSource<E> {
    pub fn new(client: E, core_address: H160) -> Self {
        Self {
            client,
            core_address,
            previous: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<E> WatchSource<EthereumStateUpdate> for EthereumSource<E>
where
    E: EthereumApi + Sync + Send,
{
    async fn get(&mut self) -> anyhow::Result<Option<EthereumStateUpdate>> {
        let update = self.client.get_starknet_state(&self.core_address).await?;

        if self.previous != update {
            self.previous = update.clone();
            Ok(Some(update))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{block_hash, state_commitment_bytes};
    use tokio::sync::Mutex;

    use super::*;

    struct EthereumMock(Mutex<Vec<EthereumStateUpdate>>);
    impl EthereumMock {
        fn source(mut responses: Vec<EthereumStateUpdate>) -> EthereumSource<Self> {
            // Reverse so that we can use pop and keep the order correct.
            responses.reverse();
            EthereumSource::new(Self(Mutex::new(responses)), H160::default())
        }
    }

    #[async_trait::async_trait]
    impl EthereumApi for EthereumMock {
        async fn get_starknet_state(&self, _: &H160) -> anyhow::Result<EthereumStateUpdate> {
            let output = self.0.lock().await.pop().expect("Another response");

            Ok(output)
        }

        async fn get_chain(&self) -> anyhow::Result<pathfinder_common::EthereumChain> {
            unimplemented!();
        }
    }

    #[tokio::test]
    async fn duplicates_are_ignored() {
        let item = EthereumStateUpdate {
            block_hash: block_hash!("0x123"),
            ..Default::default()
        };
        let items = vec![item.clone(), item.clone()];

        let mut source = EthereumMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item));

        let result = source.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn hash_change_is_considered_fresh() {
        let item0 = EthereumStateUpdate {
            block_hash: block_hash!("0x123"),
            ..Default::default()
        };
        let mut item1 = item0.clone();
        item1.block_hash = block_hash!("0x456");
        let items = vec![item0.clone(), item1.clone()];

        let mut source = EthereumMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item0));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));
    }

    #[tokio::test]
    async fn number_change_is_considered_fresh() {
        let item0 = EthereumStateUpdate {
            block_hash: block_hash!("0x123"),
            ..Default::default()
        };
        let mut item1 = item0.clone();
        item1.block_number += 1;
        let items = vec![item0.clone(), item1.clone()];

        let mut source = EthereumMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item0));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));
    }

    #[tokio::test]
    async fn state_commitment_change_is_considered_fresh() {
        let item0 = EthereumStateUpdate {
            block_hash: block_hash!("0x123"),
            ..Default::default()
        };
        let mut item1 = item0.clone();
        item1.state_root = state_commitment_bytes!(b"different");
        let items = vec![item0.clone(), item1.clone()];

        let mut source = EthereumMock::source(items);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item0));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some(item1));
    }
}
