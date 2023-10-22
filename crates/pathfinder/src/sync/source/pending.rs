use pathfinder_common::{BlockHash, BlockId, StateUpdate};
use starknet_gateway_types::reply::PendingBlock;

use crate::sync::source::watcher::WatchSource;
use crate::sync::source::Gateway;

/// A [WatchSource] which polls a [gateway](GatewayApi) for the latest pending data.
///
/// Only emits fresh pending data i.e. a new block is emitted iff:
/// - the parent hash has changed, or
/// - the data contains more transactions.
pub struct PendingSource<G: Gateway> {
    gateway: G,
    previous_tx_count: usize,
    previous_parent_hash: BlockHash,
}

impl<G: Gateway> PendingSource<G> {
    pub fn new(gateway: G) -> Self {
        Self {
            gateway,
            previous_tx_count: 0,
            previous_parent_hash: BlockHash::ZERO,
        }
    }
}

#[async_trait::async_trait]
impl<G: Gateway> WatchSource<(PendingBlock, StateUpdate)> for PendingSource<G> {
    async fn get(&mut self) -> anyhow::Result<Option<(PendingBlock, StateUpdate)>> {
        let (block, state_update) = self
            .gateway
            .state_update_with_block(BlockId::Pending)
            .await?;

        // Ignore full blocks and stale pending data. Stale data
        // can occur due to desync'd gateways returning outdated information.
        // These are identified as blocks with less transactions (but the same
        // parent hash).
        let block = block.as_pending().filter(|b| {
            b.transactions.len() > self.previous_tx_count
                || b.parent_hash != self.previous_parent_hash
        });

        if let Some(b) = block.as_ref() {
            self.previous_parent_hash = b.parent_hash;
            self.previous_tx_count = b.transactions.len();
        }

        Ok(block.map(|b| (b, state_update)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sync::source::watcher::WatchSource;

    use pathfinder_common::macro_prelude::*;

    use starknet_gateway_client::GatewayApi;
    use starknet_gateway_types::error::SequencerError;
    use starknet_gateway_types::reply::transaction::{DeployAccountTransaction, Transaction};
    use starknet_gateway_types::reply::Block;
    use starknet_gateway_types::reply::MaybePendingBlock;

    use tokio::sync::Mutex;

    fn transaction_data() -> Transaction {
        Transaction::DeployAccount(DeployAccountTransaction {
            contract_address: contract_address!("0x1"),
            transaction_hash: transaction_hash!("0x1"),
            max_fee: fee!("0x1"),
            version: pathfinder_common::TransactionVersion::ONE,
            signature: vec![transaction_signature_elem!("0x1")],
            nonce: transaction_nonce!("0x1"),
            contract_address_salt: contract_address_salt!("0x1"),
            constructor_calldata: vec![call_param!("0x1")],
            class_hash: class_hash!("0x1"),
        })
    }

    struct GatewayMock(Mutex<Vec<(MaybePendingBlock, StateUpdate)>>);
    impl GatewayMock {
        fn source(mut responses: Vec<(MaybePendingBlock, StateUpdate)>) -> PendingSource<Self> {
            // Reverse so that we can use pop and keep the order correct.
            responses.reverse();
            PendingSource::new(Self(Mutex::new(responses)))
        }
    }

    #[async_trait::async_trait]
    impl GatewayApi for GatewayMock {
        async fn state_update_with_block(
            &self,
            block: BlockId,
        ) -> Result<(MaybePendingBlock, StateUpdate), SequencerError> {
            assert_eq!(block, BlockId::Pending);
            let output = self.0.lock().await.pop().expect("Another response");

            Ok(output)
        }
    }

    #[tokio::test]
    async fn full_block_is_none() {
        // Change the parent hash to make the stream at least consider the pending data has changed.
        let block = Block {
            parent_block_hash: block_hash_bytes!(b"different parent hash"),
            ..Default::default()
        };

        let responses = vec![(block.into(), StateUpdate::default())];
        let mut source = GatewayMock::source(responses);

        let skipped = source.get().await.unwrap();
        assert!(skipped.is_none());
    }

    #[tokio::test]
    async fn stale_data_is_none() {
        // Send a fresh data, followed by stale data which should be Some(fresh), None.

        let tx = transaction_data();
        let fresh = PendingBlock {
            transactions: std::iter::repeat(tx.clone()).take(5).collect(),
            ..Default::default()
        };
        // Stale block i.e. has less transactions than the fresh block.
        let stale = PendingBlock {
            transactions: Vec::from_iter(fresh.transactions.iter().cloned().skip(1)),
            ..Default::default()
        };

        let responses = vec![
            (fresh.clone().into(), StateUpdate::default()),
            (stale.into(), StateUpdate::default()),
        ];
        let mut source = GatewayMock::source(responses);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some((fresh, StateUpdate::default())));

        let skipped = source.get().await.unwrap();
        assert!(skipped.is_none());
    }

    #[tokio::test]
    async fn increased_tx_count_is_considered_fresh() {
        let tx = transaction_data();

        let original = PendingBlock {
            transactions: std::iter::repeat(tx.clone()).take(5).collect(),
            ..Default::default()
        };
        // Fresher data i.e. has more transactions
        let fresh = PendingBlock {
            transactions: std::iter::repeat(tx.clone())
                .take(original.transactions.len() * 2)
                .collect(),
            ..Default::default()
        };

        let responses = vec![
            (original.clone().into(), StateUpdate::default()),
            (fresh.clone().into(), StateUpdate::default()),
        ];
        let mut source = GatewayMock::source(responses);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some((original, StateUpdate::default())));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some((fresh, StateUpdate::default())));
    }

    #[tokio::test]
    async fn different_parent_hash_is_considered_fresh() {
        let tx = transaction_data();

        let original = PendingBlock {
            parent_hash: block_hash_bytes!(b"stale"),
            transactions: std::iter::repeat(tx.clone()).take(5).collect(),
            ..Default::default()
        };
        // Fresher data i.e. different block hash even though tx count is lower.
        let fresh = PendingBlock {
            parent_hash: block_hash_bytes!(b"fresh"),
            ..Default::default()
        };

        let responses = vec![
            (original.clone().into(), StateUpdate::default()),
            (fresh.clone().into(), StateUpdate::default()),
        ];
        let mut source = GatewayMock::source(responses);

        let result = source.get().await.unwrap();
        assert_eq!(result, Some((original, StateUpdate::default())));

        let result = source.get().await.unwrap();
        assert_eq!(result, Some((fresh, StateUpdate::default())));
    }
}
