use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{BlockNumber, StateUpdate};
use pathfinder_storage::Transaction;
use starknet_gateway_types::reply::{PendingBlock, Status};

use tokio::sync::watch::Receiver as WatchReceiver;

/// Provides the latest [PendingData] which is consistent with a given
/// view of storage.
#[derive(Clone)]
pub struct PendingWatcher(WatchReceiver<Arc<PendingData>>);

#[derive(Default, Debug, PartialEq)]
pub struct PendingData {
    pub block: PendingBlock,
    pub state_update: StateUpdate,
    pub number: BlockNumber,
}

impl PendingWatcher {
    pub fn new(receiver: WatchReceiver<Arc<PendingData>>) -> Self {
        Self(receiver)
    }

    /// Returns [PendingData] which has been validated against the latest block
    /// available in storage.
    ///
    /// Returns an empty block with gas price and timestamp taken from the latest
    /// block if no valid pending data is available. The block number is also incremented.
    pub fn get(&self, tx: &Transaction<'_>) -> anyhow::Result<Arc<PendingData>> {
        let latest = tx
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block header")?
            .unwrap_or_default();

        let data = self.0.borrow().clone();
        if data.block.parent_hash == latest.hash {
            Ok(data)
        } else {
            let data = PendingData {
                block: PendingBlock {
                    gas_price: latest.gas_price,
                    timestamp: latest.timestamp,
                    parent_hash: latest.hash,
                    starknet_version: latest.starknet_version,
                    // This shouldn't have an impact anywhere as the RPC methods should
                    // know this is a pending block. But rather safe than sorry.
                    status: Status::Pending,
                    ..Default::default()
                },
                state_update: StateUpdate::default(),
                number: latest.number + 1,
            };

            Ok(Arc::new(data))
        }
    }

    #[cfg(test)]
    pub fn get_unchecked(&self) -> Arc<PendingData> {
        self.0.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHeader, BlockTimestamp, GasPrice};

    use super::*;

    #[test]
    fn valid() {
        let (sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::Storage::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        let latest = BlockHeader::builder()
            .with_gas_price(GasPrice(1234))
            .with_timestamp(BlockTimestamp::new_or_panic(6777))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&latest).unwrap();

        let pending = PendingData {
            block: PendingBlock {
                parent_hash: latest.hash,
                timestamp: BlockTimestamp::new_or_panic(112233),
                gas_price: GasPrice(51123),
                ..Default::default()
            },
            state_update: StateUpdate::default().with_contract_nonce(
                contract_address_bytes!(b"contract address"),
                contract_nonce_bytes!(b"nonce"),
            ),
            number: BlockNumber::GENESIS + 10,
        };
        let pending = Arc::new(pending);
        sender.send(pending.clone()).unwrap();

        let result = uut.get(&tx).unwrap();
        pretty_assertions::assert_eq!(result, pending);
    }

    #[test]
    fn invalid_defaults_to_latest_in_storage() {
        // If the pending data isn't consistent with the latest data in storage,
        // then the result should be an empty block with the gas price, timestamp
        // and hash as parent hash of the latest block in storage.

        let (_sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::Storage::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        // Required otherwise latest doesn't have a valid parent hash in storage.
        let parent = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS + 12)
            .finalize_with_hash(block_hash_bytes!(b"parent hash"));

        let latest = parent
            .child_builder()
            .with_gas_price(GasPrice(1234))
            .with_timestamp(BlockTimestamp::new_or_panic(6777))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&parent).unwrap();
        tx.insert_block_header(&latest).unwrap();

        let result = uut.get(&tx).unwrap();

        let mut expected = PendingData::default();
        expected.block.gas_price = latest.gas_price;
        expected.block.timestamp = latest.timestamp;
        expected.block.parent_hash = latest.hash;
        expected.block.starknet_version = latest.starknet_version;
        expected.block.status = Status::Pending;
        expected.number = latest.number + 1;

        pretty_assertions::assert_eq!(*result, expected);
    }
}
