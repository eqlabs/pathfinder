use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{BlockHeader, BlockNumber, StateUpdate};
use pathfinder_storage::Transaction;
use starknet_gateway_types::reply::{GasPrices, PendingBlock, Status};

use tokio::sync::watch::Receiver as WatchReceiver;

/// Provides the latest [PendingData] which is consistent with a given
/// view of storage.
#[derive(Clone)]
pub struct PendingWatcher(WatchReceiver<PendingData>);

#[derive(Clone, Default, Debug, PartialEq)]
pub struct PendingData {
    pub block: Arc<PendingBlock>,
    pub state_update: Arc<StateUpdate>,
    pub number: BlockNumber,
}

impl PendingData {
    pub fn header(&self) -> BlockHeader {
        // Be explicit about fields so that we are forced to check
        // if any new fields are added.
        BlockHeader {
            parent_hash: self.block.parent_hash,
            number: self.number,
            timestamp: self.block.timestamp,
            eth_l1_gas_price: self.block.l1_gas_price.price_in_wei,
            strk_l1_gas_price: self.block.l1_gas_price.price_in_fri,
            eth_l1_data_gas_price: self.block.l1_data_gas_price.price_in_wei,
            strk_l1_data_gas_price: self.block.l1_data_gas_price.price_in_fri,
            sequencer_address: self.block.sequencer_address,
            starknet_version: self.block.starknet_version.clone(),
            // Pending block does not know what these are yet.
            hash: Default::default(),
            class_commitment: Default::default(),
            event_commitment: Default::default(),
            state_commitment: Default::default(),
            storage_commitment: Default::default(),
            transaction_commitment: Default::default(),
            transaction_count: Default::default(),
            event_count: Default::default(),
            l1_da_mode: self.block.l1_da_mode.into(),
        }
    }
}

impl PendingWatcher {
    pub fn new(receiver: WatchReceiver<PendingData>) -> Self {
        Self(receiver)
    }

    /// Returns [PendingData] which has been validated against the latest block
    /// available in storage.
    ///
    /// Returns an empty block with gas price and timestamp taken from the latest
    /// block if no valid pending data is available. The block number is also incremented.
    pub fn get(&self, tx: &Transaction<'_>) -> anyhow::Result<PendingData> {
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
                    l1_gas_price: GasPrices {
                        price_in_wei: latest.eth_l1_gas_price,
                        price_in_fri: latest.strk_l1_gas_price,
                    },
                    l1_data_gas_price: GasPrices {
                        price_in_wei: latest.eth_l1_data_gas_price,
                        price_in_fri: latest.strk_l1_data_gas_price,
                    },
                    timestamp: latest.timestamp,
                    parent_hash: latest.hash,
                    starknet_version: latest.starknet_version,
                    l1_da_mode: latest.l1_da_mode.into(),
                    // This shouldn't have an impact anywhere as the RPC methods should
                    // know this is a pending block. But rather safe than sorry.
                    status: Status::Pending,
                    sequencer_address: latest.sequencer_address,
                    transaction_receipts: vec![],
                    transactions: vec![],
                }
                .into(),
                state_update: Default::default(),
                number: latest.number + 1,
            };

            Ok(data)
        }
    }

    #[cfg(test)]
    pub fn get_unchecked(&self) -> PendingData {
        self.0.borrow().clone()
    }
}

#[cfg(test)]
mod tests {

    use pathfinder_common::{macro_prelude::*, L1DataAvailabilityMode};
    use pathfinder_common::{BlockHeader, BlockTimestamp, GasPrice};

    use super::*;

    #[test]
    fn valid() {
        let (sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        let latest = BlockHeader::builder()
            .with_eth_l1_gas_price(GasPrice(1234))
            .with_strk_l1_gas_price(GasPrice(3377))
            .with_timestamp(BlockTimestamp::new_or_panic(6777))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&latest).unwrap();

        let pending = PendingData {
            block: PendingBlock {
                parent_hash: latest.hash,
                timestamp: BlockTimestamp::new_or_panic(112233),
                l1_gas_price: GasPrices {
                    price_in_wei: GasPrice(51123),
                    price_in_fri: GasPrice(44411),
                },
                ..Default::default()
            }
            .into(),
            state_update: StateUpdate::default()
                .with_contract_nonce(
                    contract_address_bytes!(b"contract address"),
                    contract_nonce_bytes!(b"nonce"),
                )
                .into(),
            number: BlockNumber::GENESIS + 10,
        };
        sender.send(pending.clone()).unwrap();

        let result = uut.get(&tx).unwrap();
        pretty_assertions_sorted::assert_eq_sorted!(result, pending);
    }

    #[test]
    fn invalid_defaults_to_latest_in_storage() {
        // If the pending data isn't consistent with the latest data in storage,
        // then the result should be an empty block with the gas price, timestamp
        // and hash as parent hash of the latest block in storage.

        let (_sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        // Required otherwise latest doesn't have a valid parent hash in storage.
        let parent = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS + 12)
            .finalize_with_hash(block_hash_bytes!(b"parent hash"));

        let latest = parent
            .child_builder()
            .with_eth_l1_gas_price(GasPrice(1234))
            .with_strk_l1_gas_price(GasPrice(3377))
            .with_eth_l1_data_gas_price(GasPrice(9999))
            .with_strk_l1_data_gas_price(GasPrice(8888))
            .with_l1_da_mode(L1DataAvailabilityMode::Blob)
            .with_timestamp(BlockTimestamp::new_or_panic(6777))
            .with_sequencer_address(sequencer_address!("0xffff"))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&parent).unwrap();
        tx.insert_block_header(&latest).unwrap();

        let result = uut.get(&tx).unwrap();

        let expected = PendingData {
            block: PendingBlock {
                l1_gas_price: GasPrices {
                    price_in_wei: latest.eth_l1_gas_price,
                    price_in_fri: latest.strk_l1_gas_price,
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: latest.eth_l1_data_gas_price,
                    price_in_fri: latest.strk_l1_data_gas_price,
                },
                l1_da_mode: latest.l1_da_mode.into(),
                timestamp: latest.timestamp,
                sequencer_address: latest.sequencer_address,
                parent_hash: latest.hash,
                starknet_version: latest.starknet_version,
                status: Status::Pending,
                ..Default::default()
            }
            .into(),
            number: latest.number + 1,
            ..Default::default()
        };

        pretty_assertions_sorted::assert_eq_sorted!(result, expected);
    }
}
