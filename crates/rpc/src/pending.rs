use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    L1DataAvailabilityMode,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    StateUpdate,
};
use pathfinder_storage::Transaction;
use starknet_gateway_types::reply::{GasPrices, PendingBlock, Status};
use tokio::sync::watch::Receiver as WatchReceiver;

/// Provides the latest [PendingData] which is consistent with a given
/// view of storage.
#[derive(Clone)]
pub struct PendingWatcher(pub WatchReceiver<PendingData>);

#[derive(Clone, Debug, PartialEq)]
pub struct PreConfirmedBlock {
    pub l1_gas_price: GasPrices,
    pub l1_data_gas_price: GasPrices,
    pub l2_gas_price: GasPrices,

    pub sequencer_address: SequencerAddress,
    pub status: Status,
    pub timestamp: BlockTimestamp,
    pub starknet_version: StarknetVersion,
    pub l1_da_mode: L1DataAvailabilityMode,

    pub transactions: Vec<pathfinder_common::transaction::Transaction>,

    pub transaction_receipts: Vec<(
        pathfinder_common::receipt::Receipt,
        Vec<pathfinder_common::event::Event>,
    )>,
}

type CandidateTransactions = Vec<pathfinder_common::transaction::Transaction>;

#[derive(Clone, Debug, PartialEq)]
pub enum PendingBlockVariant {
    Pending(PendingBlock),
    PreConfirmed(PreConfirmedBlock, CandidateTransactions),
}

impl Default for PendingBlockVariant {
    fn default() -> Self {
        Self::Pending(PendingBlock::default())
    }
}

impl PendingBlockVariant {
    pub fn transactions(&self) -> &[pathfinder_common::transaction::Transaction] {
        match self {
            PendingBlockVariant::Pending(block) => &block.transactions,
            PendingBlockVariant::PreConfirmed(block, _) => &block.transactions,
        }
    }

    pub fn transaction_receipts_and_events(
        &self,
    ) -> &[(
        pathfinder_common::receipt::Receipt,
        Vec<pathfinder_common::event::Event>,
    )] {
        match self {
            PendingBlockVariant::Pending(block) => &block.transaction_receipts,
            PendingBlockVariant::PreConfirmed(block, _) => &block.transaction_receipts,
        }
    }

    pub fn finality_status(&self) -> crate::dto::TxnFinalityStatus {
        match self {
            PendingBlockVariant::Pending(_) => crate::dto::TxnFinalityStatus::AcceptedOnL2,
            PendingBlockVariant::PreConfirmed(_, _) => crate::dto::TxnFinalityStatus::PreConfirmed,
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct PendingData {
    block: Arc<PendingBlockVariant>,
    state_update: Arc<StateUpdate>,
    number: BlockNumber,
}

impl PendingData {
    pub fn from_pending_block(
        block: PendingBlock,
        state_update: StateUpdate,
        number: BlockNumber,
    ) -> Self {
        Self {
            block: Arc::new(PendingBlockVariant::Pending(block)),
            state_update: Arc::new(state_update),
            number,
        }
    }

    /// Converts a pre-confirmed block fetched from the gateway into pending
    /// data.
    ///
    /// Candidate transactions are filtered out and handled separately. State
    /// update is constructed from the per-transaction updates.
    pub fn from_pre_confirmed_block(
        mut block: starknet_gateway_types::reply::PreConfirmedBlock,
        number: BlockNumber,
    ) -> Self {
        // Get rid of Nones in transaction receipt
        let transaction_receipts: Vec<_> =
            block.transaction_receipts.into_iter().flatten().collect();
        let number_of_pre_confirmed_transactions = transaction_receipts.len();
        let candidate_transactions = block
            .transactions
            .split_off(number_of_pre_confirmed_transactions);

        // Compute aggregated state diff.
        let mut state_diff = starknet_gateway_types::reply::state_update::StateDiff::default();
        for transaction_diff in block.transaction_state_diffs.into_iter().flatten() {
            state_diff.extend(transaction_diff);
        }
        state_diff.deduplicate();
        let state_update = starknet_gateway_types::reply::StateUpdate {
            state_diff,
            block_hash: Default::default(),
            new_root: StateCommitment::default(),
            old_root: StateCommitment::default(),
        };
        let state_update = StateUpdate::from(state_update);

        let block = PreConfirmedBlock {
            l1_gas_price: block.l1_gas_price,
            l1_data_gas_price: block.l1_data_gas_price,
            l2_gas_price: block.l2_gas_price,
            sequencer_address: block.sequencer_address,
            status: Status::PreConfirmed,
            timestamp: block.timestamp,
            starknet_version: block.starknet_version,
            l1_da_mode: block.l1_da_mode.into(),
            transactions: block.transactions,
            transaction_receipts,
        };

        Self {
            block: Arc::new(PendingBlockVariant::PreConfirmed(
                block,
                candidate_transactions,
            )),
            state_update: Arc::new(state_update),
            number,
        }
    }

    pub fn block_number(&self) -> BlockNumber {
        self.number
    }

    /// Returns a mutable reference to the block number.
    #[cfg(test)]
    pub fn block_number_mut(&mut self) -> &mut BlockNumber {
        &mut self.number
    }

    pub fn header(&self) -> BlockHeader {
        match self.block.as_ref() {
            PendingBlockVariant::Pending(block) => BlockHeader {
                parent_hash: block.parent_hash,
                number: self.number,
                timestamp: block.timestamp,
                eth_l1_gas_price: block.l1_gas_price.price_in_wei,
                strk_l1_gas_price: block.l1_gas_price.price_in_fri,
                eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
                strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
                eth_l2_gas_price: block.l2_gas_price.price_in_wei,
                strk_l2_gas_price: block.l2_gas_price.price_in_fri,
                sequencer_address: block.sequencer_address,
                starknet_version: block.starknet_version,
                // Pending block does not know what these are yet.
                hash: Default::default(),
                event_commitment: Default::default(),
                state_commitment: Default::default(),
                transaction_commitment: Default::default(),
                transaction_count: Default::default(),
                event_count: Default::default(),
                l1_da_mode: block.l1_da_mode.into(),
                receipt_commitment: Default::default(),
                state_diff_commitment: Default::default(),
                state_diff_length: Default::default(),
            },
            PendingBlockVariant::PreConfirmed(block, _) => BlockHeader {
                parent_hash: pathfinder_common::BlockHash::ZERO, /* Pre-confirmed blocks do not
                                                                  * have a parent hash. */
                number: self.number,
                timestamp: block.timestamp,
                eth_l1_gas_price: block.l1_gas_price.price_in_wei,
                strk_l1_gas_price: block.l1_gas_price.price_in_fri,
                eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
                strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
                eth_l2_gas_price: block.l2_gas_price.price_in_wei,
                strk_l2_gas_price: block.l2_gas_price.price_in_fri,
                sequencer_address: block.sequencer_address,
                starknet_version: block.starknet_version,
                // Pending block does not know what these are yet.
                hash: Default::default(),
                event_commitment: Default::default(),
                state_commitment: Default::default(),
                transaction_commitment: Default::default(),
                transaction_count: Default::default(),
                event_count: Default::default(),
                l1_da_mode: block.l1_da_mode,
                receipt_commitment: Default::default(),
                state_diff_commitment: Default::default(),
                state_diff_length: Default::default(),
            },
        }
    }

    pub fn block(&self) -> Arc<PendingBlockVariant> {
        Arc::clone(&self.block)
    }

    pub fn state_update(&self) -> Arc<StateUpdate> {
        Arc::clone(&self.state_update)
    }

    pub fn transactions(&self) -> &[pathfinder_common::transaction::Transaction] {
        self.block.transactions()
    }

    pub fn transaction_receipts_and_events(
        &self,
    ) -> &[(
        pathfinder_common::receipt::Receipt,
        Vec<pathfinder_common::event::Event>,
    )] {
        self.block.transaction_receipts_and_events()
    }

    pub fn candidate_transactions(&self) -> Option<&CandidateTransactions> {
        match self.block.as_ref() {
            PendingBlockVariant::Pending(_) => None,
            PendingBlockVariant::PreConfirmed(_, candidate_transactions) => {
                Some(candidate_transactions)
            }
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
    /// Returns an empty block with gas price and timestamp taken from the
    /// latest block if no valid pending data is available. The block number
    /// is also incremented.
    pub fn get(&self, tx: &Transaction<'_>) -> anyhow::Result<PendingData> {
        let latest = tx
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block header")?
            .unwrap_or_default();

        let data = self.0.borrow().clone();

        let (pending_data, status) = match data.block().as_ref() {
            PendingBlockVariant::Pending(block) => {
                if block.parent_hash == latest.hash {
                    (Some(data), Status::Pending)
                } else {
                    (None, Status::Pending)
                }
            }
            PendingBlockVariant::PreConfirmed(_, _) => {
                if data.block_number() == latest.number + 1 {
                    (Some(data), Status::PreConfirmed)
                } else {
                    (None, Status::PreConfirmed)
                }
            }
        };

        let pending_data = pending_data.unwrap_or_else(|| PendingData {
            block: PendingBlockVariant::Pending(PendingBlock {
                l1_gas_price: GasPrices {
                    price_in_wei: latest.eth_l1_gas_price,
                    price_in_fri: latest.strk_l1_gas_price,
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: latest.eth_l1_data_gas_price,
                    price_in_fri: latest.strk_l1_data_gas_price,
                },
                l2_gas_price: GasPrices {
                    price_in_wei: latest.eth_l2_gas_price,
                    price_in_fri: latest.strk_l2_gas_price,
                },
                timestamp: latest.timestamp,
                parent_hash: latest.hash,
                starknet_version: latest.starknet_version,
                l1_da_mode: latest.l1_da_mode.into(),
                // This shouldn't have an impact anywhere as the RPC methods should
                // know this is a pending block. But rather safe than sorry.
                status,
                sequencer_address: latest.sequencer_address,
                transaction_receipts: vec![],
                transactions: vec![],
            })
            .into(),
            state_update: StateUpdate::default().into(),
            number: latest.number + 1,
        });

        Ok(pending_data)
    }

    #[cfg(test)]
    pub fn get_unchecked(&self) -> PendingData {
        self.0.borrow().clone()
    }
}

#[cfg(test)]
mod tests {

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHeader, BlockTimestamp, GasPrice, L1DataAvailabilityMode};

    use super::*;

    #[test]
    fn valid_pending() {
        let (sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        let latest = BlockHeader::builder()
            .eth_l1_gas_price(GasPrice(1234))
            .strk_l1_gas_price(GasPrice(3377))
            .timestamp(BlockTimestamp::new_or_panic(6777))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&latest).unwrap();

        let pending = PendingData {
            block: PendingBlockVariant::Pending(PendingBlock {
                parent_hash: latest.hash,
                timestamp: BlockTimestamp::new_or_panic(112233),
                l1_gas_price: GasPrices {
                    price_in_wei: GasPrice(51123),
                    price_in_fri: GasPrice(44411),
                },
                ..Default::default()
            })
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
    fn valid_pre_confirmed() {
        let (sender, receiver) = tokio::sync::watch::channel(Default::default());
        let uut = PendingWatcher::new(receiver);

        let mut storage = pathfinder_storage::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();

        let latest = BlockHeader::builder()
            .eth_l1_gas_price(GasPrice(1234))
            .strk_l1_gas_price(GasPrice(3377))
            .timestamp(BlockTimestamp::new_or_panic(6777))
            .number(BlockNumber::GENESIS)
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&latest).unwrap();

        let pending = PendingData {
            block: PendingBlockVariant::PreConfirmed(
                PreConfirmedBlock {
                    l1_gas_price: Default::default(),
                    l1_data_gas_price: Default::default(),
                    l2_gas_price: Default::default(),
                    sequencer_address: sequencer_address!("0x1234"),
                    status: Status::PreConfirmed,
                    timestamp: BlockTimestamp::new_or_panic(112233),
                    starknet_version: StarknetVersion::new(0, 14, 0, 0),
                    l1_da_mode: L1DataAvailabilityMode::Blob,
                    transactions: vec![],
                    transaction_receipts: vec![],
                },
                vec![],
            )
            .into(),
            state_update: StateUpdate::default()
                .with_contract_nonce(
                    contract_address_bytes!(b"contract address"),
                    contract_nonce_bytes!(b"nonce"),
                )
                .into(),
            number: BlockNumber::GENESIS + 1,
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
            .number(BlockNumber::GENESIS + 12)
            .finalize_with_hash(block_hash_bytes!(b"parent hash"));

        let latest = parent
            .child_builder()
            .eth_l1_gas_price(GasPrice(1234))
            .strk_l1_gas_price(GasPrice(3377))
            .eth_l1_data_gas_price(GasPrice(9999))
            .strk_l1_data_gas_price(GasPrice(8888))
            .l1_da_mode(L1DataAvailabilityMode::Blob)
            .timestamp(BlockTimestamp::new_or_panic(6777))
            .sequencer_address(sequencer_address!("0xffff"))
            .finalize_with_hash(block_hash_bytes!(b"latest hash"));

        let tx = storage.transaction().unwrap();
        tx.insert_block_header(&parent).unwrap();
        tx.insert_block_header(&latest).unwrap();

        let result = uut.get(&tx).unwrap();

        let expected = PendingData {
            block: PendingBlockVariant::Pending(PendingBlock {
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
            })
            .into(),
            state_update: StateUpdate::default().into(),
            number: latest.number + 1,
        };

        pretty_assertions_sorted::assert_eq_sorted!(result, expected);
    }

    #[test]
    fn pre_confirmed_block_state_diff_conversion() {
        let json =
            starknet_gateway_test_fixtures::v0_14_0::preconfirmed_block::SEPOLIA_INTEGRATION_955821;
        let mut pre_confirmed_block: starknet_gateway_types::reply::PreConfirmedBlock =
            serde_json::from_str(json).unwrap();
        let number_of_pre_confirmed_transactions = pre_confirmed_block.transaction_receipts.len();
        let block_number = BlockNumber::new_or_panic(955821);

        // Unfortunately that fixture does not contain a _candidate_ transaction, so
        // just push one on to the end of the list.
        let candidate_transaction = pathfinder_common::transaction::Transaction {
            hash: transaction_hash!(
                "0x352057331d5ad77465315d30b98135ddb815b86aa485d659dfeef59a904f88d"
            ),
            variant: pathfinder_common::transaction::TransactionVariant::InvokeV3(
                pathfinder_common::transaction::InvokeTransactionV3 {
                    ..Default::default()
                },
            ),
        };
        pre_confirmed_block
            .transactions
            .push(candidate_transaction.clone());
        pre_confirmed_block.transaction_receipts.push(None);
        pre_confirmed_block.transaction_state_diffs.push(None);

        // Convert the pre-confirmed block into pending data.
        let pending_data = PendingData::from_pre_confirmed_block(pre_confirmed_block, block_number);

        assert_eq!(pending_data.block_number(), block_number);

        let expected_state_update = StateUpdate::default()
            .with_contract_nonce(
                contract_address!(
                    "0x352057331d5ad77465315d30b98135ddb815b86aa485d659dfeef59a904f88d"
                ),
                contract_nonce!("0x2d10e9"),
            )
            .with_storage_update(
                contract_address!(
                    "0x304d9d15c1c0ddb5824e0bd46cfb665c57a87ca5d5ed85d7f2348c6d29b2235"
                ),
                storage_address!("0x16c"),
                storage_value!("0x1d040cbb8281fe41c0ed888a970ea0747ad85e6740e772eb3c59172a437bbf"),
            )
            .with_storage_update(
                contract_address!(
                    "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
                ),
                storage_address!(
                    "0x3c204dd68b8e800b4f42e438d9ed4ccbba9f8e436518758cd36553715c1d6ab"
                ),
                storage_value!("0x15502e1d8fd6eaa9bb0"),
            )
            .with_storage_update(
                contract_address!(
                    "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
                ),
                storage_address!(
                    "0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"
                ),
                storage_value!("0x1cfaea14e6596648f874"),
            )
            .with_storage_update(
                contract_address!(
                    "0x505110514c6cd158678300c7678fdc63421f04dd2c12e1ce392dd0312f185e5"
                ),
                storage_address!("0x18d"),
                storage_value!("0x3db9b7cb22b4a3bd9f9799ea99decfd5e08ca5541f760992e8a503de253270f"),
            )
            .with_storage_update(
                contract_address!(
                    "0x505110514c6cd158678300c7678fdc63421f04dd2c12e1ce392dd0312f185e5"
                ),
                storage_address!("0x57"),
                storage_value!("0x23280cb06bd32f75b7646bf5dfabf4ab73f525ed8c02cab06888935be2f3abd"),
            );
        pretty_assertions_sorted::assert_eq_sorted!(
            &expected_state_update,
            pending_data.state_update().as_ref()
        );

        // We expect the transaction list to contain pre-confirmed transactions only.
        assert_eq!(
            number_of_pre_confirmed_transactions,
            pending_data.transactions().len()
        );

        // And the single candidate transaction we've added.
        assert_eq!(
            &vec![candidate_transaction],
            pending_data.candidate_transactions().unwrap()
        );
    }
}
