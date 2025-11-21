use fake::Dummy;

use crate::prelude::*;
use crate::{BlockCommitmentSignature, ReceiptCommitment, StateDiffCommitment};

#[derive(Debug, Clone, PartialEq, Eq, Default, Dummy)]
pub struct BlockHeader {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub eth_l1_gas_price: GasPrice,
    pub strk_l1_gas_price: GasPrice,
    pub eth_l1_data_gas_price: GasPrice,
    pub strk_l1_data_gas_price: GasPrice,
    pub eth_l2_gas_price: GasPrice,
    pub strk_l2_gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub event_commitment: EventCommitment,
    pub state_commitment: StateCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: usize,
    pub event_count: usize,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub receipt_commitment: ReceiptCommitment,
    pub state_diff_commitment: StateDiffCommitment,
    pub state_diff_length: u64,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Default, Dummy, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum L1DataAvailabilityMode {
    #[default]
    Calldata,
    Blob,
}

#[derive(Debug, Clone, PartialEq, Default, Dummy)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: BlockCommitmentSignature,
}

pub struct BlockHeaderBuilder(BlockHeader);

impl BlockHeader {
    /// Creates a [builder](BlockHeaderBuilder) with all fields initialized to
    /// default values.
    pub fn builder() -> BlockHeaderBuilder {
        BlockHeaderBuilder(BlockHeader::default())
    }

    /// Creates a [builder](BlockHeaderBuilder) with an incremented block number
    /// and parent hash set to this block's hash.
    pub fn child_builder(&self) -> BlockHeaderBuilder {
        BlockHeaderBuilder(BlockHeader::default())
            .number(self.number + 1)
            .parent_hash(self.hash)
    }

    /// Creates a [StateUpdate] with the block hash and state commitment fields
    /// initialized to match this header.
    pub fn init_state_update(&self) -> StateUpdate {
        StateUpdate::default()
            .with_block_hash(self.hash)
            .with_state_commitment(self.state_commitment)
    }
}

impl BlockHeaderBuilder {
    pub fn number(mut self, number: BlockNumber) -> Self {
        self.0.number = number;
        self
    }

    pub fn parent_hash(mut self, parent_hash: BlockHash) -> Self {
        self.0.parent_hash = parent_hash;
        self
    }

    pub fn state_commitment(mut self, state_commitment: StateCommitment) -> Self {
        self.0.state_commitment = state_commitment;
        self
    }

    /// Sets the [StateCommitment] by calculating its value from the passed
    /// [StorageCommitment] and [ClassCommitment].
    pub fn calculated_state_commitment(
        mut self,
        storage_commitment: StorageCommitment,
        class_commitment: ClassCommitment,
    ) -> Self {
        self.0.state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
        self
    }

    pub fn timestamp(mut self, timestamp: BlockTimestamp) -> Self {
        self.0.timestamp = timestamp;
        self
    }

    pub fn eth_l1_gas_price(mut self, eth_l1_gas_price: GasPrice) -> Self {
        self.0.eth_l1_gas_price = eth_l1_gas_price;
        self
    }

    pub fn strk_l1_gas_price(mut self, strk_l1_gas_price: GasPrice) -> Self {
        self.0.strk_l1_gas_price = strk_l1_gas_price;
        self
    }

    pub fn eth_l2_gas_price(mut self, eth_l2_gas_price: GasPrice) -> Self {
        self.0.eth_l2_gas_price = eth_l2_gas_price;
        self
    }

    pub fn strk_l2_gas_price(mut self, strk_l2_gas_price: GasPrice) -> Self {
        self.0.strk_l2_gas_price = strk_l2_gas_price;
        self
    }

    pub fn eth_l1_data_gas_price(mut self, eth_l1_data_gas_price: GasPrice) -> Self {
        self.0.eth_l1_data_gas_price = eth_l1_data_gas_price;
        self
    }

    pub fn strk_l1_data_gas_price(mut self, strk_l1_data_gas_price: GasPrice) -> Self {
        self.0.strk_l1_data_gas_price = strk_l1_data_gas_price;
        self
    }

    pub fn sequencer_address(mut self, sequencer_address: SequencerAddress) -> Self {
        self.0.sequencer_address = sequencer_address;
        self
    }

    pub fn transaction_commitment(mut self, transaction_commitment: TransactionCommitment) -> Self {
        self.0.transaction_commitment = transaction_commitment;
        self
    }

    pub fn event_commitment(mut self, event_commitment: EventCommitment) -> Self {
        self.0.event_commitment = event_commitment;
        self
    }

    pub fn starknet_version(mut self, starknet_version: StarknetVersion) -> Self {
        self.0.starknet_version = starknet_version;
        self
    }

    pub fn transaction_count(mut self, transaction_count: usize) -> Self {
        self.0.transaction_count = transaction_count;
        self
    }

    pub fn event_count(mut self, event_count: usize) -> Self {
        self.0.event_count = event_count;
        self
    }

    pub fn l1_da_mode(mut self, l1_da_mode: L1DataAvailabilityMode) -> Self {
        self.0.l1_da_mode = l1_da_mode;
        self
    }

    pub fn receipt_commitment(mut self, receipt_commitment: ReceiptCommitment) -> Self {
        self.0.receipt_commitment = receipt_commitment;
        self
    }

    pub fn state_diff_commitment(mut self, state_diff_commitment: StateDiffCommitment) -> Self {
        self.0.state_diff_commitment = state_diff_commitment;
        self
    }

    pub fn state_diff_length(mut self, state_diff_length: u64) -> Self {
        self.0.state_diff_length = state_diff_length;
        self
    }

    pub fn finalize_with_hash(mut self, hash: BlockHash) -> BlockHeader {
        self.0.hash = hash;
        self.0
    }
}
