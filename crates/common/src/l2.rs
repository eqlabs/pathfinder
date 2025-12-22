use fake::Dummy;

use crate::event::Event;
use crate::receipt::Receipt;
use crate::state_update::StateUpdateData;
use crate::transaction::Transaction;
use crate::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    BlockTimestamp,
    EventCommitment,
    GasPrice,
    L1DataAvailabilityMode,
    ReceiptCommitment,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    TransactionCommitment,
};

pub enum L2BlockToCommit {
    FromConsensus(ConsensusFinalizedL2Block),
    FromFgw(L2Block),
}

#[derive(Clone, Debug, Default)]
pub struct L2Block {
    pub header: BlockHeader,
    pub state_update: StateUpdateData,
    pub transactions_and_receipts: Vec<(Transaction, Receipt)>,
    pub events: Vec<Vec<Event>>,
}

/// An [L2Block] that is the result of executing a consensus proposal. The only
/// differences from an [L2Block] are:
/// - the state tries have not been updated yet,
/// - in consequence the block hash could not have been computed yet.
#[derive(Clone, Debug, Default)]
pub struct ConsensusFinalizedL2Block {
    pub header: ConsensusFinalizedBlockHeader,
    pub state_update: StateUpdateData,
    pub transactions_and_receipts: Vec<(Transaction, Receipt)>,
    pub events: Vec<Vec<Event>>,
}

/// An L2 [BlockHeader] that is the result of executing a consensus proposal
/// that was decided upon. The only differences from a [BlockHeader] are:
/// - the state tries have not been updated yet, so the state commitment is
///   missing,
/// - in consequence the block hash could not have been computed yet,
/// - parent hash is updated when the header is transformed into a full
///   [BlockHeader] to avoid additional DB lookup in consensus.

#[derive(Debug, Clone, Default, PartialEq, Eq, Dummy)]
pub struct ConsensusFinalizedBlockHeader {
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
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: usize,
    pub event_count: usize,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub receipt_commitment: ReceiptCommitment,
    pub state_diff_commitment: StateDiffCommitment,
    pub state_diff_length: u64,
}

impl From<L2Block> for L2BlockToCommit {
    fn from(block: L2Block) -> Self {
        L2BlockToCommit::FromFgw(block)
    }
}

impl From<ConsensusFinalizedL2Block> for L2BlockToCommit {
    fn from(block: ConsensusFinalizedL2Block) -> Self {
        L2BlockToCommit::FromConsensus(block)
    }
}

impl L2BlockToCommit {
    pub fn number(&self) -> BlockNumber {
        match self {
            L2BlockToCommit::FromConsensus(block) => block.header.number,
            L2BlockToCommit::FromFgw(block) => block.header.number,
        }
    }

    pub fn state_commitment(&self) -> Option<StateCommitment> {
        match self {
            L2BlockToCommit::FromConsensus(_) => None,
            L2BlockToCommit::FromFgw(block) => Some(block.header.state_commitment),
        }
    }

    pub fn state_update(&self) -> &StateUpdateData {
        match self {
            L2BlockToCommit::FromConsensus(block) => &block.state_update,
            L2BlockToCommit::FromFgw(block) => &block.state_update,
        }
    }
}

impl ConsensusFinalizedBlockHeader {
    pub fn compute_hash(
        self,
        parent_hash: BlockHash,
        state_commitment: StateCommitment,
        block_hash_fn: impl Fn(&BlockHeader) -> BlockHash,
    ) -> BlockHeader {
        let mut header = BlockHeader {
            // Intentionally set to zero, will be computed later.
            hash: BlockHash::ZERO,
            parent_hash,
            number: self.number,
            timestamp: self.timestamp,
            eth_l1_gas_price: self.eth_l1_gas_price,
            strk_l1_gas_price: self.strk_l1_gas_price,
            eth_l1_data_gas_price: self.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.strk_l1_data_gas_price,
            eth_l2_gas_price: self.eth_l2_gas_price,
            strk_l2_gas_price: self.strk_l2_gas_price,
            sequencer_address: self.sequencer_address,
            starknet_version: self.starknet_version,
            event_commitment: self.event_commitment,
            state_commitment,
            transaction_commitment: self.transaction_commitment,
            transaction_count: self.transaction_count,
            event_count: self.event_count,
            l1_da_mode: self.l1_da_mode,
            receipt_commitment: self.receipt_commitment,
            state_diff_commitment: self.state_diff_commitment,
            state_diff_length: self.state_diff_length,
        };
        header.hash = block_hash_fn(&header);
        header
    }
}
