use anyhow::Context;
use fake::Dummy;
use libp2p::PeerId;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::{ExecutionResources, ExecutionStatus, L2ToL1Message};
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::{
    BlockCommitmentSignature,
    BlockCommitmentSignatureElem,
    BlockHash,
    BlockNumber,
    BlockTimestamp,
    ClassCommitment,
    EventCommitment,
    Fee,
    GasPrice,
    L1DataAvailabilityMode,
    ReceiptCommitment,
    SequencerAddress,
    StarknetVersion,
    StateCommitment,
    StateDiffCommitment,
    StorageCommitment,
    TransactionCommitment,
    TransactionHash,
    TransactionIndex,
};
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;

use crate::client::conv::TryFromDto;

#[derive(Clone, PartialEq, Dummy, TaggedDebug)]
pub enum ClassDefinition {
    Cairo {
        block_number: BlockNumber,
        definition: Vec<u8>,
    },
    Sierra {
        block_number: BlockNumber,
        sierra_definition: Vec<u8>,
    },
}

impl ClassDefinition {
    /// Return Cairo or Sierra class definition depending on the variant.
    pub fn class_definition(&self) -> Vec<u8> {
        match self {
            Self::Cairo { definition, .. } => definition.clone(),
            Self::Sierra {
                sierra_definition, ..
            } => sierra_definition.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Dummy)]
pub struct Receipt {
    pub actual_fee: Fee,
    pub execution_resources: ExecutionResources,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_index: TransactionIndex,
}

impl From<pathfinder_common::receipt::Receipt> for Receipt {
    fn from(receipt: pathfinder_common::receipt::Receipt) -> Self {
        Self {
            actual_fee: receipt.actual_fee,
            execution_resources: receipt.execution_resources,
            l2_to_l1_messages: receipt.l2_to_l1_messages,
            execution_status: receipt.execution_status,
            transaction_index: receipt.transaction_index,
        }
    }
}

/// For a single block
#[derive(Clone, Debug, PartialEq)]
pub struct UnverifiedTransactionData {
    pub expected_commitment: TransactionCommitment,
    pub transactions: Vec<(TransactionVariant, Receipt)>,
}

pub type UnverifiedTransactionDataWithBlockNumber = (UnverifiedTransactionData, BlockNumber);

/// For a single block
#[derive(Clone, PartialEq, Dummy, TaggedDebug)]
pub struct UnverifiedStateUpdateData {
    pub expected_commitment: StateDiffCommitment,
    pub state_diff: StateUpdateData,
}

pub type UnverifiedStateUpdateWithBlockNumber = (UnverifiedStateUpdateData, BlockNumber);

pub type EventsForBlockByTransaction = (BlockNumber, Vec<(TransactionHash, Vec<Event>)>);

// TODO make it a variant of the core type
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
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub event_commitment: EventCommitment,
    pub state_commitment: StateCommitment,
    pub transaction_commitment: TransactionCommitment,
    pub transaction_count: usize,
    pub event_count: usize,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub receipt_commitment: ReceiptCommitment,
}

// TODO make it a variant of the core type
#[derive(Clone, PartialEq, Default, TaggedDebug, Dummy)]
pub struct SignedBlockHeader {
    pub header: BlockHeader,
    pub signature: BlockCommitmentSignature,
    pub state_diff_commitment: StateDiffCommitment,
    pub state_diff_length: u64,
}

impl SignedBlockHeader {
    pub fn finalize(
        self,
        storage_commitment: StorageCommitment,
        class_commitment: ClassCommitment,
    ) -> pathfinder_common::SignedBlockHeader {
        pathfinder_common::SignedBlockHeader {
            header: self.header.finalize(storage_commitment, class_commitment),
            signature: self.signature,
            state_diff_commitment: self.state_diff_commitment,
            state_diff_length: self.state_diff_length,
        }
    }
}

impl From<pathfinder_common::SignedBlockHeader> for SignedBlockHeader {
    fn from(h: pathfinder_common::SignedBlockHeader) -> Self {
        Self {
            header: h.header.into(),
            signature: h.signature,
            state_diff_commitment: h.state_diff_commitment,
            state_diff_length: h.state_diff_length,
        }
    }
}

impl BlockHeader {
    pub fn finalize(
        self,
        storage_commitment: StorageCommitment,
        class_commitment: ClassCommitment,
    ) -> pathfinder_common::BlockHeader {
        pathfinder_common::BlockHeader {
            hash: self.hash,
            parent_hash: self.parent_hash,
            number: self.number,
            timestamp: self.timestamp,
            eth_l1_gas_price: self.eth_l1_gas_price,
            strk_l1_gas_price: self.strk_l1_gas_price,
            eth_l1_data_gas_price: self.eth_l1_data_gas_price,
            strk_l1_data_gas_price: self.strk_l1_data_gas_price,
            sequencer_address: self.sequencer_address,
            starknet_version: self.starknet_version,
            event_commitment: self.event_commitment,
            state_commitment: self.state_commitment,
            transaction_commitment: self.transaction_commitment,
            transaction_count: self.transaction_count,
            event_count: self.event_count,
            l1_da_mode: self.l1_da_mode,
            receipt_commitment: self.receipt_commitment,
            storage_commitment,
            class_commitment,
        }
    }
}

impl From<pathfinder_common::BlockHeader> for BlockHeader {
    fn from(h: pathfinder_common::BlockHeader) -> Self {
        Self {
            hash: h.hash,
            parent_hash: h.parent_hash,
            number: h.number,
            timestamp: h.timestamp,
            eth_l1_gas_price: h.eth_l1_gas_price,
            strk_l1_gas_price: h.strk_l1_gas_price,
            eth_l1_data_gas_price: h.eth_l1_data_gas_price,
            strk_l1_data_gas_price: h.strk_l1_data_gas_price,
            sequencer_address: h.sequencer_address,
            starknet_version: h.starknet_version,
            event_commitment: h.event_commitment,
            state_commitment: h.state_commitment,
            transaction_commitment: h.transaction_commitment,
            transaction_count: h.transaction_count,
            event_count: h.event_count,
            l1_da_mode: h.l1_da_mode,
            receipt_commitment: h.receipt_commitment,
        }
    }
}

impl TryFrom<p2p_proto::header::SignedBlockHeader> for SignedBlockHeader {
    type Error = anyhow::Error;

    fn try_from(dto: p2p_proto::header::SignedBlockHeader) -> anyhow::Result<Self> {
        anyhow::ensure!(dto.signatures.len() == 1, "expected exactly one signature");
        let signature = dto
            .signatures
            .into_iter()
            .map(|sig| BlockCommitmentSignature {
                r: BlockCommitmentSignatureElem(sig.r),
                s: BlockCommitmentSignatureElem(sig.s),
            })
            .next()
            .expect("exactly one element");
        Ok(SignedBlockHeader {
            header: BlockHeader {
                hash: BlockHash(dto.block_hash.0),
                parent_hash: BlockHash(dto.parent_hash.0),
                number: BlockNumber::new(dto.number).context("block number > i64::MAX")?,
                timestamp: BlockTimestamp::new(dto.time).context("block timestamp > i64::MAX")?,
                eth_l1_gas_price: GasPrice(dto.gas_price_wei),
                strk_l1_gas_price: GasPrice(dto.gas_price_fri),
                eth_l1_data_gas_price: GasPrice(dto.data_gas_price_wei),
                strk_l1_data_gas_price: GasPrice(dto.data_gas_price_fri),
                sequencer_address: SequencerAddress(dto.sequencer_address.0),
                starknet_version: dto.protocol_version.parse()?,
                event_commitment: EventCommitment(dto.events.root.0),
                state_commitment: StateCommitment(dto.state_root.0),
                transaction_commitment: TransactionCommitment(dto.transactions.root.0),
                transaction_count: dto.transactions.n_leaves.try_into()?,
                event_count: dto.events.n_leaves.try_into()?,
                receipt_commitment: ReceiptCommitment(dto.receipts.0),
                l1_da_mode: TryFromDto::try_from_dto(dto.l1_data_availability_mode)?,
            },
            signature,
            state_diff_commitment: StateDiffCommitment(dto.state_diff_commitment.root.0),
            state_diff_length: dto.state_diff_commitment.state_diff_length,
        })
    }
}

#[derive(Debug)]
pub struct IncorrectStateDiffCount(pub PeerId);

impl std::fmt::Display for IncorrectStateDiffCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Incorrect state diff count from peer {}", self.0)
    }
}

#[derive(Debug)]
pub enum ClassDefinitionsError {
    IncorrectClassDefinitionCount(PeerId),
    CairoDefinitionError(PeerId),
    SierraDefinitionError(PeerId),
}

impl std::fmt::Display for ClassDefinitionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassDefinitionsError::IncorrectClassDefinitionCount(peer) => {
                write!(f, "Incorrect class definition count from peer {}", peer)
            }
            ClassDefinitionsError::CairoDefinitionError(peer) => {
                write!(f, "Cairo class definition error from peer {}", peer)
            }
            ClassDefinitionsError::SierraDefinitionError(peer) => {
                write!(f, "Sierra class definition error from peer {}", peer)
            }
        }
    }
}
