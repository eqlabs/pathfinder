use pathfinder_storage::{
    DeclareTransactionV4,
    DeployAccountTransactionV4,
    InvokeTransactionV4,
    L1HandlerTransactionV0,
    MinimalFelt,
    TransactionV2,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum ProposalParts {
    V0(Vec<ProposalPart>),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ProposalPart {
    Init(ProposalInit),
    Fin(ProposalFin),
    BlockInfo(BlockInfo),
    TransactionBatch(Vec<TransactionWithClass>),
    TransactionsFin(TransactionsFin),
    ProposalCommitment(Box<ProposalCommitment>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProposalInit {
    pub block_number: u64,
    pub round: u32,
    pub valid_round: Option<u32>,
    pub proposer: MinimalFelt,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockInfo {
    pub block_number: u64,
    pub builder: MinimalFelt,
    pub timestamp: u64,
    pub l2_gas_price_fri: u128,
    pub l1_gas_price_wei: u128,
    pub l1_data_gas_price_wei: u128,
    pub eth_to_strk_rate: u128,
    pub l1_da_mode: u8,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProposalFin {
    pub proposal_commitment: MinimalFelt,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionWithClass {
    pub variant: TransactionVariantWithClass,
    pub hash: MinimalFelt,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionsFin {
    pub executed_transaction_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProposalCommitment {
    pub block_number: u64,
    pub parent_commitment: MinimalFelt,
    pub builder: MinimalFelt,
    pub timestamp: u64,
    pub protocol_version: String,
    pub old_state_root: MinimalFelt,
    pub version_constant_commitment: MinimalFelt,
    pub state_diff_commitment: MinimalFelt,
    pub transaction_commitment: MinimalFelt,
    pub event_commitment: MinimalFelt,
    pub receipt_commitment: MinimalFelt,
    pub concatenated_counts: MinimalFelt,
    pub l1_gas_price_fri: u128,
    pub l1_data_gas_price_fri: u128,
    pub l2_gas_price_fri: u128,
    pub l2_gas_used: u128,
    pub next_l2_gas_price_fri: u128,
    pub l1_da_mode: u8,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransactionVariantWithClass {
    Declare(DeclareTransactionWithClass),
    DeployAccount(DeployAccountTransactionV4),
    Invoke(InvokeTransactionV4),
    L1Handler(L1HandlerTransactionV0),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeclareTransactionWithClass {
    pub declare_transaction: DeclareTransactionV4,
    pub class: Cairo1Class,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cairo1Class {
    pub abi: String,
    pub entry_points: Cairo1EntryPoints,
    pub program: Vec<MinimalFelt>,
    pub contract_class_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cairo1EntryPoints {
    pub externals: Vec<SierraEntryPoint>,
    pub l1_handlers: Vec<SierraEntryPoint>,
    pub constructors: Vec<SierraEntryPoint>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SierraEntryPoint {
    pub index: u64,
    pub selector: MinimalFelt,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PersistentFinalizedBlock {
    V0(FinalizedBlock),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FinalizedBlock {
    pub header: BlockHeader,
    pub state_update: StateUpdateData,
    pub transactions_and_receipts: Vec<(TransactionV2, Receipt)>,
    pub events: Vec<Vec<pathfinder_common::event::Event>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockHeader {
    pub hash: pathfinder_common::BlockHash,
    pub parent_hash: pathfinder_common::BlockHash,
    pub number: pathfinder_common::BlockNumber,
    pub timestamp: pathfinder_common::BlockTimestamp,
    pub eth_l1_gas_price: pathfinder_common::GasPrice,
    pub strk_l1_gas_price: pathfinder_common::GasPrice,
    pub eth_l1_data_gas_price: pathfinder_common::GasPrice,
    pub strk_l1_data_gas_price: pathfinder_common::GasPrice,
    pub eth_l2_gas_price: pathfinder_common::GasPrice,
    pub strk_l2_gas_price: pathfinder_common::GasPrice,
    pub sequencer_address: pathfinder_common::SequencerAddress,
    pub starknet_version: u32,
    pub event_commitment: pathfinder_common::EventCommitment,
    pub state_commitment: pathfinder_common::StateCommitment,
    pub transaction_commitment: pathfinder_common::TransactionCommitment,
    pub transaction_count: u64,
    pub event_count: u64,
    pub receipt_commitment: pathfinder_common::ReceiptCommitment,
    pub state_diff_commitment: pathfinder_common::StateDiffCommitment,
    pub state_diff_length: u64,
    pub l1_da_mode: pathfinder_common::L1DataAvailabilityMode,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StateUpdateData {
    pub contract_updates: LinearMap<pathfinder_common::ContractAddress, ContractUpdate>,
    pub system_contract_updates:
        LinearMap<pathfinder_common::ContractAddress, SystemContractUpdate>,
    pub declared_cairo_classes: Vec<pathfinder_common::ClassHash>,
    pub declared_sierra_classes:
        LinearMap<pathfinder_common::SierraHash, pathfinder_common::CasmHash>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LinearMap<K, V> {
    pub line: Vec<(K, V)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractUpdate {
    pub storage: LinearMap<pathfinder_common::StorageAddress, pathfinder_common::StorageValue>,
    pub class: Option<ContractClassUpdate>,
    pub nonce: Option<pathfinder_common::ContractNonce>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ContractClassUpdate {
    Deploy(pathfinder_common::ClassHash),
    Replace(pathfinder_common::ClassHash),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SystemContractUpdate {
    pub storage: LinearMap<pathfinder_common::StorageAddress, pathfinder_common::StorageValue>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Receipt {
    pub actual_fee: pathfinder_common::Fee,
    pub execution_resources: ExecutionResources,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub execution_status: ExecutionStatus,
    pub transaction_hash: pathfinder_common::TransactionHash,
    pub transaction_index: pathfinder_common::TransactionIndex,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct L2ToL1Message {
    pub from_address: pathfinder_common::ContractAddress,
    pub payload: Vec<pathfinder_common::L2ToL1MessagePayloadElem>,
    pub to_address: pathfinder_common::ContractAddress,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExecutionResources {
    pub builtins: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
    pub data_availability: L1Gas,
    pub total_gas_consumed: L1Gas,
    pub l2_gas: u128,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct L1Gas {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BuiltinCounters {
    pub output: u64,
    pub pedersen: u64,
    pub range_check: u64,
    pub ecdsa: u64,
    pub bitwise: u64,
    pub ec_op: u64,
    pub keccak: u64,
    pub poseidon: u64,
    pub segment_arena: u64,
    pub add_mod: u64,
    pub mul_mod: u64,
    pub range_check96: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ExecutionStatus {
    Succeeded,
    Reverted { reason: String },
}
