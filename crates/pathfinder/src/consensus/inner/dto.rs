use pathfinder_storage::{
    DeclareTransactionV4,
    DeployAccountTransactionV4,
    InvokeTransactionV4,
    L1HandlerTransactionV0,
    MinimalFelt,
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
