use anyhow::Context;
use pathfinder_common::{
    ContractAddress, EthereumAddress, Fee, L2ToL1MessagePayloadElem, TransactionHash,
    TransactionIndex,
};
use pathfinder_serde::{EthereumAddressAsHexStr, L2ToL1MessagePayloadElemAsDecimalStr};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDto {
    #[serde(default)]
    pub actual_fee: Option<Fee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<pathfinder_common::event::Event>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_resources: Option<ExecutionResources>,
    // This field exists in our database but is unused within our code.
    // It is redundant data that is also contained in the L1 handler.
    pub l1_to_l2_consumed_message: Option<serde_json::Value>,
    pub l2_to_l1_messages: Vec<L2ToL1Message>,
    pub transaction_hash: TransactionHash,
    pub transaction_index: TransactionIndex,
    // Introduced in v0.12.1
    #[serde(default)]
    pub execution_status: ExecutionStatus,
    // Introduced in v0.12.1
    /// Only present if status is [ExecutionStatus::Reverted].
    #[serde(default)]
    pub revert_error: Option<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L2ToL1Message {
    pub from_address: ContractAddress,
    #[serde_as(as = "Vec<L2ToL1MessagePayloadElemAsDecimalStr>")]
    pub payload: Vec<L2ToL1MessagePayloadElem>,
    #[serde_as(as = "EthereumAddressAsHexStr")]
    pub to_address: EthereumAddress,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResources {
    pub builtin_instance_counter: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
    // TODO make these mandatory once some new release makes resyncing necessary
    pub l1_gas: Option<u128>,
    pub l1_data_gas: Option<u128>,
}

#[derive(Copy, Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct BuiltinCounters {
    pub output_builtin: u64,
    pub pedersen_builtin: u64,
    pub range_check_builtin: u64,
    pub ecdsa_builtin: u64,
    pub bitwise_builtin: u64,
    pub ec_op_builtin: u64,
    pub keccak_builtin: u64,
    pub poseidon_builtin: u64,
    pub segment_arena_builtin: u64,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    // This must be the default as pre v0.12.1 receipts did not contain this value and
    // were always success as reverted did not exist.
    #[default]
    Succeeded,
    Reverted,
}

/// NOTE: DO NOT RUN THIS IN PROD.
/// TODO: Update this to use bincode serialization instead of serde_json. (Follow-up PR)
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"
CREATE TABLE starknet_events (
    transaction_hash BLOB NOT NULL REFERENCES starknet_transactions(hash) ON DELETE CASCADE,
    events BLOB NOT NULL
)
",
        [],
    )
    .context("Creating starknet_events table")?;
    let mut stmt = tx.prepare("SELECT hash, receipt FROM starknet_transactions")?;
    let mut rows = stmt.query([])?;
    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
    while let Some(row) = rows.next()? {
        let hash = row.get_ref_unwrap(0).as_blob()?;
        let receipt = row.get_ref_unwrap(1).as_blob()?;
        let receipt = zstd::decode_all(receipt).context("Decompressing receipt")?;
        let mut receipt: ReceiptDto =
            serde_json::from_slice(&receipt).context("Deserializing receipt")?;
        let events =
            serde_json::to_vec(&receipt.events.as_ref().unwrap()).context("Serializing events")?;
        let events = compressor.compress(&events).context("Compressing events")?;
        tx.execute(
            "INSERT INTO starknet_events (transaction_hash, events) VALUES (?, ?)",
            params![hash, events],
        )?;
        receipt.events = None;
        let receipt = serde_json::to_vec(&receipt).context("Serializing receipt")?;
        let receipt = compressor
            .compress(&receipt)
            .context("Compressing receipt")?;
        tx.execute(
            "UPDATE starknet_transactions SET receipt = ? WHERE hash = ?",
            params![receipt, hash],
        )?;
    }
    Ok(())
}
