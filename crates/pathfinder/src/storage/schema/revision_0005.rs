use anyhow::Context;
use rusqlite::{named_params, Transaction};
use tracing::info;

// This is a copy of data structures and their serialization specification as of
// revision 4. We have to keep these intact so that future changes to these types
// do not break database upgrades.
mod transaction {
    use pathfinder_common::{
        CallParam, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
        EthereumAddress, EventData, EventKey, L1ToL2MessageNonce, L1ToL2MessagePayloadElem,
        L2ToL1MessagePayloadElem, StarknetTransactionHash, StarknetTransactionIndex,
        TransactionSignatureElem,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
        EventDataAsDecimalStr, EventKeyAsDecimalStr, L1ToL2MessagePayloadElemAsDecimalStr,
        L2ToL1MessagePayloadElemAsDecimalStr, TransactionSignatureElemAsDecimalStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResources {
        pub builtin_instance_counter: execution_resources::BuiltinInstanceCounter,
        pub n_steps: u64,
        pub n_memory_holes: u64,
    }

    /// Types used when deserializing L2 execution resources related data.
    pub mod execution_resources {
        use serde::{Deserialize, Serialize};

        /// Sometimes `builtin_instance_counter` JSON object is returned empty.
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(untagged)]
        #[serde(deny_unknown_fields)]
        pub enum BuiltinInstanceCounter {
            Normal(NormalBuiltinInstanceCounter),
            Empty(EmptyBuiltinInstanceCounter),
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub struct NormalBuiltinInstanceCounter {
            bitwise_builtin: u64,
            ecdsa_builtin: u64,
            ec_op_builtin: u64,
            output_builtin: u64,
            pedersen_builtin: u64,
            range_check_builtin: u64,
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        pub struct EmptyBuiltinInstanceCounter {}
    }

    /// Represents deserialized L1 to L2 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1ToL2Message {
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub from_address: EthereumAddress,
        #[serde_as(as = "Vec<L1ToL2MessagePayloadElemAsDecimalStr>")]
        pub payload: Vec<L1ToL2MessagePayloadElem>,
        pub selector: EntryPoint,
        pub to_address: ContractAddress,
        #[serde(default)]
        pub nonce: Option<L1ToL2MessageNonce>,
    }

    /// Represents deserialized L2 to L1 message.
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

    /// Represents deserialized L2 transaction receipt data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        pub events: Vec<Event>,
        pub execution_resources: ExecutionResources,
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub transaction_hash: StarknetTransactionHash,
        pub transaction_index: StarknetTransactionIndex,
    }

    /// Represents deserialized L2 transaction event data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
        pub data: Vec<EventData>,
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
        pub keys: Vec<EventKey>,
    }

    /// Represents deserialized object containing L2 contract address and transaction type.
    #[serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        pub contract_address: ContractAddress,
        pub r#type: Type,
    }

    /// Represents deserialized L2 transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Transaction {
        #[serde_as(as = "Option<Vec<CallParamAsDecimalStr>>")]
        #[serde(default)]
        pub calldata: Option<Vec<CallParam>>,
        #[serde_as(as = "Option<Vec<ConstructorParamAsDecimalStr>>")]
        #[serde(default)]
        pub constructor_calldata: Option<Vec<ConstructorParam>>,
        pub contract_address: ContractAddress,
        #[serde(default)]
        pub contract_address_salt: Option<ContractAddressSalt>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        pub entry_point_selector: Option<EntryPoint>,
        #[serde_as(as = "Option<Vec<TransactionSignatureElemAsDecimalStr>>")]
        #[serde(default)]
        pub signature: Option<Vec<TransactionSignatureElem>>,
        pub transaction_hash: StarknetTransactionHash,
        pub r#type: Type,
    }

    /// Describes L2 transaction types.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum Type {
        #[serde(rename = "DEPLOY")]
        Deploy,
        #[serde(rename = "INVOKE_FUNCTION")]
        InvokeFunction,
    }

    /// Describes L2 transaction failure details.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
        pub tx_id: u64,
    }
}

/// This schema migration moves the Starknet transactions and transaction receipts into
/// their own table. These tables are indexed by the origin Starknet block hash.
///
/// This migration has a non-fatal bug where it fails to drop the columns if the table is empty.
/// This bug is fixed in [schema revision 6](super::revision_0006::migrate).
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // Create the new transaction and transaction receipt tables.
    transaction
        .execute(
            r"CREATE TABLE starknet_transactions (
            hash        BLOB PRIMARY KEY,
            idx         INTEGER NOT NULL,
            block_hash  BLOB NOT NULL,
            tx          BLOB,
            receipt     BLOB
        )",
            [],
        )
        .context("Create starknet transactions table")?;

    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_blocks", [], |r| r.get(0))
        .context("Count rows in starknet blocks table")?;

    // Only perform data migration if there is actual data.
    if todo > 0 {
        info!(
            "Decompressing and migrating {} blocks of transaction data, this may take a while.",
            todo
        );

        let mut stmt = transaction
            .prepare("SELECT hash, transactions, transaction_receipts FROM starknet_blocks")
            .context("Prepare statement")?;
        let mut rows = stmt.query([])?;

        let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

        while let Some(r) = rows.next()? {
            let block_hash = r.get_ref_unwrap("hash").as_blob()?;
            let transactions = r.get_ref_unwrap("transactions").as_blob()?;
            let receipts = r.get_ref_unwrap("transaction_receipts").as_blob()?;

            let transactions =
                zstd::decode_all(transactions).context("Decompressing transactions")?;
            let transactions =
                serde_json::from_slice::<Vec<transaction::Transaction>>(&transactions)
                    .context("Deserializing transactions")?;

            let receipts = zstd::decode_all(receipts).context("Decompressing transactions")?;
            let receipts = serde_json::from_slice::<Vec<transaction::Receipt>>(&receipts)
                .context("Deserializing transaction receipts")?;

            anyhow::ensure!(
                transactions.len() == receipts.len(),
                "Mismatched number of transactions and receipts"
            );

            transactions
                .into_iter()
                .zip(receipts.into_iter())
                .enumerate()
                .try_for_each(|(idx, (tx, rx))| -> anyhow::Result<_> {
                    let transaction_data = serde_json::ser::to_vec(&tx).context("Serializing transaction data")?;
                    let transaction_data = compressor.compress(&transaction_data).context("Compressing transaction data")?;

                    let receipt_data = serde_json::ser::to_vec(&rx).context("Serializing transaction receipt data")?;
                    let receipt_data = compressor.compress(&receipt_data).context("Compressing transaction receipt data")?;

                    transaction.execute(r"INSERT INTO starknet_transactions ( hash,  idx,  block_hash,  tx,  receipt)
                                                                         VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
            named_params![
                        ":hash": &tx.transaction_hash.0.as_be_bytes()[..],
                        ":idx": idx,
                        ":block_hash": block_hash,
                        ":tx": &transaction_data,
                        ":receipt": &receipt_data,
                    ]).context("Insert transaction data into transactions table")?;

                    Ok(())
                })?;
        }
    }

    // Remove transaction columns from blocks table.
    transaction
        .execute("ALTER TABLE starknet_blocks DROP COLUMN transactions", [])
        .context("Dropping transactions from starknet_blocks table")?;

    transaction
        .execute(
            "ALTER TABLE starknet_blocks DROP COLUMN transaction_receipts",
            [],
        )
        .context("Dropping transaction receipts from starknet_blocks table")?;

    Ok(())
}
