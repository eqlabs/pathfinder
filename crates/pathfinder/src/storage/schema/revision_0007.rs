use anyhow::Context;
use rusqlite::{named_params, Transaction};

// This is a copy of data structures and their serialization specification as of
// revision 6. We have to keep these intact so that future changes to these types
// do not break database upgrades.
mod transaction {
    use pathfinder_common::{
        CallParam, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
        EthereumAddress, EventData, EventKey, Fee, L1ToL2MessageNonce, L1ToL2MessagePayloadElem,
        L2ToL1MessagePayloadElem, StarknetTransactionHash, StarknetTransactionIndex,
        TransactionSignatureElem,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
        EventDataAsDecimalStr, EventKeyAsDecimalStr, FeeAsHexStr,
        L1ToL2MessagePayloadElemAsDecimalStr, L2ToL1MessagePayloadElemAsDecimalStr,
        TransactionSignatureElemAsDecimalStr,
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
        #[serde_as(as = "Option<FeeAsHexStr>")]
        #[serde(default)]
        pub max_fee: Option<Fee>,
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

const STARKNET_EVENTS_CREATE_STMT: &str = r"CREATE TABLE starknet_events (
        block_number  INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        transaction_hash BLOB NOT NULL,
        from_address BLOB NOT NULL,
        -- Keys are represented as base64 encoded strings separated by space
        keys TEXT,
        data BLOB,
        FOREIGN KEY(block_number) REFERENCES starknet_blocks(number)
        ON DELETE CASCADE
    );

    -- Event filters can specify ranges of blocks
    CREATE INDEX starknet_events_block_number ON starknet_events(block_number);

    -- Event filter can specify a contract address
    CREATE INDEX starknet_events_from_address ON starknet_events(from_address);

    CREATE VIRTUAL TABLE starknet_events_keys
    USING fts5(
        keys,
        content='starknet_events',
        content_rowid='rowid',
        tokenize='ascii'
    );

    CREATE TRIGGER starknet_events_ai
    AFTER INSERT ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;

    CREATE TRIGGER starknet_events_ad
    AFTER DELETE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
    END;

    CREATE TRIGGER starknet_events_au
    AFTER UPDATE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;";

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    migrate_with(transaction, STARKNET_EVENTS_CREATE_STMT)
}

pub(crate) fn migrate_with(
    transaction: &Transaction<'_>,
    starknet_events_create_stmt: &'static str,
) -> anyhow::Result<()> {
    // Create the new events table.
    transaction
        .execute_batch(starknet_events_create_stmt)
        .context("Create starknet events tables and indexes")?;

    // Create an index on starknet_blocks(hash) so that we can look up block numbers based
    // on block hashes quicker.
    transaction
        .execute(
            r"CREATE INDEX starknet_blocks_hash ON starknet_blocks(hash)",
            [],
        )
        .context("Create block hash index")?;

    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_transactions", [], |r| {
            r.get(0)
        })
        .context("Count rows in starknet transactions table")?;

    if todo == 0 {
        return Ok(());
    }

    tracing::info!(
        num_transactions=%todo,
        "Decompressing and migrating events, this may take a while.",
    );

    let mut stmt = transaction
        .prepare("SELECT hash, block_hash, tx, receipt FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut rows = stmt.query([])?;

    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let block_hash = r.get_ref_unwrap("block_hash").as_blob()?;
        let tx = r.get_ref_unwrap("tx").as_blob()?;
        let receipt = r.get_ref_unwrap("receipt").as_blob()?;

        let tx = zstd::decode_all(tx).context("Decompress transaction")?;
        let tx: transaction::Transaction =
            serde_json::from_slice(&tx).context("Deserializing transaction")?;
        let receipt = zstd::decode_all(receipt).context("Decompress receipt")?;
        let receipt: transaction::Receipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;

        receipt.events.into_iter().enumerate().try_for_each(
            |(idx, event)| -> anyhow::Result<_> {
                let block_number: u64 = transaction.query_row("SELECT number FROM starknet_blocks WHERE hash=:block_hash",
                    named_params![
                        ":block_hash": block_hash,
                    ],
                    |row| row.get(0)
                ).context("Query block number based on block hash")?;

                let serialized_data = event_data_to_bytes(&event.data);
                let serialized_keys = event_keys_to_base64_strings(&event.keys);

                transaction.execute(r"INSERT INTO starknet_events ( block_number,  idx,  transaction_hash,  from_address,  keys,  data)
                                                           VALUES (:block_number, :idx, :transaction_hash, :from_address, :keys, :data)",
                    named_params![
                        ":block_number": block_number,
                        ":idx": idx,
                        ":transaction_hash": transaction_hash,
                        ":from_address": tx.contract_address,
                        ":keys": &serialized_keys,
                        ":data": &serialized_data,
                    ]
                ).context("Insert event data into events table")?;

                Ok(())
            },
        )?;
    }

    Ok(())
}

/// Copy of `StarknetEventsTable::event_data_to_bytes` at the time of this migration.
fn event_data_to_bytes(data: &[pathfinder_common::EventData]) -> Vec<u8> {
    data.iter()
        .flat_map(|e| (*e.0.as_be_bytes()).into_iter())
        .collect()
}

/// Copy of `StarknetEventsTable::event_keys_to_base64_strings` at the time of this migration.
fn event_keys_to_base64_strings(keys: &[pathfinder_common::EventKey]) -> String {
    // TODO: we really should be using Iterator::intersperse() here once it's stabilized.
    let keys: Vec<String> = keys
        .iter()
        .map(|key| base64::encode(key.0.as_be_bytes()))
        .collect();
    keys.join(" ")
}
