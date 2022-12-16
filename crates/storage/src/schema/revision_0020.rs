use crate::{StarknetBlocksTable, StarknetEventsTable};
use anyhow::Context;
use pathfinder_common::{
    felt, ContractAddress, EventData, EventKey, StarknetBlockNumber, StarknetTransactionHash,
};
use rusqlite::named_params;
use stark_hash::Felt;

/// Removes bogus transfer events from the affected block range on Starknet Testnet.
///
/// After deploying Starknet 0.10.0 to Testnet there was a period where the sequencer
/// was returning blocks with extra "transfer" events added. These were not originally
/// part of these blocks while on Starknet 0.9.1, so the event commitment used to
/// calculate the block hash didn't have these.
///
/// This caused block hash mismatches for these affected blocks. Pathfinder databases
/// might contain these extra events for blocks that were synced during this period.
///
/// This migration removes these bogus events from blocks in the affected range.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    match StarknetBlocksTable::get_chain(tx)? {
        Some(chain) => chain,
        None => return Ok(()),
    };

    let mut number_of_affected_transactions = tx.prepare(
        r#"SELECT count(DISTINCT transaction_hash)
        FROM starknet_events
        INNER JOIN starknet_events_keys ON starknet_events.rowid = starknet_events_keys.rowid
        WHERE
            block_number BETWEEN :first_block AND :last_block AND
            from_address=:from_address AND
            starknet_events_keys.keys MATCH '"AJnNi95VeBSEKjEh6N39QzpTm4yfFL8x6/EI0S5hluk="' AND
            substr(hex(data), 65, 64) = '046A89AE102987331D369645031B49C27738ED096F2789C24449966DA4C6DE6B'"#
    ).context("Preparing query for number of potentially affected transactions")?;

    let mut affected_transactions = tx.prepare(
        r#"SELECT block_number, transaction_hash
        FROM starknet_events
        INNER JOIN starknet_events_keys ON starknet_events.rowid = starknet_events_keys.rowid
        WHERE
            block_number BETWEEN :first_block AND :last_block AND
            from_address=:from_address AND
            starknet_events_keys.keys MATCH '"AJnNi95VeBSEKjEh6N39QzpTm4yfFL8x6/EI0S5hluk="' AND
            substr(hex(data), 65, 64) = '046A89AE102987331D369645031B49C27738ED096F2789C24449966DA4C6DE6B'
        GROUP BY transaction_hash"#
    ).context("Preparing query of potentially affected transactions")?;

    tracing::info!("Checking if there are potential bogus transfer events");

    let count: usize = number_of_affected_transactions.query_row(
        named_params! {
            ":first_block": FIRST_BLOCK,
            ":last_block": LAST_BLOCK,
            ":from_address": FROM_ADDRESS,
        },
        |row| row.get(0),
    )?;
    if count == 0 {
        // WARNING: _no_ changes should be made to the database prior to this point
        return Ok(());
    }
    tracing::info!(%count, "Removing bogus transfer events from transactions");

    tracing::info!("Creating helper index for migration");
    tx.execute(
        "CREATE INDEX starknet_events_transaction_hash ON starknet_events(transaction_hash)",
        [],
    )
    .context("Creating 'starknet_events_transaction_hash' index")?;

    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

    let mut rows = affected_transactions.query(named_params! {
        ":first_block": FIRST_BLOCK,
        ":last_block": LAST_BLOCK,
        ":from_address": FROM_ADDRESS,
    })?;

    let mut idx = 0;
    let t_begin = std::time::Instant::now();
    let mut t_log = t_begin;
    while let Some(row) = rows.next().context("Fetching next transaction hash")? {
        let block_number: StarknetBlockNumber = row.get_unwrap("block_number");
        let transaction_hash: StarknetTransactionHash = row.get_unwrap("transaction_hash");

        process_transaction(tx, &mut compressor, &transaction_hash, block_number)?;

        idx += 1;

        if idx % 100 == 0 && t_log.elapsed() > std::time::Duration::from_secs(10) {
            t_log = std::time::Instant::now();

            let t_tot = t_begin.elapsed();
            let t_avg = t_tot / idx;
            let t_rem = t_avg * (count as u32 - idx);

            tracing::info!(%idx, %count, complete=idx*100/(count as u32), eta=?t_rem, "Migration status");
        }
    }

    tracing::info!("Dropping helper index for migration");
    tx.execute("DROP INDEX starknet_events_transaction_hash", [])
        .context("Dropping 'starknet_events_transaction_hash'")?;

    Ok(())
}

/// Processes events in a transaction.
///
/// Fetches both the transaction and the receipt from the database, then removes
/// transfer events. Updates the database if events have changed.
fn process_transaction(
    tx: &rusqlite::Transaction<'_>,
    compressor: &mut zstd::bulk::Compressor<'_>,
    transaction_hash: &StarknetTransactionHash,
    block_number: StarknetBlockNumber,
) -> anyhow::Result<()> {
    let mut get_transaction_and_receipt = tx
        .prepare_cached(
            r"SELECT tx, receipt
            FROM starknet_transactions
            WHERE
                hash=:transaction_hash
            ",
        )
        .context("Preparing query of transaction data")?;
    let mut tx_rows = get_transaction_and_receipt
        .query(named_params! {
            ":transaction_hash": transaction_hash
        })
        .context("Querying transaction and receipt")?;
    let tx_row = tx_rows
        .next()?
        .ok_or_else(|| anyhow::anyhow!("Transaction not found"))?;

    let transaction = tx_row.get_ref_unwrap("tx").as_blob()?;
    let receipt = tx_row.get_ref_unwrap("receipt").as_blob()?;

    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;

    let transaction: types::Transaction =
        serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    let receipt = zstd::decode_all(receipt).context("Decompressing receipt")?;

    let mut receipt: types::Receipt =
        serde_json::from_slice(&receipt).context("Deserializing receipt")?;

    let num_events = receipt.events.len();
    let contract_address = *transaction.contract_address().get();

    // remove transfer events
    receipt
        .events
        .retain(|e| !is_transfer_event(contract_address, e));

    if num_events != receipt.events.len() {
        update_database(tx, compressor, transaction_hash, block_number, receipt)?;
    }

    Ok(())
}

// First Starknet 0.9.0 block on Testnet -- this is the first block known to have extra
// events on Starknet Testnet.
const FIRST_BLOCK: u64 = 226000;
// Last Starknet 0.9.1 block on Testnet -- this is the last block to have bogus events.
const LAST_BLOCK: u64 = 322548;

// Keccak mod 2**251 of the string Transfer
const TRANSFER_KEY: Felt =
    felt!("0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9");

// Address of ETH ERC20
const FROM_ADDRESS: ContractAddress = ContractAddress::new_or_panic(felt!(
    "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
));

// Sequencer address on Goerli
const GOERLI_SEQUENCER_ADDRESS: EventData = EventData(felt!(
    "046a89ae102987331d369645031b49c27738ed096f2789c24449966da4c6de6b"
));

/// Matches bogus transfer events.
///
/// According to Starkware these events all are from a well-known contract with a well-known key,
/// and the event data is also expected to start with the contract address of the transaction
/// and contain the well-known Goerli sequencer address.
fn is_transfer_event(contract_address: Felt, e: &types::Event) -> bool {
    e.from_address == FROM_ADDRESS
        && e.keys.contains(&EventKey(TRANSFER_KEY))
        && e.data
            .starts_with(&[EventData(contract_address), GOERLI_SEQUENCER_ADDRESS])
}

/// Updates a single receipt (along with all events) in the database.
///
/// Serializes the receipt into JSON and updates it in starknet_transactions.
/// All events for the given transaction are first removed, and then re-inserted.
fn update_database(
    tx: &rusqlite::Transaction<'_>,
    compressor: &mut zstd::bulk::Compressor<'_>,
    transaction_hash: &StarknetTransactionHash,
    block_number: StarknetBlockNumber,
    receipt: types::Receipt,
) -> anyhow::Result<()> {
    let mut delete_events =
        tx.prepare_cached("DELETE FROM starknet_events WHERE transaction_hash=?")?;
    let mut update_receipt = tx
        .prepare_cached(
            r"UPDATE starknet_transactions
            SET receipt=:receipt
            WHERE
                hash=:transaction_hash
            ",
        )
        .context("Preparing query for transaction receipt updates")?;
    let mut insert_events = tx.prepare_cached(
            r"INSERT INTO starknet_events (block_number, idx, transaction_hash, from_address, keys, data)
                VALUES (:block_number, :idx, :transaction_hash, :from_address, :keys, :data)")
            .context("Preparing query for event insertion")?;

    tracing::trace!(
        ?block_number,
        ?transaction_hash,
        "Updating modified transaction receipt"
    );

    let serialized_receipt =
        serde_json::ser::to_vec(&receipt).context("Serialize Starknet transaction receipt")?;
    let serialized_receipt = compressor
        .compress(&serialized_receipt)
        .context("Compress Starknet transaction receipt")?;

    delete_events.execute([transaction_hash])?;
    update_receipt.execute(named_params! {
        ":transaction_hash": transaction_hash,
        ":receipt": serialized_receipt,
    })?;

    let mut keys = String::new();
    let mut data_buffer = Vec::new();
    for (idx, event) in receipt.events.iter().enumerate() {
        keys.clear();
        StarknetEventsTable::event_keys_to_base64_strings(&event.keys, &mut keys);

        data_buffer.clear();
        StarknetEventsTable::encode_event_data_to_bytes(&event.data, &mut data_buffer);

        insert_events
            .execute(named_params! {
                ":block_number": block_number,
                ":idx": idx,
                ":transaction_hash": transaction_hash,
                ":from_address": event.from_address,
                ":keys": &keys,
                ":data": &data_buffer,
            })
            .context("Insert events into events table")?;
    }

    Ok(())
}

/// These are the copies of data structures used for de/serialization of receipt JSONs
/// in the database. We copy these here so that further modifications don't break this
/// migration.
mod types {
    use pathfinder_common::{
        CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
        EthereumAddress, EventData, EventKey, Fee, L1ToL2MessageNonce, L1ToL2MessagePayloadElem,
        L2ToL1MessagePayloadElem, StarknetTransactionHash, StarknetTransactionIndex,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
        EventDataAsDecimalStr, EventKeyAsDecimalStr, FeeAsHexStr,
        L1ToL2MessagePayloadElemAsDecimalStr, L2ToL1MessagePayloadElemAsDecimalStr,
        TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// Represents deserialized L2 transaction receipt data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde_as(as = "Option<FeeAsHexStr>")]
        #[serde(default)]
        pub actual_fee: Option<Fee>,
        pub events: Vec<Event>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execution_resources: Option<ExecutionResources>,
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

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransaction),
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    impl Transaction {
        pub fn contract_address(&self) -> ContractAddress {
            match self {
                Transaction::Declare(t) => t.sender_address,
                Transaction::Deploy(t) => t.contract_address,
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.contract_address,
                    InvokeTransaction::V1(t) => t.contract_address,
                },
                Transaction::L1Handler(t) => t.contract_address,
            }
        }
    }

    /// Represents deserialized L2 declare transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransaction {
        pub class_hash: ClassHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    fn transaction_version_zero() -> TransactionVersion {
        TransactionVersion(ethers::types::H256::zero())
    }

    /// Represents deserialized L2 deploy transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransaction {
        pub contract_address: ContractAddress,
        pub contract_address_salt: ContractAddressSalt,
        pub class_hash: ClassHash,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(tag = "version")]
    pub enum InvokeTransaction {
        #[serde(rename = "0x0")]
        V0(InvokeTransactionV0),
        #[serde(rename = "0x1")]
        V1(InvokeTransactionV1),
    }

    impl<'de> Deserialize<'de> for InvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use ethers::types::H256;
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default = "transaction_version_zero")]
                pub version: TransactionVersion,
            }

            let mut v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            // remove "version", since v0 and v1 transactions use deny_unknown_fields
            v.as_object_mut()
                .expect("must be an object because deserializing version succeeded")
                .remove("version");
            match version.version {
                TransactionVersion(x) if x == H256::from_low_u64_be(0) => Ok(Self::V0(
                    InvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion(x) if x == H256::from_low_u64_be(1) => {
                    // Starknet 0.10.0 still has `entry_point_selector` and `entry_point_type` because
                    // of a bug that will be fixed in 0.10.1. We should just ignore these fields until
                    // this gets fixed.
                    let o = v
                        .as_object_mut()
                        .expect("must be an object because deserializing version succeeded");
                    o.remove("entry_point_selector");
                    o.remove("entry_point_type");
                    Ok(Self::V1(
                        InvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                    ))
                }
                _v => Err(de::Error::custom("version must be 0 or 1")),
            }
        }
    }

    /// Represents deserialized L2 invoke transaction v0 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV0 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub entry_point_type: EntryPointType,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
    }

    /// Represents deserialized L2 invoke transaction v1 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV1 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        pub contract_address: ContractAddress,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub transaction_hash: StarknetTransactionHash,
    }

    /// Represents deserialized L2 "L1 handler" transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1HandlerTransaction {
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub nonce: TransactionNonce,
        pub calldata: Vec<CallParam>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }
}
