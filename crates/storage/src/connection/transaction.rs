//! Contains starknet transaction related code and __not__ database transaction.

use anyhow::Context;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction as StarknetTransaction;
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash};

use crate::{prelude::*, BlockId};

pub enum TransactionStatus {
    L1Accepted,
    L2Accepted,
}

pub(super) fn insert_transactions(
    tx: &Transaction<'_>,
    block_hash: BlockHash,
    block_number: BlockNumber,
    transaction_data: &[(StarknetTransaction, Receipt)],
) -> anyhow::Result<()> {
    if transaction_data.is_empty() {
        return Ok(());
    }

    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
    for (i, (transaction, receipt)) in transaction_data.iter().enumerate() {
        // Serialize and compress transaction data.
        let transaction = dto::Transaction::from(transaction);
        let receipt = dto::Receipt::from(receipt);

        let tx_data = serde_json::to_vec(&transaction).context("Serializing transaction")?;
        let tx_data = compressor
            .compress(&tx_data)
            .context("Compressing transaction")?;

        let serialized_receipt = serde_json::to_vec(&receipt).context("Serializing receipt")?;
        let serialized_receipt = compressor
            .compress(&serialized_receipt)
            .context("Compressing receipt")?;

        let execution_status = match receipt.execution_status {
            dto::ExecutionStatus::Succeeded => 0,
            dto::ExecutionStatus::Reverted => 1,
        };

        tx.inner().execute(r"INSERT OR REPLACE INTO starknet_transactions (hash,  idx,  block_hash,  tx,  receipt,  execution_status) 
                                                                  VALUES (:hash, :idx, :block_hash, :tx, :receipt, :execution_status)",
            named_params![
            ":hash": &transaction.hash(),
            ":idx": &i.try_into_sql_int()?,
            ":block_hash": &block_hash,
            ":tx": &tx_data,
            ":receipt": &serialized_receipt,
            ":execution_status": &execution_status,
        ]).context("Inserting transaction data")?;
    }

    let events = transaction_data
        .iter()
        .flat_map(|(_, receipt)| &receipt.events);
    super::event::insert_block_events(tx, block_number, events)
        .context("Inserting events into Bloom filter")?;
    Ok(())
}

pub(super) fn transaction(
    tx: &Transaction<'_>,
    transaction: TransactionHash,
) -> anyhow::Result<Option<StarknetTransaction>> {
    let mut stmt = tx
        .inner()
        .prepare("SELECT tx FROM starknet_transactions WHERE hash = ?")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&transaction])
        .context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = row.get_ref_unwrap(0).as_blob()?;
    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction: dto::Transaction =
        serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    Ok(Some(transaction.into()))
}

pub(super) fn transaction_with_receipt(
    tx: &Transaction<'_>,
    txn_hash: TransactionHash,
) -> anyhow::Result<Option<(StarknetTransaction, Receipt, BlockHash)>> {
    let mut stmt = tx
        .inner()
        .prepare("SELECT tx, receipt, block_hash FROM starknet_transactions WHERE hash = ?1")
        .context("Preparing statement")?;

    let mut rows = stmt.query(params![&txn_hash]).context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = row.get_ref_unwrap("tx").as_blob()?;
    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction: dto::Transaction =
        serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    let receipt = match row.get_ref_unwrap("receipt").as_blob_or_null()? {
        Some(data) => data,
        None => return Ok(None),
    };
    let receipt = zstd::decode_all(receipt).context("Decompressing receipt")?;
    let receipt: dto::Receipt =
        serde_json::from_slice(&receipt).context("Deserializing receipt")?;

    let block_hash = row.get_block_hash("block_hash")?;

    Ok(Some((transaction.into(), receipt.into(), block_hash)))
}

pub(super) fn transaction_at_block(
    tx: &Transaction<'_>,
    block: BlockId,
    index: usize,
) -> anyhow::Result<Option<StarknetTransaction>> {
    // Identify block hash
    let Some(block_hash) = tx.block_hash(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare("SELECT tx FROM starknet_transactions WHERE block_hash = ? AND idx = ?")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash, &index.try_into_sql_int()?])
        .context("Executing query")?;

    let row = match rows.next()? {
        Some(row) => row,
        None => return Ok(None),
    };

    let transaction = match row.get_ref_unwrap(0).as_blob_or_null()? {
        Some(data) => data,
        None => return Ok(None),
    };

    let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
    let transaction: dto::Transaction =
        serde_json::from_slice(&transaction).context("Deserializing transaction")?;

    Ok(Some(transaction.into()))
}

pub(super) fn transaction_count(tx: &Transaction<'_>, block: BlockId) -> anyhow::Result<usize> {
    match block {
        BlockId::Number(number) => tx
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM starknet_transactions
                JOIN block_headers ON starknet_transactions.block_hash = block_headers.hash
                WHERE number = ?1",
                params![&number],
                |row| row.get(0),
            )
            .context("Counting transactions"),
        BlockId::Hash(hash) => tx
            .inner()
            .query_row(
                "SELECT COUNT(*) FROM starknet_transactions WHERE block_hash = ?1",
                params![&hash],
                |row| row.get(0),
            )
            .context("Counting transactions"),
        BlockId::Latest => {
            // First get the latest block
            let block = match tx.block_hash(BlockId::Latest)? {
                Some(hash) => hash,
                None => return Ok(0),
            };

            transaction_count(tx, block.into())
        }
    }
}

pub(super) fn transaction_data_for_block(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<Vec<(StarknetTransaction, Receipt)>>> {
    let Some(block_hash) = tx.block_hash(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare(
            "SELECT tx, receipt FROM starknet_transactions WHERE block_hash = ? ORDER BY idx ASC",
        )
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash])
        .context("Executing query")?;

    let mut data = Vec::new();
    while let Some(row) = rows.next()? {
        let receipt = row
            .get_ref_unwrap("receipt")
            .as_blob_or_null()?
            .context("Receipt data missing")?;
        let receipt = zstd::decode_all(receipt).context("Decompressing transaction receipt")?;
        let receipt: dto::Receipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;

        let transaction = row
            .get_ref_unwrap("tx")
            .as_blob_or_null()?
            .context("Transaction data missing")?;
        let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
        let transaction: dto::Transaction =
            serde_json::from_slice(&transaction).context("Deserializing transaction")?;

        data.push((transaction.into(), receipt.into()));
    }

    Ok(Some(data))
}

pub(super) fn transactions_for_block(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<Vec<StarknetTransaction>>> {
    let Some(block_hash) = tx.block_hash(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare("SELECT tx FROM starknet_transactions WHERE block_hash = ? ORDER BY idx ASC")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash])
        .context("Executing query")?;

    let mut data = Vec::new();
    while let Some(row) = rows.next()? {
        let transaction = row
            .get_ref_unwrap("tx")
            .as_blob_or_null()?
            .context("Transaction data missing")?;
        let transaction = zstd::decode_all(transaction).context("Decompressing transaction")?;
        let transaction: dto::Transaction =
            serde_json::from_slice(&transaction).context("Deserializing transaction")?;

        data.push(transaction.into());
    }

    Ok(Some(data))
}

pub(super) fn receipts_for_block(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<Vec<Receipt>>> {
    let Some(block_hash) = tx.block_hash(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare("SELECT receipt FROM starknet_transactions WHERE block_hash = ? ORDER BY idx ASC")
        .context("Preparing statement")?;

    let mut rows = stmt
        .query(params![&block_hash])
        .context("Executing query")?;

    let mut data = Vec::new();
    while let Some(row) = rows.next()? {
        let receipt = row
            .get_ref_unwrap("receipt")
            .as_blob_or_null()?
            .context("Transaction data missing")?;
        let receipt = zstd::decode_all(receipt).context("Decompressing receipt")?;
        let receipt: dto::Receipt =
            serde_json::from_slice(&receipt).context("Deserializing receipt")?;

        data.push(receipt.into());
    }

    Ok(Some(data))
}

pub(super) fn transaction_hashes_for_block(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<Vec<TransactionHash>>> {
    let Some(block_hash) = tx.block_hash(block)? else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare("SELECT hash FROM starknet_transactions WHERE block_hash = ? ORDER BY idx ASC")
        .context("Preparing statement")?;

    let data = stmt
        .query_map(params![&block_hash], |row| row.get_transaction_hash("hash"))
        .context("Executing query")?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(data))
}

pub(super) fn transaction_block_hash(
    tx: &Transaction<'_>,
    hash: TransactionHash,
) -> anyhow::Result<Option<BlockHash>> {
    tx.inner()
        .query_row(
            "SELECT block_hash FROM starknet_transactions WHERE hash = ?",
            params![&hash],
            |row| row.get_block_hash(0),
        )
        .optional()
        .map_err(|e| e.into())
}

/// A copy of the gateway definitions which are currently used as the storage serde implementation. Having a copy here
/// allows us to decouple this crate from the gateway types, while only exposing the common types via the storage API.
pub(crate) mod dto {
    use fake::Dummy;
    use pathfinder_common::*;
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
        L2ToL1MessagePayloadElemAsDecimalStr, ResourceAmountAsHexStr, ResourcePricePerUnitAsHexStr,
        TipAsHexStr, TransactionSignatureElemAsDecimalStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    impl From<pathfinder_common::transaction::EntryPointType> for EntryPointType {
        fn from(value: pathfinder_common::transaction::EntryPointType) -> Self {
            use pathfinder_common::transaction::EntryPointType::{External, L1Handler};
            match value {
                External => Self::External,
                L1Handler => Self::L1Handler,
            }
        }
    }

    impl From<EntryPointType> for pathfinder_common::transaction::EntryPointType {
        fn from(value: EntryPointType) -> Self {
            match value {
                EntryPointType::External => Self::External,
                EntryPointType::L1Handler => Self::L1Handler,
            }
        }
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResources {
        pub builtin_instance_counter: BuiltinCounters,
        pub n_steps: u64,
        pub n_memory_holes: u64,
    }

    impl From<&ExecutionResources> for pathfinder_common::receipt::ExecutionResources {
        fn from(value: &ExecutionResources) -> Self {
            Self {
                builtin_instance_counter: value.builtin_instance_counter.into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
            }
        }
    }

    impl From<&pathfinder_common::receipt::ExecutionResources> for ExecutionResources {
        fn from(value: &pathfinder_common::receipt::ExecutionResources) -> Self {
            Self {
                builtin_instance_counter: (&value.builtin_instance_counter).into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
            }
        }
    }

    // This struct purposefully allows for unknown fields as it is not critical to
    // store these counters perfectly. Failure would be far more costly than simply
    // ignoring them.
    #[derive(Copy, Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
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

    impl From<BuiltinCounters> for pathfinder_common::receipt::BuiltinCounters {
        fn from(value: BuiltinCounters) -> Self {
            // Use deconstruction to ensure these structs remain in-sync.
            let BuiltinCounters {
                output_builtin,
                pedersen_builtin,
                range_check_builtin,
                ecdsa_builtin,
                bitwise_builtin,
                ec_op_builtin,
                keccak_builtin,
                poseidon_builtin,
                segment_arena_builtin,
            } = value;
            Self {
                output_builtin,
                pedersen_builtin,
                range_check_builtin,
                ecdsa_builtin,
                bitwise_builtin,
                ec_op_builtin,
                keccak_builtin,
                poseidon_builtin,
                segment_arena_builtin,
            }
        }
    }

    impl From<&pathfinder_common::receipt::BuiltinCounters> for BuiltinCounters {
        fn from(value: &pathfinder_common::receipt::BuiltinCounters) -> Self {
            // Use deconstruction to ensure these structs remain in-sync.
            let pathfinder_common::receipt::BuiltinCounters {
                output_builtin,
                pedersen_builtin,
                range_check_builtin,
                ecdsa_builtin,
                bitwise_builtin,
                ec_op_builtin,
                keccak_builtin,
                poseidon_builtin,
                segment_arena_builtin,
            } = value.clone();
            Self {
                output_builtin,
                pedersen_builtin,
                range_check_builtin,
                ecdsa_builtin,
                bitwise_builtin,
                ec_op_builtin,
                keccak_builtin,
                poseidon_builtin,
                segment_arena_builtin,
            }
        }
    }

    /// Represents deserialized L2 to L1 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct L2ToL1Message {
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<L2ToL1MessagePayloadElemAsDecimalStr>")]
        pub payload: Vec<L2ToL1MessagePayloadElem>,
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub to_address: EthereumAddress,
    }

    impl From<L2ToL1Message> for pathfinder_common::receipt::L2ToL1Message {
        fn from(value: L2ToL1Message) -> Self {
            let L2ToL1Message {
                from_address,
                payload,
                to_address,
            } = value;
            pathfinder_common::receipt::L2ToL1Message {
                from_address,
                payload,
                to_address,
            }
        }
    }

    impl From<&pathfinder_common::receipt::L2ToL1Message> for L2ToL1Message {
        fn from(value: &pathfinder_common::receipt::L2ToL1Message) -> Self {
            let pathfinder_common::receipt::L2ToL1Message {
                from_address,
                payload,
                to_address,
            } = value.clone();
            Self {
                from_address,
                payload,
                to_address,
            }
        }
    }

    #[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum ExecutionStatus {
        // This must be the default as pre v0.12.1 receipts did not contain this value and
        // were always success as reverted did not exist.
        #[default]
        Succeeded,
        Reverted,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde(default)]
        pub actual_fee: Option<Fee>,
        pub events: Vec<pathfinder_common::event::Event>,
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

    impl From<&pathfinder_common::receipt::Receipt> for Receipt {
        fn from(value: &pathfinder_common::receipt::Receipt) -> Self {
            let (execution_status, revert_error) = match &value.execution_status {
                receipt::ExecutionStatus::Succeeded => (ExecutionStatus::Succeeded, None),
                receipt::ExecutionStatus::Reverted { reason } => {
                    (ExecutionStatus::Reverted, Some(reason.clone()))
                }
            };

            Self {
                actual_fee: value.actual_fee,
                events: value.events.clone(),
                execution_resources: value.execution_resources.as_ref().map(Into::into),
                // We don't care about this field anymore.
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: value.l2_to_l1_messages.iter().map(Into::into).collect(),
                transaction_hash: value.transaction_hash,
                transaction_index: value.transaction_index,
                execution_status,
                revert_error,
            }
        }
    }

    impl From<Receipt> for pathfinder_common::receipt::Receipt {
        fn from(value: Receipt) -> Self {
            use pathfinder_common::receipt as common;

            let Receipt {
                actual_fee,
                events,
                execution_resources,
                // This information is redundant as it is already in the transaction itself.
                l1_to_l2_consumed_message: _,
                l2_to_l1_messages,
                transaction_hash,
                transaction_index,
                execution_status,
                revert_error,
            } = value;

            common::Receipt {
                actual_fee,
                events,
                execution_resources: execution_resources.as_ref().map(Into::into),
                l2_to_l1_messages: l2_to_l1_messages.into_iter().map(Into::into).collect(),
                transaction_hash,
                transaction_index,
                execution_status: match execution_status {
                    ExecutionStatus::Succeeded => common::ExecutionStatus::Succeeded,
                    ExecutionStatus::Reverted => common::ExecutionStatus::Reverted {
                        reason: revert_error.unwrap_or_default(),
                    },
                },
            }
        }
    }

    #[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Dummy)]
    pub enum DataAvailabilityMode {
        #[default]
        L1,
        L2,
    }

    impl Serialize for DataAvailabilityMode {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                DataAvailabilityMode::L1 => serializer.serialize_u8(0),
                DataAvailabilityMode::L2 => serializer.serialize_u8(1),
            }
        }
    }

    impl<'de> Deserialize<'de> for DataAvailabilityMode {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            match <u8 as Deserialize>::deserialize(deserializer)? {
                0 => Ok(Self::L1),
                1 => Ok(Self::L2),
                _ => Err(serde::de::Error::custom("invalid data availability mode")),
            }
        }
    }

    impl From<DataAvailabilityMode> for pathfinder_common::transaction::DataAvailabilityMode {
        fn from(value: DataAvailabilityMode) -> Self {
            match value {
                DataAvailabilityMode::L1 => Self::L1,
                DataAvailabilityMode::L2 => Self::L2,
            }
        }
    }

    impl From<pathfinder_common::transaction::DataAvailabilityMode> for DataAvailabilityMode {
        fn from(value: pathfinder_common::transaction::DataAvailabilityMode) -> Self {
            match value {
                pathfinder_common::transaction::DataAvailabilityMode::L1 => Self::L1,
                pathfinder_common::transaction::DataAvailabilityMode::L2 => Self::L2,
            }
        }
    }

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    pub struct ResourceBounds {
        #[serde(rename = "L1_GAS")]
        pub l1_gas: ResourceBound,
        #[serde(rename = "L2_GAS")]
        pub l2_gas: ResourceBound,
    }

    impl From<ResourceBounds> for pathfinder_common::transaction::ResourceBounds {
        fn from(value: ResourceBounds) -> Self {
            Self {
                l1_gas: value.l1_gas.into(),
                l2_gas: value.l2_gas.into(),
            }
        }
    }

    impl From<pathfinder_common::transaction::ResourceBounds> for ResourceBounds {
        fn from(value: pathfinder_common::transaction::ResourceBounds) -> Self {
            Self {
                l1_gas: value.l1_gas.into(),
                l2_gas: value.l2_gas.into(),
            }
        }
    }

    #[serde_as]
    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    pub struct ResourceBound {
        #[serde_as(as = "ResourceAmountAsHexStr")]
        pub max_amount: ResourceAmount,
        #[serde_as(as = "ResourcePricePerUnitAsHexStr")]
        pub max_price_per_unit: ResourcePricePerUnit,
    }

    impl From<ResourceBound> for pathfinder_common::transaction::ResourceBound {
        fn from(value: ResourceBound) -> Self {
            Self {
                max_amount: value.max_amount,
                max_price_per_unit: value.max_price_per_unit,
            }
        }
    }

    impl From<pathfinder_common::transaction::ResourceBound> for ResourceBound {
        fn from(value: pathfinder_common::transaction::ResourceBound) -> Self {
            Self {
                max_amount: value.max_amount,
                max_price_per_unit: value.max_price_per_unit,
            }
        }
    }

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq, Dummy)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "DEPLOY")]
        // FIXME regenesis: remove Deploy txn type after regenesis
        // We are keeping this type of transaction until regenesis
        // only to support older pre-0.11.0 blocks
        Deploy(DeployTransaction),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccountTransaction),
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    // This manual deserializtion is a work-around for L1 handler transactions
    // historically being served as Invoke V0. However, the gateway has retroactively
    // changed these to L1 handlers. This means older databases will have these as Invoke
    // but modern one's as L1 handler. This causes confusion, so we convert these old Invoke
    // to L1 handler manually.
    //
    // The alternative is to do a costly database migration which involves opening every tx.
    //
    // This work-around may be removed once we are certain all databases no longer contain these
    // transactions, which will likely only occur after either a migration, or regenesis.
    impl<'de> Deserialize<'de> for Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            /// Copy of [Transaction] to deserialize into, before converting to [Transaction]
            /// with the potential Invoke V0 -> L1 handler cast.
            #[derive(Deserialize)]
            #[serde(tag = "type", deny_unknown_fields)]
            pub enum InnerTransaction {
                #[serde(rename = "DECLARE")]
                Declare(DeclareTransaction),
                #[serde(rename = "DEPLOY")]
                Deploy(DeployTransaction),
                #[serde(rename = "DEPLOY_ACCOUNT")]
                DeployAccount(DeployAccountTransaction),
                #[serde(rename = "INVOKE_FUNCTION")]
                Invoke(InvokeTransaction),
                #[serde(rename = "L1_HANDLER")]
                L1Handler(L1HandlerTransaction),
            }

            let tx = InnerTransaction::deserialize(deserializer)?;
            let tx = match tx {
                InnerTransaction::Declare(x) => Transaction::Declare(x),
                InnerTransaction::Deploy(x) => Transaction::Deploy(x),
                InnerTransaction::DeployAccount(x) => Transaction::DeployAccount(x),
                InnerTransaction::Invoke(InvokeTransaction::V0(i))
                    if i.entry_point_type == Some(EntryPointType::L1Handler) =>
                {
                    let l1_handler = L1HandlerTransaction {
                        contract_address: i.sender_address,
                        entry_point_selector: i.entry_point_selector,
                        nonce: TransactionNonce::ZERO,
                        calldata: i.calldata,
                        transaction_hash: i.transaction_hash,
                        version: TransactionVersion::ZERO,
                    };

                    Transaction::L1Handler(l1_handler)
                }
                InnerTransaction::Invoke(x) => Transaction::Invoke(x),
                InnerTransaction::L1Handler(x) => Transaction::L1Handler(x),
            };

            Ok(tx)
        }
    }

    impl From<&pathfinder_common::transaction::Transaction> for Transaction {
        fn from(value: &pathfinder_common::transaction::Transaction) -> Self {
            use pathfinder_common::transaction::TransactionVariant::*;
            use pathfinder_common::transaction::*;

            let transaction_hash = value.hash;
            match value.variant.clone() {
                DeclareV0(DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                }) => Self::Declare(DeclareTransaction::V0(self::DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash,
                })),
                DeclareV1(DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                }) => Self::Declare(DeclareTransaction::V1(self::DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash,
                })),
                DeclareV2(DeclareTransactionV2 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    compiled_class_hash,
                }) => Self::Declare(DeclareTransaction::V2(self::DeclareTransactionV2 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash,
                    compiled_class_hash,
                })),
                DeclareV3(DeclareTransactionV3 {
                    class_hash,
                    nonce,
                    nonce_data_availability_mode,
                    fee_data_availability_mode,
                    resource_bounds,
                    tip,
                    paymaster_data,
                    signature,
                    account_deployment_data,
                    sender_address,
                    compiled_class_hash,
                }) => Self::Declare(DeclareTransaction::V3(self::DeclareTransactionV3 {
                    class_hash,
                    nonce,
                    nonce_data_availability_mode: nonce_data_availability_mode.into(),
                    fee_data_availability_mode: fee_data_availability_mode.into(),
                    resource_bounds: resource_bounds.into(),
                    tip,
                    paymaster_data,
                    sender_address,
                    signature,
                    transaction_hash,
                    compiled_class_hash,
                    account_deployment_data,
                })),
                Deploy(DeployTransaction {
                    contract_address,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                    version,
                }) => Self::Deploy(self::DeployTransaction {
                    contract_address,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                    transaction_hash,
                    version,
                }),
                DeployAccountV0V1(DeployAccountTransactionV0V1 {
                    contract_address,
                    max_fee,
                    version,
                    signature,
                    nonce,
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                }) => Self::DeployAccount(self::DeployAccountTransaction::V0V1(
                    self::DeployAccountTransactionV0V1 {
                        contract_address,
                        transaction_hash,
                        max_fee,
                        version,
                        signature,
                        nonce,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                )),
                DeployAccountV3(DeployAccountTransactionV3 {
                    contract_address,
                    signature,
                    nonce,
                    nonce_data_availability_mode,
                    fee_data_availability_mode,
                    resource_bounds,
                    tip,
                    paymaster_data,
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                }) => Self::DeployAccount(self::DeployAccountTransaction::V3(
                    self::DeployAccountTransactionV3 {
                        nonce,
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data,
                        sender_address: contract_address,
                        signature,
                        transaction_hash,
                        version: TransactionVersion::THREE,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                )),
                InvokeV0(InvokeTransactionV0 {
                    calldata,
                    sender_address,
                    entry_point_selector,
                    entry_point_type,
                    max_fee,
                    signature,
                }) => Self::Invoke(InvokeTransaction::V0(self::InvokeTransactionV0 {
                    calldata,
                    sender_address,
                    entry_point_selector,
                    entry_point_type: entry_point_type.map(Into::into),
                    max_fee,
                    signature,
                    transaction_hash,
                })),
                InvokeV1(InvokeTransactionV1 {
                    calldata,
                    sender_address,
                    max_fee,
                    signature,
                    nonce,
                }) => Self::Invoke(InvokeTransaction::V1(self::InvokeTransactionV1 {
                    calldata,
                    sender_address,
                    max_fee,
                    signature,
                    nonce,
                    transaction_hash,
                })),
                InvokeV3(InvokeTransactionV3 {
                    signature,
                    nonce,
                    nonce_data_availability_mode,
                    fee_data_availability_mode,
                    resource_bounds,
                    tip,
                    paymaster_data,
                    account_deployment_data,
                    calldata,
                    sender_address,
                }) => Self::Invoke(InvokeTransaction::V3(self::InvokeTransactionV3 {
                    nonce,
                    nonce_data_availability_mode: nonce_data_availability_mode.into(),
                    fee_data_availability_mode: fee_data_availability_mode.into(),
                    resource_bounds: resource_bounds.into(),
                    tip,
                    paymaster_data,
                    sender_address,
                    signature,
                    transaction_hash,
                    calldata,
                    account_deployment_data,
                })),
                L1Handler(L1HandlerTransaction {
                    contract_address,
                    entry_point_selector,
                    nonce,
                    calldata,
                }) => Self::L1Handler(self::L1HandlerTransaction {
                    contract_address,
                    entry_point_selector,
                    nonce,
                    calldata,
                    transaction_hash,
                    version: TransactionVersion::ZERO,
                }),
            }
        }
    }

    impl From<Transaction> for pathfinder_common::transaction::Transaction {
        fn from(value: Transaction) -> Self {
            use pathfinder_common::transaction::TransactionVariant;

            let hash = value.hash();
            let variant = match value {
                Transaction::Declare(DeclareTransaction::V0(DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash: _,
                })) => TransactionVariant::DeclareV0(
                    pathfinder_common::transaction::DeclareTransactionV0V1 {
                        class_hash,
                        max_fee,
                        nonce,
                        sender_address,
                        signature,
                    },
                ),
                Transaction::Declare(DeclareTransaction::V1(DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash: _,
                })) => TransactionVariant::DeclareV1(
                    pathfinder_common::transaction::DeclareTransactionV0V1 {
                        class_hash,
                        max_fee,
                        nonce,
                        sender_address,
                        signature,
                    },
                ),
                Transaction::Declare(DeclareTransaction::V2(DeclareTransactionV2 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    transaction_hash: _,
                    compiled_class_hash,
                })) => TransactionVariant::DeclareV2(
                    pathfinder_common::transaction::DeclareTransactionV2 {
                        class_hash,
                        max_fee,
                        nonce,
                        sender_address,
                        signature,
                        compiled_class_hash,
                    },
                ),
                Transaction::Declare(DeclareTransaction::V3(DeclareTransactionV3 {
                    class_hash,
                    nonce,
                    nonce_data_availability_mode,
                    fee_data_availability_mode,
                    resource_bounds,
                    tip,
                    paymaster_data,
                    sender_address,
                    signature,
                    transaction_hash: _,
                    compiled_class_hash,
                    account_deployment_data,
                })) => TransactionVariant::DeclareV3(
                    pathfinder_common::transaction::DeclareTransactionV3 {
                        class_hash,
                        nonce,
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data,
                        sender_address,
                        signature,
                        compiled_class_hash,
                        account_deployment_data,
                    },
                ),
                Transaction::Deploy(DeployTransaction {
                    contract_address,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                    transaction_hash: _,
                    version,
                }) => {
                    TransactionVariant::Deploy(pathfinder_common::transaction::DeployTransaction {
                        contract_address,
                        contract_address_salt,
                        class_hash,
                        constructor_calldata,
                        version,
                    })
                }
                Transaction::DeployAccount(DeployAccountTransaction::V0V1(
                    DeployAccountTransactionV0V1 {
                        contract_address,
                        transaction_hash: _,
                        max_fee,
                        version,
                        signature,
                        nonce,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                )) => TransactionVariant::DeployAccountV0V1(
                    pathfinder_common::transaction::DeployAccountTransactionV0V1 {
                        contract_address,
                        max_fee,
                        version,
                        signature,
                        nonce,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                ),
                Transaction::DeployAccount(DeployAccountTransaction::V3(
                    DeployAccountTransactionV3 {
                        nonce,
                        nonce_data_availability_mode,
                        fee_data_availability_mode,
                        resource_bounds,
                        tip,
                        paymaster_data,
                        sender_address,
                        signature,
                        transaction_hash: _,
                        version: _,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                )) => TransactionVariant::DeployAccountV3(
                    pathfinder_common::transaction::DeployAccountTransactionV3 {
                        contract_address: sender_address,
                        signature,
                        nonce,
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data,
                        contract_address_salt,
                        constructor_calldata,
                        class_hash,
                    },
                ),
                Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                    calldata,
                    sender_address,
                    entry_point_selector,
                    entry_point_type,
                    max_fee,
                    signature,
                    transaction_hash: _,
                })) => TransactionVariant::InvokeV0(
                    pathfinder_common::transaction::InvokeTransactionV0 {
                        calldata,
                        sender_address,
                        entry_point_selector,
                        entry_point_type: entry_point_type.map(Into::into),
                        max_fee,
                        signature,
                    },
                ),
                Transaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                    calldata,
                    sender_address,
                    max_fee,
                    signature,
                    nonce,
                    transaction_hash: _,
                })) => TransactionVariant::InvokeV1(
                    pathfinder_common::transaction::InvokeTransactionV1 {
                        calldata,
                        sender_address,
                        max_fee,
                        signature,
                        nonce,
                    },
                ),
                Transaction::Invoke(InvokeTransaction::V3(InvokeTransactionV3 {
                    nonce,
                    nonce_data_availability_mode,
                    fee_data_availability_mode,
                    resource_bounds,
                    tip,
                    paymaster_data,
                    sender_address,
                    signature,
                    transaction_hash: _,
                    calldata,
                    account_deployment_data,
                })) => TransactionVariant::InvokeV3(
                    pathfinder_common::transaction::InvokeTransactionV3 {
                        signature,
                        nonce,
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data,
                        account_deployment_data,
                        calldata,
                        sender_address,
                    },
                ),
                Transaction::L1Handler(L1HandlerTransaction {
                    contract_address,
                    entry_point_selector,
                    nonce,
                    calldata,
                    transaction_hash: _,
                    // This should always be zero.
                    version: _,
                }) => TransactionVariant::L1Handler(
                    pathfinder_common::transaction::L1HandlerTransaction {
                        contract_address,
                        entry_point_selector,
                        nonce,
                        calldata,
                    },
                ),
            };

            pathfinder_common::transaction::Transaction { hash, variant }
        }
    }

    impl Transaction {
        /// Returns hash of the transaction
        pub fn hash(&self) -> TransactionHash {
            match self {
                Transaction::Declare(t) => match t {
                    DeclareTransaction::V0(t) => t.transaction_hash,
                    DeclareTransaction::V1(t) => t.transaction_hash,
                    DeclareTransaction::V2(t) => t.transaction_hash,
                    DeclareTransaction::V3(t) => t.transaction_hash,
                },
                Transaction::Deploy(t) => t.transaction_hash,
                Transaction::DeployAccount(t) => match t {
                    DeployAccountTransaction::V0V1(t) => t.transaction_hash,
                    DeployAccountTransaction::V3(t) => t.transaction_hash,
                },
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.transaction_hash,
                    InvokeTransaction::V1(t) => t.transaction_hash,
                    InvokeTransaction::V3(t) => t.transaction_hash,
                },
                Transaction::L1Handler(t) => t.transaction_hash,
            }
        }

        pub fn contract_address(&self) -> ContractAddress {
            match self {
                Transaction::Declare(DeclareTransaction::V0(t)) => t.sender_address,
                Transaction::Declare(DeclareTransaction::V1(t)) => t.sender_address,
                Transaction::Declare(DeclareTransaction::V2(t)) => t.sender_address,
                Transaction::Declare(DeclareTransaction::V3(t)) => t.sender_address,
                Transaction::Deploy(t) => t.contract_address,
                Transaction::DeployAccount(t) => match t {
                    DeployAccountTransaction::V0V1(t) => t.contract_address,
                    DeployAccountTransaction::V3(t) => t.sender_address,
                },
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.sender_address,
                    InvokeTransaction::V1(t) => t.sender_address,
                    InvokeTransaction::V3(t) => t.sender_address,
                },
                Transaction::L1Handler(t) => t.contract_address,
            }
        }

        pub fn version(&self) -> TransactionVersion {
            match self {
                Transaction::Declare(DeclareTransaction::V0(_)) => TransactionVersion::ZERO,
                Transaction::Declare(DeclareTransaction::V1(_)) => TransactionVersion::ONE,
                Transaction::Declare(DeclareTransaction::V2(_)) => TransactionVersion::TWO,
                Transaction::Declare(DeclareTransaction::V3(_)) => TransactionVersion::THREE,

                Transaction::Deploy(t) => t.version,
                Transaction::DeployAccount(t) => match t {
                    DeployAccountTransaction::V0V1(t) => t.version,
                    DeployAccountTransaction::V3(t) => t.version,
                },
                Transaction::Invoke(InvokeTransaction::V0(_)) => TransactionVersion::ZERO,
                Transaction::Invoke(InvokeTransaction::V1(_)) => TransactionVersion::ONE,
                Transaction::Invoke(InvokeTransaction::V3(_)) => TransactionVersion::THREE,
                Transaction::L1Handler(t) => t.version,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq, Dummy)]
    #[serde(tag = "version")]
    pub enum DeclareTransaction {
        #[serde(rename = "0x0")]
        V0(DeclareTransactionV0V1),
        #[serde(rename = "0x1")]
        V1(DeclareTransactionV0V1),
        #[serde(rename = "0x2")]
        V2(DeclareTransactionV2),
        #[serde(rename = "0x3")]
        V3(DeclareTransactionV3),
    }

    impl<'de> Deserialize<'de> for DeclareTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
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
                TransactionVersion::ZERO => Ok(Self::V0(
                    DeclareTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::ONE => Ok(Self::V1(
                    DeclareTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::TWO => Ok(Self::V2(
                    DeclareTransactionV2::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::THREE => Ok(Self::V3(
                    DeclareTransactionV3::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1, 2 or 3")),
            }
        }
    }

    impl DeclareTransaction {
        pub fn signature(&self) -> &[TransactionSignatureElem] {
            match self {
                DeclareTransaction::V0(tx) => tx.signature.as_ref(),
                DeclareTransaction::V1(tx) => tx.signature.as_ref(),
                DeclareTransaction::V2(tx) => tx.signature.as_ref(),
                DeclareTransaction::V3(tx) => tx.signature.as_ref(),
            }
        }
    }

    /// A version 0 or 1 declare transaction.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV0V1 {
        pub class_hash: ClassHash,
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
    }

    /// A version 2 declare transaction.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV2 {
        pub class_hash: ClassHash,
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
        pub compiled_class_hash: CasmHash,
    }

    /// A version 2 declare transaction.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV3 {
        pub class_hash: ClassHash,

        pub nonce: TransactionNonce,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        #[serde_as(as = "TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,

        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
        pub compiled_class_hash: CasmHash,

        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
    }

    const fn transaction_version_zero() -> TransactionVersion {
        TransactionVersion::ZERO
    }

    /// Represents deserialized L2 deploy transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransaction {
        pub contract_address: ContractAddress,
        pub contract_address_salt: ContractAddressSalt,
        pub class_hash: ClassHash,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
        pub transaction_hash: TransactionHash,
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 deploy account transaction data.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq, Dummy)]
    #[serde(untagged)]
    pub enum DeployAccountTransaction {
        V0V1(DeployAccountTransactionV0V1),
        V3(DeployAccountTransactionV3),
    }

    impl<'de> Deserialize<'de> for DeployAccountTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde(default = "transaction_version_zero")]
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;

            match version.version {
                TransactionVersion::ZERO => Ok(Self::V0V1(
                    DeployAccountTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::ONE => Ok(Self::V0V1(
                    DeployAccountTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::THREE => Ok(Self::V3(
                    DeployAccountTransactionV3::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1 or 3")),
            }
        }
    }

    impl DeployAccountTransaction {
        pub fn contract_address(&self) -> ContractAddress {
            match self {
                Self::V0V1(tx) => tx.contract_address,
                Self::V3(tx) => tx.sender_address,
            }
        }

        pub fn signature(&self) -> &[TransactionSignatureElem] {
            match self {
                Self::V0V1(tx) => tx.signature.as_ref(),
                Self::V3(tx) => tx.signature.as_ref(),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountTransactionV0V1 {
        pub contract_address: ContractAddress,
        pub transaction_hash: TransactionHash,
        pub max_fee: Fee,
        pub version: TransactionVersion,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountTransactionV3 {
        pub nonce: TransactionNonce,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        #[serde_as(as = "TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,

        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
        pub version: TransactionVersion,
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq, Dummy)]
    #[serde(tag = "version")]
    pub enum InvokeTransaction {
        #[serde(rename = "0x0")]
        V0(InvokeTransactionV0),
        #[serde(rename = "0x1")]
        V1(InvokeTransactionV1),
        #[serde(rename = "0x3")]
        V3(InvokeTransactionV3),
    }

    impl<'de> Deserialize<'de> for InvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
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
                TransactionVersion::ZERO => Ok(Self::V0(
                    InvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::ONE => Ok(Self::V1(
                    InvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion::THREE => Ok(Self::V3(
                    InvokeTransactionV3::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1 or 3")),
            }
        }
    }

    impl InvokeTransaction {
        pub fn signature(&self) -> &[TransactionSignatureElem] {
            match self {
                Self::V0(tx) => tx.signature.as_ref(),
                Self::V1(tx) => tx.signature.as_ref(),
                Self::V3(tx) => tx.signature.as_ref(),
            }
        }
    }

    /// Represents deserialized L2 invoke transaction v0 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV0 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        // contract_address is the historic name for this field. sender_address was
        // introduced with starknet v0.11. Although the gateway no longer uses the historic
        // name at all, this alias must be kept until a database migration fixes all historic
        // transaction naming, or until regenesis removes them all.
        #[serde(alias = "contract_address")]
        pub sender_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entry_point_type: Option<EntryPointType>,
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
    }

    /// Represents deserialized L2 invoke transaction v1 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV1 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        // contract_address is the historic name for this field. sender_address was
        // introduced with starknet v0.11. Although the gateway no longer uses the historic
        // name at all, this alias must be kept until a database migration fixes all historic
        // transaction naming, or until regenesis removes them all.
        #[serde(alias = "contract_address")]
        pub sender_address: ContractAddress,
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub transaction_hash: TransactionHash,
    }

    /// Represents deserialized L2 invoke transaction v3 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV3 {
        pub nonce: TransactionNonce,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        #[serde_as(as = "TipAsHexStr")]
        pub tip: Tip,
        pub paymaster_data: Vec<PaymasterDataElem>,

        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,

        pub account_deployment_data: Vec<AccountDeploymentDataElem>,
    }

    /// Represents deserialized L2 "L1 handler" transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct L1HandlerTransaction {
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        // FIXME: remove once starkware fixes their gateway bug which was missing this field.
        #[serde(default)]
        pub nonce: TransactionNonce,
        pub calldata: Vec<CallParam>,
        pub transaction_hash: TransactionHash,
        pub version: TransactionVersion,
    }

    /// Describes L2 transaction failure details.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::transaction::*;
    use pathfinder_common::TransactionVersion;
    use pathfinder_common::{BlockHeader, TransactionIndex};

    use super::*;

    fn setup() -> (
        crate::Connection,
        BlockHeader,
        Vec<(StarknetTransaction, Receipt)>,
    ) {
        let header = BlockHeader::builder().finalize_with_hash(block_hash_bytes!(b"block hash"));

        // Create one of each transaction type.
        let transactions = vec![
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"declare v0 tx hash"),
                variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                    class_hash: class_hash_bytes!(b"declare v0 class hash"),
                    max_fee: fee_bytes!(b"declare v0 max fee"),
                    nonce: transaction_nonce_bytes!(b"declare v0 tx nonce"),
                    sender_address: contract_address_bytes!(b"declare v0 contract address"),
                    signature: vec![
                        transaction_signature_elem_bytes!(b"declare v0 tx sig 0"),
                        transaction_signature_elem_bytes!(b"declare v0 tx sig 1"),
                    ],
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"declare v1 tx hash"),
                variant: TransactionVariant::DeclareV1(DeclareTransactionV0V1 {
                    class_hash: class_hash_bytes!(b"declare v1 class hash"),
                    max_fee: fee_bytes!(b"declare v1 max fee"),
                    nonce: transaction_nonce_bytes!(b"declare v1 tx nonce"),
                    sender_address: contract_address_bytes!(b"declare v1 contract address"),
                    signature: vec![
                        transaction_signature_elem_bytes!(b"declare v1 tx sig 0"),
                        transaction_signature_elem_bytes!(b"declare v1 tx sig 1"),
                    ],
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"declare v2 tx hash"),
                variant: TransactionVariant::DeclareV2(DeclareTransactionV2 {
                    class_hash: class_hash_bytes!(b"declare v2 class hash"),
                    max_fee: fee_bytes!(b"declare v2 max fee"),
                    nonce: transaction_nonce_bytes!(b"declare v2 tx nonce"),
                    sender_address: contract_address_bytes!(b"declare v2 contract address"),
                    signature: vec![
                        transaction_signature_elem_bytes!(b"declare v2 tx sig 0"),
                        transaction_signature_elem_bytes!(b"declare v2 tx sig 1"),
                    ],
                    compiled_class_hash: casm_hash_bytes!(b"declare v2 casm hash"),
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"deploy tx hash"),
                variant: TransactionVariant::Deploy(DeployTransaction {
                    contract_address: contract_address_bytes!(b"deploy contract address"),
                    contract_address_salt: contract_address_salt_bytes!(
                        b"deploy contract address salt"
                    ),
                    class_hash: class_hash_bytes!(b"deploy class hash"),
                    constructor_calldata: vec![
                        constructor_param_bytes!(b"deploy call data 0"),
                        constructor_param_bytes!(b"deploy call data 1"),
                    ],
                    version: TransactionVersion::ZERO,
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"deploy account tx hash"),
                variant: TransactionVariant::DeployAccountV0V1(DeployAccountTransactionV0V1 {
                    contract_address: contract_address_bytes!(b"deploy account contract address"),
                    max_fee: fee_bytes!(b"deploy account max fee"),
                    version: TransactionVersion::ZERO,
                    signature: vec![
                        transaction_signature_elem_bytes!(b"deploy account tx sig 0"),
                        transaction_signature_elem_bytes!(b"deploy account tx sig 1"),
                    ],
                    nonce: transaction_nonce_bytes!(b"deploy account tx nonce"),
                    contract_address_salt: contract_address_salt_bytes!(
                        b"deploy account address salt"
                    ),
                    constructor_calldata: vec![
                        call_param_bytes!(b"deploy account call data 0"),
                        call_param_bytes!(b"deploy account call data 1"),
                    ],
                    class_hash: class_hash_bytes!(b"deploy account class hash"),
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"invoke v0 tx hash"),
                variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
                    calldata: vec![
                        call_param_bytes!(b"invoke v0 call data 0"),
                        call_param_bytes!(b"invoke v0 call data 1"),
                    ],
                    sender_address: contract_address_bytes!(b"invoke v0 contract address"),
                    entry_point_selector: entry_point_bytes!(b"invoke v0 entry point"),
                    entry_point_type: None,
                    max_fee: fee_bytes!(b"invoke v0 max fee"),
                    signature: vec![
                        transaction_signature_elem_bytes!(b"invoke v0 tx sig 0"),
                        transaction_signature_elem_bytes!(b"invoke v0 tx sig 1"),
                    ],
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"invoke v1 tx hash"),
                variant: TransactionVariant::InvokeV1(InvokeTransactionV1 {
                    calldata: vec![
                        call_param_bytes!(b"invoke v1 call data 0"),
                        call_param_bytes!(b"invoke v1 call data 1"),
                    ],
                    sender_address: contract_address_bytes!(b"invoke v1 contract address"),
                    max_fee: fee_bytes!(b"invoke v1 max fee"),
                    signature: vec![
                        transaction_signature_elem_bytes!(b"invoke v1 tx sig 0"),
                        transaction_signature_elem_bytes!(b"invoke v1 tx sig 1"),
                    ],
                    nonce: transaction_nonce_bytes!(b"invoke v1 tx nonce"),
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"L1 handler tx hash"),
                variant: TransactionVariant::L1Handler(L1HandlerTransaction {
                    contract_address: contract_address_bytes!(b"L1 handler contract address"),
                    entry_point_selector: entry_point_bytes!(b"L1 handler entry point"),
                    nonce: transaction_nonce_bytes!(b"L1 handler tx nonce"),
                    calldata: vec![
                        call_param_bytes!(b"L1 handler call data 0"),
                        call_param_bytes!(b"L1 handler call data 1"),
                    ],
                }),
            },
        ];

        // Generate a random receipt for each transaction. Note that these won't make physical sense
        // but its enough for the tests.
        let receipts: Vec<pathfinder_common::receipt::Receipt> = transactions
            .iter()
            .enumerate()
            .map(|(i, t)| Receipt {
                transaction_hash: t.hash,
                transaction_index: TransactionIndex::new_or_panic(i as u64),
                ..Default::default()
            })
            .collect();
        assert_eq!(transactions.len(), receipts.len());

        let body = transactions.into_iter().zip(receipts).collect::<Vec<_>>();

        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let db_tx = db.transaction().unwrap();

        db_tx.insert_block_header(&header).unwrap();
        db_tx
            .insert_transaction_data(header.hash, header.number, &body)
            .unwrap();

        db_tx.commit().unwrap();

        (db, header, body)
    }

    #[test]
    fn transaction() {
        let (mut db, _, body) = setup();
        let tx = db.transaction().unwrap();

        let (expected, _) = body.first().unwrap().clone();

        let result = super::transaction(&tx, expected.hash).unwrap().unwrap();
        assert_eq!(result, expected);

        let invalid = super::transaction(&tx, transaction_hash_bytes!(b"invalid")).unwrap();
        assert_eq!(invalid, None);
    }

    #[test]
    fn transaction_with_receipt() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let (transaction, receipt) = body.first().unwrap().clone();

        let result = super::transaction_with_receipt(&tx, transaction.hash)
            .unwrap()
            .unwrap();
        assert_eq!(result.0, transaction);
        assert_eq!(result.1, receipt);
        assert_eq!(result.2, header.hash);

        let invalid =
            super::transaction_with_receipt(&tx, transaction_hash_bytes!(b"invalid")).unwrap();
        assert_eq!(invalid, None);
    }

    #[test]
    fn transaction_at_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let idx = 5;
        let expected = Some(body[idx].0.clone());

        let by_number = super::transaction_at_block(&tx, header.number.into(), idx).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = super::transaction_at_block(&tx, header.hash.into(), idx).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = super::transaction_at_block(&tx, BlockId::Latest, idx).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_index =
            super::transaction_at_block(&tx, header.number.into(), body.len() + 1).unwrap();
        assert_eq!(invalid_index, None);

        let invalid_index = super::transaction_at_block(&tx, BlockNumber::MAX.into(), idx).unwrap();
        assert_eq!(invalid_index, None);
    }

    #[test]
    fn transaction_count() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let by_latest = super::transaction_count(&tx, BlockId::Latest).unwrap();
        assert_eq!(by_latest, body.len());
        let by_number = super::transaction_count(&tx, header.number.into()).unwrap();
        assert_eq!(by_number, body.len());
        let by_hash = super::transaction_count(&tx, header.hash.into()).unwrap();
        assert_eq!(by_hash, body.len());
    }

    #[test]
    fn transaction_data_for_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let expected = Some(body);

        let by_number = super::transaction_data_for_block(&tx, header.number.into()).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = super::transaction_data_for_block(&tx, header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = super::transaction_data_for_block(&tx, BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block =
            super::transaction_data_for_block(&tx, BlockNumber::MAX.into()).unwrap();
        assert_eq!(invalid_block, None);
    }

    #[test]
    fn transactions_for_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let expected = Some(body.into_iter().map(|(t, _)| t).collect::<Vec<_>>());

        let by_number = super::transactions_for_block(&tx, header.number.into()).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = super::transactions_for_block(&tx, header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = super::transactions_for_block(&tx, BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block =
            super::transaction_data_for_block(&tx, BlockNumber::MAX.into()).unwrap();
        assert_eq!(invalid_block, None);
    }

    #[test]
    fn transaction_hashes_for_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let expected = Some(
            body.iter()
                .map(|(transaction, _)| transaction.hash)
                .collect(),
        );

        let by_number = super::transaction_hashes_for_block(&tx, header.number.into()).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = super::transaction_hashes_for_block(&tx, header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = super::transaction_hashes_for_block(&tx, BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block =
            super::transaction_hashes_for_block(&tx, BlockNumber::MAX.into()).unwrap();
        assert_eq!(invalid_block, None);
    }

    #[test]
    fn transaction_block_hash() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let target = body.first().unwrap().0.hash;
        let valid = super::transaction_block_hash(&tx, target).unwrap().unwrap();
        assert_eq!(valid, header.hash);

        let invalid =
            super::transaction_block_hash(&tx, transaction_hash_bytes!(b"invalid hash")).unwrap();
        assert_eq!(invalid, None);
    }
}
