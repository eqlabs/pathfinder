use std::{
    mem,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use rusqlite::params;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("migrating starknet_transactions to new format");

    let mut transformers = Vec::new();
    let (insert_tx, insert_rx) = mpsc::channel();
    let (transform_tx, transform_rx) =
        flume::unbounded::<(Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>)>();
    for _ in 0..thread::available_parallelism().unwrap().get() {
        let insert_tx = insert_tx.clone();
        let transform_rx = transform_rx.clone();
        let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
        let transformer = thread::spawn(move || {
            for (hash, idx, block_hash, transaction, receipt) in transform_rx.iter() {
                // Load old DTOs.
                let transaction = zstd::decode_all(transaction.as_slice())
                    .context("Decompressing transaction")
                    .unwrap();
                let transaction: old_dto::Transaction = serde_json::from_slice(&transaction)
                    .context("Deserializing transaction")
                    .unwrap();
                let transaction = pathfinder_common::transaction::Transaction::from(transaction);
                let receipt = zstd::decode_all(receipt.as_slice())
                    .context("Decompressing receipt")
                    .unwrap();
                let mut receipt: old_dto::Receipt = serde_json::from_slice(&receipt)
                    .context("Deserializing receipt")
                    .unwrap();
                let events = mem::take(&mut receipt.events);
                if receipt.actual_fee.is_none() {
                    panic!("receipt with no fee {receipt:?}");
                }
                let receipt = pathfinder_common::receipt::Receipt::from(receipt);

                // Serialize into new DTOs.
                let transaction = crate::transaction::dto::Transaction::from(&transaction);
                let transaction =
                    bincode::serde::encode_to_vec(transaction, bincode::config::standard())
                        .context("Serializing transaction")
                        .unwrap();
                let transaction = compressor
                    .compress(&transaction)
                    .context("Compressing transaction")
                    .unwrap();
                let receipt = crate::transaction::dto::Receipt::from(&receipt);
                let receipt = bincode::serde::encode_to_vec(receipt, bincode::config::standard())
                    .context("Serializing receipt")
                    .unwrap();
                let receipt = compressor
                    .compress(&receipt)
                    .context("Compressing receipt")
                    .unwrap();
                let events = bincode::serde::encode_to_vec(
                    crate::transaction::dto::Events::V0 {
                        events: events.into_iter().map(Into::into).collect(),
                    },
                    bincode::config::standard(),
                )
                .context("Serializing events")
                .unwrap();
                let events = compressor
                    .compress(&events)
                    .context("Compressing events")
                    .unwrap();

                // Store the updated values.
                if let Err(err) =
                    insert_tx.send((hash, idx, block_hash, transaction, receipt, events))
                {
                    panic!("Failed to send transaction: {:?}", err);
                }
            }
        });
        transformers.push(transformer);
    }

    let mut progress_logged = Instant::now();
    const LOG_RATE: Duration = Duration::from_secs(10);

    let count = tx.query_row("SELECT COUNT(*) FROM starknet_transactions", [], |row| {
        row.get::<_, i64>(0)
    })?;
    tx.execute(
        r"
        CREATE TABLE starknet_transactions_new (
            hash        BLOB PRIMARY KEY,
            idx         INTEGER NOT NULL,
            block_hash  BLOB NOT NULL,
            tx          BLOB,
            receipt     BLOB,
            events      BLOB
        )",
        [],
    )
    .context("Creating starknet_transactions_new table")?;
    let mut query_stmt =
        tx.prepare("SELECT hash, idx, block_hash, tx, receipt FROM starknet_transactions")?;
    let mut insert_stmt = tx.prepare(
        r"INSERT INTO starknet_transactions_new (hash, idx, block_hash, tx, receipt, events)
                                         VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    const BATCH_SIZE: usize = 10_000;
    let mut rows = query_stmt.query([])?;
    let mut progress = 0;
    loop {
        if progress_logged.elapsed() > LOG_RATE {
            progress_logged = Instant::now();
            tracing::info!(
                "Migrating rows: {:.2}%",
                (progress as f64 / count as f64) * 100.0
            );
        }

        let mut batch_size = 0;
        for _ in 0..BATCH_SIZE {
            match rows.next() {
                Ok(Some(row)) => {
                    let hash = row.get_ref_unwrap("hash").as_blob()?;
                    let idx = row.get_ref_unwrap("idx").as_i64()?;
                    let block_hash = row.get_ref_unwrap("block_hash").as_blob()?;
                    let transaction = row.get_ref_unwrap("tx").as_blob()?;
                    let receipt = row.get_ref_unwrap("receipt").as_blob()?;
                    transform_tx
                        .send((
                            hash.to_vec(),
                            idx,
                            block_hash.to_vec(),
                            transaction.to_vec(),
                            receipt.to_vec(),
                        ))
                        .context("Sending transaction to transformer")?;
                    batch_size += 1;
                }
                Ok(None) => break,
                Err(err) => return Err(err.into()),
            }
        }
        for _ in 0..batch_size {
            let (hash, idx, block_hash, transaction, receipt, events) = insert_rx.recv()?;
            insert_stmt.execute(params![hash, idx, block_hash, transaction, receipt, events])?;
            progress += 1;
        }
        if batch_size < BATCH_SIZE {
            // This was the last batch.
            break;
        }
    }

    drop(insert_tx);
    drop(transform_tx);

    // Ensure that all transformers have finished successfully.
    for transformer in transformers {
        transformer.join().unwrap();
    }

    tracing::info!("Dropping old starknet_transactions table");
    tx.execute("DROP TABLE starknet_transactions", [])?;
    tracing::info!("Renaming starknet_transactions_new to starknet_transactions");
    tx.execute(
        "ALTER TABLE starknet_transactions_new RENAME TO starknet_transactions",
        [],
    )?;
    Ok(())
}

pub(crate) mod old_dto {
    use fake::{Dummy, Fake, Faker};
    use pathfinder_common::*;
    use pathfinder_crypto::Felt;
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

    impl From<&ExecutionResources> for pathfinder_common::receipt::ExecutionResources {
        fn from(value: &ExecutionResources) -> Self {
            Self {
                builtins: value.builtin_instance_counter.into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
                data_availability: match (value.l1_gas, value.l1_data_gas) {
                    (Some(l1_gas), Some(l1_data_gas)) => {
                        pathfinder_common::receipt::ExecutionDataAvailability {
                            l1_gas,
                            l1_data_gas,
                        }
                    }
                    _ => Default::default(),
                },
            }
        }
    }

    impl From<&pathfinder_common::receipt::ExecutionResources> for ExecutionResources {
        fn from(value: &pathfinder_common::receipt::ExecutionResources) -> Self {
            Self {
                builtin_instance_counter: (&value.builtins).into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
                l1_gas: Some(value.data_availability.l1_gas),
                l1_data_gas: Some(value.data_availability.l1_data_gas),
            }
        }
    }

    impl<T> Dummy<T> for ExecutionResources {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let (l1_gas, l1_data_gas) = if rng.gen() {
                (Some(rng.next_u32() as u128), Some(rng.next_u32() as u128))
            } else {
                (None, None)
            };

            Self {
                builtin_instance_counter: Faker.fake_with_rng(rng),
                n_steps: rng.next_u32() as u64,
                n_memory_holes: rng.next_u32() as u64,
                l1_gas,
                l1_data_gas,
            }
        }
    }

    // This struct purposefully allows for unknown fields as it is not critical to
    // store these counters perfectly. Failure would be far more costly than simply
    // ignoring them.
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
                output: output_builtin,
                pedersen: pedersen_builtin,
                range_check: range_check_builtin,
                ecdsa: ecdsa_builtin,
                bitwise: bitwise_builtin,
                ec_op: ec_op_builtin,
                keccak: keccak_builtin,
                poseidon: poseidon_builtin,
                segment_arena: segment_arena_builtin,
            }
        }
    }

    impl From<&pathfinder_common::receipt::BuiltinCounters> for BuiltinCounters {
        fn from(value: &pathfinder_common::receipt::BuiltinCounters) -> Self {
            // Use deconstruction to ensure these structs remain in-sync.
            let pathfinder_common::receipt::BuiltinCounters {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
            } = value.clone();
            Self {
                output_builtin: output,
                pedersen_builtin: pedersen,
                range_check_builtin: range_check,
                ecdsa_builtin: ecdsa,
                bitwise_builtin: bitwise,
                ec_op_builtin: ec_op,
                keccak_builtin: keccak,
                poseidon_builtin: poseidon,
                segment_arena_builtin: segment_arena,
            }
        }
    }

    impl<T> Dummy<T> for BuiltinCounters {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                output_builtin: rng.next_u32() as u64,
                pedersen_builtin: rng.next_u32() as u64,
                range_check_builtin: rng.next_u32() as u64,
                ecdsa_builtin: rng.next_u32() as u64,
                bitwise_builtin: rng.next_u32() as u64,
                ec_op_builtin: rng.next_u32() as u64,
                keccak_builtin: rng.next_u32() as u64,
                poseidon_builtin: rng.next_u32() as u64,
                segment_arena_builtin: 0, // Not used in p2p
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
                actual_fee: Some(value.actual_fee),
                events: vec![],
                execution_resources: Some((&value.execution_resources).into()),
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
                events: _,
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
                actual_fee: actual_fee.unwrap_or_default(),
                execution_resources: (&execution_resources.unwrap_or_default()).into(),
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

    impl<T> Dummy<T> for Receipt {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let execution_status = Faker.fake_with_rng(rng);
            let revert_error =
                (execution_status == ExecutionStatus::Reverted).then(|| Faker.fake_with_rng(rng));

            // Those fields that were missing in very old receipts are always present
            Self {
                actual_fee: Some(Faker.fake_with_rng(rng)),
                execution_resources: Some(Faker.fake_with_rng(rng)),
                events: Faker.fake_with_rng(rng),
                l1_to_l2_consumed_message: Faker.fake_with_rng(rng),
                l2_to_l1_messages: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
                transaction_index: Faker.fake_with_rng(rng),
                execution_status,
                revert_error,
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
                DeployAccountV1(DeployAccountTransactionV1 {
                    contract_address,
                    max_fee,
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
                        version: TransactionVersion::ONE,
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
                )) if version.without_query_version()
                    == TransactionVersion::ONE.without_query_version() =>
                {
                    TransactionVariant::DeployAccountV1(
                        pathfinder_common::transaction::DeployAccountTransactionV1 {
                            contract_address,
                            max_fee,
                            signature,
                            nonce,
                            contract_address_salt,
                            constructor_calldata,
                            class_hash,
                        },
                    )
                }
                Transaction::DeployAccount(DeployAccountTransaction::V0V1(
                    DeployAccountTransactionV0V1 { version, .. },
                )) => panic!("unexpected version for DeployAccountV0V1: {version:?}"),
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

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for DeclareTransaction {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            match rng.gen_range(0..=3) {
                0 => {
                    let mut v0: DeclareTransactionV0V1 = Faker.fake_with_rng(rng);
                    v0.nonce = TransactionNonce::ZERO;
                    Self::V0(v0)
                }
                1 => Self::V1(Faker.fake_with_rng(rng)),
                2 => Self::V2(Faker.fake_with_rng(rng)),
                3 => Self::V3(Faker.fake_with_rng(rng)),
                _ => unreachable!(),
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for DeclareTransactionV3 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                class_hash: Faker.fake_with_rng(rng),

                nonce: Faker.fake_with_rng(rng),
                nonce_data_availability_mode: Faker.fake_with_rng(rng),
                fee_data_availability_mode: Faker.fake_with_rng(rng),
                resource_bounds: Faker.fake_with_rng(rng),
                tip: Faker.fake_with_rng(rng),
                paymaster_data: vec![Faker.fake_with_rng(rng)], // TODO p2p allows 1 elem only

                sender_address: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
                compiled_class_hash: Faker.fake_with_rng(rng),
                account_deployment_data: vec![Faker.fake_with_rng(rng)], // TODO p2p allows 1 elem only
            }
        }
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
        pub transaction_hash: TransactionHash,
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,
    }

    impl<T> Dummy<T> for DeployTransaction {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                version: TransactionVersion(Felt::from_u64(rng.gen_range(0..=1))),
                contract_address: ContractAddress::ZERO, // Faker.fake_with_rng(rng), FIXME
                contract_address_salt: Faker.fake_with_rng(rng),
                class_hash: Faker.fake_with_rng(rng),
                constructor_calldata: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
            }
        }
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for DeployAccountTransactionV0V1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let contract_address_salt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<CallParam> = Faker.fake_with_rng(rng);
            let class_hash = Faker.fake_with_rng(rng);

            Self {
                version: TransactionVersion::ONE,
                contract_address: ContractAddress::deployed_contract_address(
                    constructor_calldata.iter().copied(),
                    &contract_address_salt,
                    &class_hash,
                ),
                transaction_hash: Faker.fake_with_rng(rng),
                max_fee: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
                nonce: Faker.fake_with_rng(rng),
                contract_address_salt,
                constructor_calldata,
                class_hash,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for DeployAccountTransactionV3 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let contract_address_salt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<CallParam> = Faker.fake_with_rng(rng);
            let class_hash = Faker.fake_with_rng(rng);

            Self {
                nonce: Faker.fake_with_rng(rng),
                nonce_data_availability_mode: Faker.fake_with_rng(rng),
                fee_data_availability_mode: Faker.fake_with_rng(rng),
                resource_bounds: Faker.fake_with_rng(rng),
                tip: Faker.fake_with_rng(rng),
                paymaster_data: vec![Faker.fake_with_rng(rng)], // TODO p2p allows 1 elem only

                sender_address: ContractAddress::deployed_contract_address(
                    constructor_calldata.iter().copied(),
                    &contract_address_salt,
                    &class_hash,
                ),
                signature: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
                version: TransactionVersion::THREE,
                contract_address_salt,
                constructor_calldata,
                class_hash,
            }
        }
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for InvokeTransactionV0 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                calldata: Faker.fake_with_rng(rng),
                sender_address: Faker.fake_with_rng(rng),
                entry_point_selector: Faker.fake_with_rng(rng),
                entry_point_type: None,
                max_fee: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
            }
        }
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for InvokeTransactionV3 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                nonce: Faker.fake_with_rng(rng),
                nonce_data_availability_mode: Faker.fake_with_rng(rng),
                fee_data_availability_mode: Faker.fake_with_rng(rng),
                resource_bounds: Faker.fake_with_rng(rng),
                tip: Faker.fake_with_rng(rng),
                paymaster_data: vec![Faker.fake_with_rng(rng)], // TODO p2p allows 1 elem only

                sender_address: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
                calldata: Faker.fake_with_rng(rng),
                account_deployment_data: vec![Faker.fake_with_rng(rng)], // TODO p2p allows 1 elem only
            }
        }
    }

    /// Represents deserialized L2 "L1 handler" transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

    impl<T> Dummy<T> for L1HandlerTransaction {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                // TODO verify this is the only realistic value
                version: TransactionVersion::ZERO,

                contract_address: Faker.fake_with_rng(rng),
                entry_point_selector: Faker.fake_with_rng(rng),
                nonce: Faker.fake_with_rng(rng),
                calldata: Faker.fake_with_rng(rng),
                transaction_hash: Faker.fake_with_rng(rng),
            }
        }
    }

    /// Describes L2 transaction failure details.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
    }
}
