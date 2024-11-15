//! Contains starknet transaction related code and __not__ database transaction.

use anyhow::Context;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction as StarknetTransaction;
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash};

use super::{EventsForBlock, TransactionDataForBlock, TransactionWithReceipt};
use crate::prelude::*;
use crate::BlockId;

pub(crate) mod compression {
    use std::sync::LazyLock;

    /// Compression level to use.
    ///
    /// Note that our dictionaries are optimized to be used with level 10.
    const ZSTD_COMPRESSION_LEVEL: i32 = 10;

    /// The maximum allowed uncompressed size of a serialized blob of
    /// transactions.
    const MAX_TRANSACTIONS_UNCOMPRESSED_SIZE: usize = 128usize * 1024 * 1024;
    /// The maximum allowed uncompressed size of a serialized blob of events.
    const MAX_EVENTS_UNCOMPRESSED_SIZE: usize = 128usize * 1024 * 1024;

    static ZSTD_TXS_ENCODER_DICTIONARY: LazyLock<zstd::dict::EncoderDictionary<'static>> =
        LazyLock::new(|| {
            zstd::dict::EncoderDictionary::new(
                include_bytes!("../assets/txs.zdict"),
                ZSTD_COMPRESSION_LEVEL,
            )
        });
    static ZSTD_EVENTS_ENCODER_DICTIONARY: LazyLock<zstd::dict::EncoderDictionary<'static>> =
        LazyLock::new(|| {
            zstd::dict::EncoderDictionary::new(
                include_bytes!("../assets/events.zdict"),
                ZSTD_COMPRESSION_LEVEL,
            )
        });

    static ZSTD_TXS_DECODER_DICTIONARY: LazyLock<zstd::dict::DecoderDictionary<'static>> =
        LazyLock::new(|| zstd::dict::DecoderDictionary::new(include_bytes!("../assets/txs.zdict")));
    static ZSTD_EVENTS_DECODER_DICTIONARY: LazyLock<zstd::dict::DecoderDictionary<'static>> =
        LazyLock::new(|| {
            zstd::dict::DecoderDictionary::new(include_bytes!("../assets/events.zdict"))
        });

    pub(super) fn compress_transactions(input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut compressor = new_txs_compressor()?;
        compressor.compress(input)
    }

    pub(crate) fn new_txs_compressor() -> std::io::Result<zstd::bulk::Compressor<'static>> {
        zstd::bulk::Compressor::with_prepared_dictionary(&ZSTD_TXS_ENCODER_DICTIONARY)
    }

    pub(super) fn compress_events(input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut compressor = new_events_compressor()?;
        compressor.compress(input)
    }

    pub(crate) fn new_events_compressor() -> std::io::Result<zstd::bulk::Compressor<'static>> {
        zstd::bulk::Compressor::with_prepared_dictionary(&ZSTD_EVENTS_ENCODER_DICTIONARY)
    }

    pub(crate) fn decompress_transactions(input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut decompressor = new_txs_decompressor()?;
        decompressor.decompress(input, MAX_TRANSACTIONS_UNCOMPRESSED_SIZE)
    }

    fn new_txs_decompressor() -> std::io::Result<zstd::bulk::Decompressor<'static>> {
        zstd::bulk::Decompressor::with_prepared_dictionary(&ZSTD_TXS_DECODER_DICTIONARY)
    }

    pub(crate) fn decompress_events(input: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut decompressor = new_events_decompressor()?;
        decompressor.decompress(input, MAX_EVENTS_UNCOMPRESSED_SIZE)
    }

    fn new_events_decompressor() -> std::io::Result<zstd::bulk::Decompressor<'static>> {
        zstd::bulk::Decompressor::with_prepared_dictionary(&ZSTD_EVENTS_DECODER_DICTIONARY)
    }
}

type TransactionsAndEventsByBlock = (Vec<(StarknetTransaction, Receipt)>, Vec<Vec<Event>>);
type TransactionAndEventsByHash = (
    BlockNumber,
    StarknetTransaction,
    Receipt,
    Option<Vec<Event>>,
);

impl Transaction<'_> {
    /// Inserts the transaction, receipt and event data.
    pub fn insert_transaction_data(
        &self,
        block_number: BlockNumber,
        transactions: &[(StarknetTransaction, Receipt)],
        events: Option<&[Vec<Event>]>,
    ) -> anyhow::Result<()> {
        if transactions.is_empty() && events.map_or(true, |x| x.is_empty()) {
            // Advance the running event bloom filter even if there's nothing to add since
            // it requires that no blocks are skipped.
            #[cfg(feature = "aggregate_bloom")]
            self.upsert_block_events_aggregate(block_number, std::iter::empty())?;
            return Ok(());
        }

        let mut insert_transaction_stmt = self
            .inner()
            .prepare_cached(
                "INSERT INTO transactions (block_number, transactions, events) VALUES \
                 (:block_number, :transactions, :events)",
            )
            .context("Preparing insert transaction statement")?;
        let mut insert_transaction_hash_stmt = self
            .inner()
            .prepare_cached(
                "INSERT INTO transaction_hashes (hash, block_number, idx) VALUES (:hash, \
                 :block_number, :idx)",
            )
            .context("Preparing insert transaction hash statement")?;

        for (idx, (transaction, ..)) in transactions.iter().enumerate() {
            let idx: i64 = idx.try_into()?;
            insert_transaction_hash_stmt.execute(named_params![
                ":hash": &transaction.hash,
                ":block_number": &block_number,
                ":idx": &idx,
            ])?;
        }
        let transactions_with_receipts: Vec<_> = transactions
            .iter()
            .map(|(transaction, receipt)| dto::TransactionWithReceiptV2 {
                transaction: dto::TransactionV1::from(transaction),
                receipt: receipt.into(),
            })
            .collect();
        let transactions_with_receipts = dto::TransactionsWithReceiptsForBlock::V2 {
            transactions_with_receipts,
        };
        let transactions_with_receipts =
            bincode::serde::encode_to_vec(transactions_with_receipts, bincode::config::standard())
                .context("Serializing transaction")?;
        let transactions_with_receipts =
            compression::compress_transactions(&transactions_with_receipts)
                .context("Compressing transaction")?;

        let encoded_events = match events {
            Some(events) => {
                let events = dto::EventsForBlock::V0 {
                    events: events
                        .iter()
                        .map(|events| events.iter().cloned().map(Into::into).collect())
                        .collect(),
                };
                let events = bincode::serde::encode_to_vec(events, bincode::config::standard())
                    .context("Serializing events")?;
                Some(compression::compress_events(&events).context("Compressing events")?)
            }
            None => None,
        };

        insert_transaction_stmt
            .execute(named_params![
                ":block_number": &block_number,
                ":transactions": &transactions_with_receipts,
                ":events": &encoded_events,
            ])
            .context("Inserting transaction data")?;

        #[cfg(feature = "aggregate_bloom")]
        {
            let events = events.unwrap_or_default().iter().flatten();
            self.upsert_block_events_aggregate(block_number, events)
                .context("Inserting events into Bloom filter aggregate")?;
        }

        if let Some(events) = events {
            let events = events.iter().flatten();
            self.upsert_block_events(block_number, events)
                .context("Inserting events into Bloom filter")?;
        }

        Ok(())
    }

    pub fn update_events(
        &self,
        block_number: BlockNumber,
        events: Vec<Vec<Event>>,
    ) -> anyhow::Result<()> {
        let mut stmt = self
            .inner()
            .prepare_cached(
                r"
                UPDATE transactions
                SET events = :events
                WHERE block_number = :block_number
                ",
            )
            .context("Preparing update events statement")?;

        let encoded_events = dto::EventsForBlock::V0 {
            events: events
                .iter()
                .cloned()
                .map(|events| events.into_iter().map(Into::into).collect())
                .collect(),
        };
        let encoded_events =
            bincode::serde::encode_to_vec(encoded_events, bincode::config::standard())
                .context("Serializing events")?;
        let encoded_events =
            compression::compress_events(&encoded_events).context("Compressing events")?;

        stmt.execute(named_params![
            ":block_number": &block_number,
            ":events": &encoded_events,
        ])
        .context("Updating events")?;

        #[cfg(feature = "aggregate_bloom")]
        {
            let events = events.iter().flatten();
            self.upsert_block_events_aggregate(block_number, events)
                .context("Inserting events into Bloom filter aggregate")?;
        }
        self.upsert_block_events(block_number, events.iter().flatten())
            .context("Inserting events into Bloom filter")?;

        Ok(())
    }

    pub fn transaction(
        &self,
        transaction: TransactionHash,
    ) -> anyhow::Result<Option<StarknetTransaction>> {
        let Some((_, transaction, _)) = self.query_transaction_by_hash(transaction)? else {
            return Ok(None);
        };
        Ok(Some(transaction))
    }

    pub fn transaction_with_receipt(
        &self,
        txn_hash: TransactionHash,
    ) -> anyhow::Result<Option<TransactionWithReceipt>> {
        let Some((block_number, transaction, receipt, events)) =
            self.query_transaction_and_events_by_hash(txn_hash)?
        else {
            return Ok(None);
        };
        let events = events.context("Events missing")?;
        Ok(Some((transaction, receipt, events, block_number)))
    }

    pub fn transaction_at_block(
        &self,
        block: BlockId,
        index: usize,
    ) -> anyhow::Result<Option<StarknetTransaction>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };
        Ok(self
            .query_transactions_by_block(block_number)?
            .get(index)
            .map(|(transaction, ..)| transaction.clone()))
    }

    pub fn transaction_count(&self, block: BlockId) -> anyhow::Result<usize> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(0);
        };
        Ok(self.query_transactions_by_block(block_number)?.len())
    }

    pub fn transaction_data_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<TransactionDataForBlock>>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };

        let (transactions, events) = self.query_transactions_and_events_by_block(block_number)?;

        Ok(Some(
            transactions
                .into_iter()
                .zip(events)
                .map(|((transaction, receipt), events)| (transaction, receipt, events))
                .collect(),
        ))
    }

    pub fn transactions_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<StarknetTransaction>>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };

        Ok(Some(
            self.query_transactions_by_block(block_number)?
                .into_iter()
                .map(|(transaction, ..)| transaction)
                .collect(),
        ))
    }

    pub fn transactions_with_receipts_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<(StarknetTransaction, Receipt)>>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };

        Ok(Some(
            self.query_transactions_by_block(block_number)?
                .into_iter()
                .map(|(t, r, ..)| (t, r))
                .collect(),
        ))
    }

    pub fn events_for_block(&self, block: BlockId) -> anyhow::Result<Option<Vec<EventsForBlock>>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };

        let Some(events) = self.query_events_by_block(block_number)? else {
            return Ok(None);
        };

        let transaction_hashes = self
            .query_transaction_hashes_by_block(block_number)
            .context("Querying transaction hashes")?;

        if events.len() != transaction_hashes.len() {
            anyhow::bail!("Event list and transaction list mismatch");
        }

        Ok(Some(
            events
                .into_iter()
                .zip(transaction_hashes)
                .map(|(events, transaction_hash)| (transaction_hash, events))
                .collect(),
        ))
    }

    pub fn transaction_hashes_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<TransactionHash>>> {
        let Some(block_number) = self.block_number(block)? else {
            return Ok(None);
        };

        let transactions = self.query_transaction_hashes_by_block(block_number)?;

        Ok(Some(transactions))
    }

    pub fn transaction_block_hash(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<BlockHash>> {
        self.inner()
            .query_row(
                r"
                SELECT block_headers.hash FROM transaction_hashes
                JOIN block_headers ON transaction_hashes.block_number = block_headers.number
                WHERE transaction_hashes.hash = ?
                ",
                params![&hash],
                |row| row.get_block_hash(0),
            )
            .optional()
            .map_err(|e| e.into())
    }

    fn query_transactions_by_block(
        &self,
        block_number: BlockNumber,
    ) -> anyhow::Result<Vec<(StarknetTransaction, Receipt)>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT transactions
            FROM transactions
            WHERE block_number = ?
            ",
        )?;
        let mut rows = stmt.query(params![&block_number])?;
        let Some(row) = rows.next()? else {
            return Ok(vec![]);
        };
        let transactions = row.get_blob(0)?;
        let transactions = compression::decompress_transactions(transactions)
            .context("Decompressing transactions")?;
        let transactions: dto::TransactionsWithReceiptsForBlock =
            bincode::serde::decode_from_slice(&transactions, bincode::config::standard())
                .context("Deserializing transactions")?
                .0;
        let transactions = transactions.transactions_with_receipts();

        Ok(transactions
            .into_iter()
            .map(
                |dto::TransactionWithReceiptV2 {
                     transaction,
                     receipt,
                 }| { (transaction.into(), receipt.into()) },
            )
            .collect())
    }

    fn query_transaction_hashes_by_block(
        &self,
        block_number: BlockNumber,
    ) -> anyhow::Result<Vec<TransactionHash>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT hash
            FROM transaction_hashes
            WHERE block_number = ? ORDER BY idx
            ",
        )?;
        let transaction_hashes: Result<Vec<_>, _> = stmt
            .query_map(params![&block_number], |row| row.get_transaction_hash(0))
            .context("Querying transaction hashes for block")?
            .collect();
        let transaction_hashes = transaction_hashes?;

        Ok(transaction_hashes)
    }

    fn query_transactions_and_events_by_block(
        &self,
        block_number: BlockNumber,
    ) -> anyhow::Result<TransactionsAndEventsByBlock> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT transactions, events
            FROM transactions
            WHERE block_number = ?
            ",
        )?;
        let mut rows = stmt.query(params![&block_number])?;
        let Some(row) = rows.next()? else {
            return Ok((vec![], vec![]));
        };
        let transactions = row.get_blob(0)?;
        let transactions = compression::decompress_transactions(transactions)
            .context("Decompressing transactions")?;
        let transactions: dto::TransactionsWithReceiptsForBlock =
            bincode::serde::decode_from_slice(&transactions, bincode::config::standard())
                .context("Deserializing transactions")?
                .0;
        let transactions = transactions.transactions_with_receipts();
        let events: Option<dto::EventsForBlock> = match row.get_optional_blob(1)? {
            Some(events) => {
                let events =
                    compression::decompress_events(events).context("Decompressing events")?;
                Some(
                    bincode::serde::decode_from_slice(&events, bincode::config::standard())
                        .context("Deserializing events")?
                        .0,
                )
            }
            None => None,
        };
        let events = events.map(|events| match events {
            dto::EventsForBlock::V0 { events } => events,
        });
        Ok((
            transactions
                .into_iter()
                .map(
                    |dto::TransactionWithReceiptV2 {
                         transaction,
                         receipt,
                     }| { (transaction.into(), receipt.into()) },
                )
                .collect(),
            events
                .map(|events| {
                    events
                        .into_iter()
                        .map(|e| e.into_iter().map(Into::into).collect())
                        .collect()
                })
                .unwrap_or_default(),
        ))
    }

    fn query_events_by_block(
        &self,
        block_number: BlockNumber,
    ) -> anyhow::Result<Option<Vec<Vec<Event>>>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT events
            FROM transactions
            WHERE block_number = ?
            ",
        )?;
        let mut rows = stmt.query(params![&block_number])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let events: Option<dto::EventsForBlock> = match row.get_optional_blob(0)? {
            Some(events) => {
                let events =
                    compression::decompress_events(events).context("Decompressing events")?;
                let events: dto::EventsForBlock =
                    bincode::serde::decode_from_slice(&events, bincode::config::standard())
                        .context("Deserializing events")?
                        .0;

                Some(events)
            }
            None => None,
        };
        let events = events.map(|e| e.events());

        Ok(events.map(|events| {
            events
                .into_iter()
                .map(|e| e.into_iter().map(Into::into).collect())
                .collect()
        }))
    }

    fn query_transaction_by_hash(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<(BlockNumber, StarknetTransaction, Receipt)>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT transactions.block_number, transactions, idx
            FROM transactions
            JOIN transaction_hashes ON transactions.block_number = transaction_hashes.block_number
            WHERE hash = ?
            ",
        )?;
        let mut rows = stmt.query(params![&hash])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let block_number = row.get_block_number(0)?;
        let transactions = row.get_blob(1)?;
        let idx: usize = row.get_i64(2)?.try_into()?;

        let transactions = compression::decompress_transactions(transactions)
            .context("Decompressing transactions")?;
        let transactions: dto::TransactionsWithReceiptsForBlock =
            bincode::serde::decode_from_slice(&transactions, bincode::config::standard())
                .context("Deserializing transactions")?
                .0;
        let transactions = transactions.transactions_with_receipts();
        let dto::TransactionWithReceiptV2 {
            transaction,
            receipt,
        } = transactions.get(idx).context("Transaction not found")?;

        Ok(Some((
            block_number,
            transaction.clone().into(),
            receipt.clone().into(),
        )))
    }

    fn query_transaction_and_events_by_hash(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<TransactionAndEventsByHash>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT transactions.block_number, transactions, events, idx
            FROM transactions
            JOIN transaction_hashes ON transactions.block_number = transaction_hashes.block_number
            WHERE hash = ?
            ",
        )?;
        let mut rows = stmt.query(params![&hash])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let block_number = row.get_block_number(0)?;
        let idx: usize = row.get_i64(3)?.try_into()?;
        let transactions = row.get_blob(1)?;

        let transactions = compression::decompress_transactions(transactions)
            .context("Decompressing transactions")?;
        let transactions: dto::TransactionsWithReceiptsForBlock =
            bincode::serde::decode_from_slice(&transactions, bincode::config::standard())
                .context("Deserializing transactions")?
                .0;
        let transactions = transactions.transactions_with_receipts();

        let events: Option<Vec<Vec<dto::Event>>> = match row.get_optional_blob(2)? {
            Some(events) => {
                let events =
                    compression::decompress_events(events).context("Decompressing events")?;
                let events: dto::EventsForBlock =
                    bincode::serde::decode_from_slice(&events, bincode::config::standard())
                        .context("Deserializing events")?
                        .0;
                Some(events.events())
            }
            None => None,
        };
        let dto::TransactionWithReceiptV2 {
            transaction,
            receipt,
        } = transactions.get(idx).context("Transaction not found")?;
        let events = match events {
            Some(events) => {
                let events = events.get(idx).context("Events missing")?;
                Some(events.iter().cloned().map(Into::into).collect())
            }
            None => None,
        };
        Ok(Some((
            block_number,
            transaction.clone().into(),
            receipt.clone().into(),
            events,
        )))
    }
}

pub(crate) mod dto {
    use std::fmt;

    use fake::{Dummy, Fake, Faker};
    use pathfinder_common::*;
    use pathfinder_crypto::Felt;
    use serde::{Deserialize, Serialize};

    /// Minimally encoded Felt value.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct MinimalFelt(Felt);

    impl serde::Serialize for MinimalFelt {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let bytes = self.0.as_be_bytes();
            let zeros = bytes.iter().take_while(|&&x| x == 0).count();
            bytes[zeros..].serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for MinimalFelt {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = MinimalFelt;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a sequence")
                }

                fn visit_seq<B>(self, mut seq: B) -> Result<Self::Value, B::Error>
                where
                    B: serde::de::SeqAccess<'de>,
                {
                    let len = seq.size_hint().unwrap();
                    let mut bytes = [0; 32];
                    let num_zeros = bytes.len() - len;
                    let mut i = num_zeros;
                    while let Some(value) = seq.next_element()? {
                        bytes[i] = value;
                        i += 1;
                    }
                    Ok(MinimalFelt(Felt::from_be_bytes(bytes).unwrap()))
                }
            }

            deserializer.deserialize_seq(Visitor)
        }
    }

    impl From<Felt> for MinimalFelt {
        fn from(value: Felt) -> Self {
            Self(value)
        }
    }

    impl From<MinimalFelt> for Felt {
        fn from(value: MinimalFelt) -> Self {
            value.0
        }
    }

    impl<T> Dummy<T> for MinimalFelt {
        fn dummy_with_rng<R: rand::prelude::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
            let felt: Felt = Dummy::dummy_with_rng(config, rng);
            felt.into()
        }
    }

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        External,
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

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EventsForBlock {
        V0 { events: Vec<Vec<Event>> },
    }

    impl EventsForBlock {
        pub fn events(self) -> Vec<Vec<Event>> {
            match self {
                EventsForBlock::V0 { events } => events,
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        pub data: Vec<MinimalFelt>,
        pub from_address: MinimalFelt,
        pub keys: Vec<MinimalFelt>,
    }

    impl From<pathfinder_common::event::Event> for Event {
        fn from(value: pathfinder_common::event::Event) -> Self {
            let pathfinder_common::event::Event {
                data,
                from_address,
                keys,
            } = value;
            Self {
                data: data
                    .into_iter()
                    .map(|x| x.as_inner().to_owned().into())
                    .collect(),
                from_address: from_address.as_inner().to_owned().into(),
                keys: keys
                    .into_iter()
                    .map(|x| x.as_inner().to_owned().into())
                    .collect(),
            }
        }
    }

    impl From<Event> for pathfinder_common::event::Event {
        fn from(value: Event) -> Self {
            Self {
                data: value
                    .data
                    .into_iter()
                    .map(|x| EventData(x.into()))
                    .collect(),
                from_address: ContractAddress::new_or_panic(value.from_address.into()),
                keys: value.keys.into_iter().map(|x| EventKey(x.into())).collect(),
            }
        }
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResourcesV0 {
        pub builtins: BuiltinCountersV0,
        pub n_steps: u64,
        pub n_memory_holes: u64,
        pub data_availability: L1Gas,
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResourcesV1 {
        pub builtins: BuiltinCountersV1,
        pub n_steps: u64,
        pub n_memory_holes: u64,
        pub data_availability: L1Gas,
        pub total_gas_consumed: L1Gas,
    }

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1Gas {
        // TODO make these mandatory once some new release makes resyncing necessary
        pub l1_gas: Option<u128>,
        pub l1_data_gas: Option<u128>,
    }

    impl From<ExecutionResourcesV0> for ExecutionResourcesV1 {
        fn from(value: ExecutionResourcesV0) -> Self {
            Self {
                builtins: value.builtins.into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
                data_availability: value.data_availability,
                total_gas_consumed: Default::default(),
            }
        }
    }

    impl From<ExecutionResourcesV1> for pathfinder_common::receipt::ExecutionResources {
        fn from(value: ExecutionResourcesV1) -> Self {
            Self {
                builtins: value.builtins.into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
                data_availability: match (
                    value.data_availability.l1_gas,
                    value.data_availability.l1_data_gas,
                ) {
                    (Some(l1_gas), Some(l1_data_gas)) => pathfinder_common::receipt::L1Gas {
                        l1_gas,
                        l1_data_gas,
                    },
                    _ => Default::default(),
                },
                total_gas_consumed: match (
                    value.total_gas_consumed.l1_gas,
                    value.total_gas_consumed.l1_data_gas,
                ) {
                    (Some(l1_gas), Some(l1_data_gas)) => pathfinder_common::receipt::L1Gas {
                        l1_gas,
                        l1_data_gas,
                    },
                    _ => Default::default(),
                },
                l2_gas: Default::default(),
            }
        }
    }

    impl From<&pathfinder_common::receipt::ExecutionResources> for ExecutionResourcesV1 {
        fn from(value: &pathfinder_common::receipt::ExecutionResources) -> Self {
            Self {
                builtins: (&value.builtins).into(),
                n_steps: value.n_steps,
                n_memory_holes: value.n_memory_holes,
                data_availability: L1Gas {
                    l1_gas: Some(value.data_availability.l1_gas),
                    l1_data_gas: Some(value.data_availability.l1_data_gas),
                },
                total_gas_consumed: L1Gas {
                    l1_gas: Some(value.total_gas_consumed.l1_gas),
                    l1_data_gas: Some(value.total_gas_consumed.l1_data_gas),
                },
            }
        }
    }

    impl<T> Dummy<T> for ExecutionResourcesV0 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let (l1_gas, l1_data_gas) = if rng.gen() {
                (Some(rng.next_u32() as u128), Some(rng.next_u32() as u128))
            } else {
                (None, None)
            };

            Self {
                builtins: Faker.fake_with_rng(rng),
                n_steps: rng.next_u32() as u64,
                n_memory_holes: rng.next_u32() as u64,
                data_availability: L1Gas {
                    l1_gas,
                    l1_data_gas,
                },
            }
        }
    }

    impl<T> Dummy<T> for ExecutionResourcesV1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let (l1_gas, l1_data_gas) = if rng.gen() {
                (Some(rng.next_u32() as u128), Some(rng.next_u32() as u128))
            } else {
                (None, None)
            };

            Self {
                builtins: Faker.fake_with_rng(rng),
                n_steps: rng.next_u32() as u64,
                n_memory_holes: rng.next_u32() as u64,
                data_availability: L1Gas {
                    l1_gas,
                    l1_data_gas,
                },
                total_gas_consumed: L1Gas {
                    l1_gas: l1_gas.map(|x| x + rng.next_u32() as u128),
                    l1_data_gas: l1_data_gas.map(|x| x + rng.next_u32() as u128),
                },
            }
        }
    }

    #[derive(Copy, Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct BuiltinCountersV0 {
        pub output: u64,
        pub pedersen: u64,
        pub range_check: u64,
        pub ecdsa: u64,
        pub bitwise: u64,
        pub ec_op: u64,
        pub keccak: u64,
        pub poseidon: u64,
        pub segment_arena: u64,
    }

    #[derive(Copy, Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct BuiltinCountersV1 {
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

    impl From<BuiltinCountersV0> for BuiltinCountersV1 {
        fn from(value: BuiltinCountersV0) -> Self {
            // Use deconstruction to ensure these structs remain in-sync.
            let BuiltinCountersV0 {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
            } = value;
            Self {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
                ..Default::default()
            }
        }
    }

    impl From<BuiltinCountersV1> for pathfinder_common::receipt::BuiltinCounters {
        fn from(value: BuiltinCountersV1) -> Self {
            // Use deconstruction to ensure these structs remain in-sync.
            let BuiltinCountersV1 {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
                add_mod,
                mul_mod,
                range_check96,
            } = value;
            Self {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
                add_mod,
                mul_mod,
                range_check96,
            }
        }
    }

    impl From<&pathfinder_common::receipt::BuiltinCounters> for BuiltinCountersV1 {
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
                add_mod,
                mul_mod,
                range_check96,
            } = value.clone();
            Self {
                output,
                pedersen,
                range_check,
                ecdsa,
                bitwise,
                ec_op,
                keccak,
                poseidon,
                segment_arena,
                add_mod,
                mul_mod,
                range_check96,
            }
        }
    }

    impl<T> Dummy<T> for BuiltinCountersV0 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                output: rng.next_u32() as u64,
                pedersen: rng.next_u32() as u64,
                range_check: rng.next_u32() as u64,
                ecdsa: rng.next_u32() as u64,
                bitwise: rng.next_u32() as u64,
                ec_op: rng.next_u32() as u64,
                keccak: rng.next_u32() as u64,
                poseidon: rng.next_u32() as u64,
                segment_arena: 0, // Not used in p2p
            }
        }
    }

    impl<T> Dummy<T> for BuiltinCountersV1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                output: rng.next_u32() as u64,
                pedersen: rng.next_u32() as u64,
                range_check: rng.next_u32() as u64,
                ecdsa: rng.next_u32() as u64,
                bitwise: rng.next_u32() as u64,
                ec_op: rng.next_u32() as u64,
                keccak: rng.next_u32() as u64,
                poseidon: rng.next_u32() as u64,
                segment_arena: 0, // Not used in p2p
                add_mod: rng.next_u32() as u64,
                mul_mod: rng.next_u32() as u64,
                range_check96: rng.next_u32() as u64,
            }
        }
    }

    /// Represents deserialized L2 to L1 message.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct L2ToL1MessageV0 {
        pub from_address: MinimalFelt,
        pub payload: Vec<MinimalFelt>,
        pub to_address: EthereumAddress,
    }

    /// Represents deserialized L2 to L1 message.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L2ToL1MessageV1 {
        pub from_address: MinimalFelt,
        pub payload: Vec<MinimalFelt>,
        pub to_address: MinimalFelt,
    }

    impl<T> Dummy<T> for L2ToL1MessageV1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                from_address: Faker.fake_with_rng(rng),
                payload: fake::vec![MinimalFelt; 1..10],
                // Create a Felt using only 160 bits. This is required because p2p specification
                // uses the wrong type to represent this field.
                to_address: MinimalFelt(Felt::from_be_slice(&fake::vec![u8; 20]).unwrap()),
            }
        }
    }

    impl From<L2ToL1MessageV0> for L2ToL1MessageV1 {
        fn from(value: L2ToL1MessageV0) -> Self {
            Self {
                from_address: value.from_address,
                payload: value.payload,
                to_address: Felt::from_be_slice(value.to_address.0.as_bytes())
                    .expect("H160 will always fit into a Felt")
                    .into(),
            }
        }
    }

    impl From<L2ToL1MessageV1> for pathfinder_common::receipt::L2ToL1Message {
        fn from(value: L2ToL1MessageV1) -> Self {
            let L2ToL1MessageV1 {
                from_address,
                payload,
                to_address,
            } = value;
            pathfinder_common::receipt::L2ToL1Message {
                from_address: ContractAddress::new_or_panic(from_address.into()),
                payload: payload
                    .into_iter()
                    .map(|x| L2ToL1MessagePayloadElem(x.into()))
                    .collect(),
                to_address: ContractAddress::new_or_panic(to_address.into()),
            }
        }
    }

    impl From<&pathfinder_common::receipt::L2ToL1Message> for L2ToL1MessageV1 {
        fn from(value: &pathfinder_common::receipt::L2ToL1Message) -> Self {
            let pathfinder_common::receipt::L2ToL1Message {
                from_address,
                payload,
                to_address,
            } = value.clone();
            Self {
                from_address: from_address.as_inner().to_owned().into(),
                payload: payload
                    .into_iter()
                    .map(|x| x.as_inner().to_owned().into())
                    .collect(),
                to_address: to_address.as_inner().to_owned().into(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    pub enum ExecutionStatus {
        Succeeded,
        Reverted { reason: String },
    }

    /// Represents deserialized L2 transaction receipt data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct ReceiptV0 {
        pub actual_fee: MinimalFelt,
        pub execution_resources: Option<ExecutionResourcesV0>,
        pub l2_to_l1_messages: Vec<L2ToL1MessageV0>,
        pub transaction_hash: MinimalFelt,
        pub transaction_index: TransactionIndex,
        pub execution_status: ExecutionStatus,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct ReceiptV1 {
        pub actual_fee: MinimalFelt,
        pub execution_resources: Option<ExecutionResourcesV0>,
        pub l2_to_l1_messages: Vec<L2ToL1MessageV1>,
        pub transaction_hash: MinimalFelt,
        pub transaction_index: TransactionIndex,
        pub execution_status: ExecutionStatus,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct ReceiptV2 {
        pub actual_fee: MinimalFelt,
        pub execution_resources: Option<ExecutionResourcesV1>,
        pub l2_to_l1_messages: Vec<L2ToL1MessageV1>,
        pub transaction_hash: MinimalFelt,
        pub transaction_index: TransactionIndex,
        pub execution_status: ExecutionStatus,
    }

    impl From<ReceiptV0> for ReceiptV2 {
        fn from(value: ReceiptV0) -> Self {
            Self {
                actual_fee: value.actual_fee,
                execution_resources: value.execution_resources.map(Into::into),
                l2_to_l1_messages: value
                    .l2_to_l1_messages
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                transaction_hash: value.transaction_hash,
                transaction_index: value.transaction_index,
                execution_status: value.execution_status,
            }
        }
    }

    impl From<ReceiptV1> for ReceiptV2 {
        fn from(value: ReceiptV1) -> Self {
            Self {
                actual_fee: value.actual_fee,
                execution_resources: value.execution_resources.map(Into::into),
                l2_to_l1_messages: value
                    .l2_to_l1_messages
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                transaction_hash: value.transaction_hash,
                transaction_index: value.transaction_index,
                execution_status: value.execution_status,
            }
        }
    }

    impl From<ReceiptV2> for pathfinder_common::receipt::Receipt {
        fn from(value: ReceiptV2) -> Self {
            use pathfinder_common::receipt as common;

            let ReceiptV2 {
                actual_fee,
                execution_resources,
                // This information is redundant as it is already in the transaction itself.
                l2_to_l1_messages,
                transaction_hash,
                transaction_index,
                execution_status,
            } = value;

            common::Receipt {
                actual_fee: Fee(actual_fee.into()),
                execution_resources: execution_resources.unwrap_or_default().into(),
                l2_to_l1_messages: l2_to_l1_messages.into_iter().map(Into::into).collect(),
                transaction_hash: TransactionHash(transaction_hash.into()),
                transaction_index,
                execution_status: match execution_status {
                    ExecutionStatus::Succeeded => common::ExecutionStatus::Succeeded,
                    ExecutionStatus::Reverted { reason } => {
                        common::ExecutionStatus::Reverted { reason }
                    }
                },
            }
        }
    }

    impl From<&pathfinder_common::receipt::Receipt> for ReceiptV2 {
        fn from(value: &pathfinder_common::receipt::Receipt) -> Self {
            Self {
                actual_fee: value.actual_fee.as_inner().to_owned().into(),
                execution_resources: Some((&value.execution_resources).into()),
                l2_to_l1_messages: value.l2_to_l1_messages.iter().map(Into::into).collect(),
                transaction_hash: value.transaction_hash.as_inner().to_owned().into(),
                transaction_index: value.transaction_index,
                execution_status: match &value.execution_status {
                    receipt::ExecutionStatus::Succeeded => ExecutionStatus::Succeeded,
                    receipt::ExecutionStatus::Reverted { reason } => ExecutionStatus::Reverted {
                        reason: reason.clone(),
                    },
                },
            }
        }
    }

    #[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Dummy)]
    pub enum DataAvailabilityMode {
        L1,
        L2,
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
        pub l1_gas: ResourceBound,
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

    #[derive(Copy, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    pub struct ResourceBound {
        pub max_amount: ResourceAmount,
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

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum TransactionsWithReceiptsForBlock {
        V0 {
            transactions_with_receipts: Vec<TransactionWithReceiptV0>,
        },
        V1 {
            transactions_with_receipts: Vec<TransactionWithReceiptV1>,
        },
        V2 {
            transactions_with_receipts: Vec<TransactionWithReceiptV2>,
        },
    }

    impl TransactionsWithReceiptsForBlock {
        pub fn transactions_with_receipts(self) -> Vec<TransactionWithReceiptV2> {
            match self {
                TransactionsWithReceiptsForBlock::V0 {
                    transactions_with_receipts: v0,
                } => v0.into_iter().map(Into::into).collect(),
                TransactionsWithReceiptsForBlock::V1 {
                    transactions_with_receipts: v1,
                } => v1.into_iter().map(Into::into).collect(),
                TransactionsWithReceiptsForBlock::V2 {
                    transactions_with_receipts,
                } => transactions_with_receipts,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TransactionWithReceiptV0 {
        pub transaction: TransactionV0,
        pub receipt: ReceiptV0,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TransactionWithReceiptV1 {
        pub transaction: TransactionV1,
        pub receipt: ReceiptV1,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TransactionWithReceiptV2 {
        pub transaction: TransactionV1,
        pub receipt: ReceiptV2,
    }

    impl From<TransactionWithReceiptV0> for TransactionWithReceiptV2 {
        fn from(v0: TransactionWithReceiptV0) -> Self {
            Self {
                transaction: v0.transaction.into(),
                receipt: v0.receipt.into(),
            }
        }
    }

    impl From<TransactionWithReceiptV1> for TransactionWithReceiptV2 {
        fn from(v0: TransactionWithReceiptV1) -> Self {
            Self {
                transaction: v0.transaction,
                receipt: v0.receipt.into(),
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct TransactionV0 {
        hash: MinimalFelt,
        variant: TransactionVariantV0,
    }

    impl TransactionV0 {
        /// Returns hash of the transaction
        pub fn hash(&self) -> TransactionHash {
            TransactionHash(self.hash.to_owned().into())
        }
    }

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub enum TransactionVariantV0 {
        DeclareV0(DeclareTransactionV0V1),
        DeclareV1(DeclareTransactionV0V1),
        DeclareV2(DeclareTransactionV2),
        DeclareV3(DeclareTransactionV3),
        // FIXME regenesis: remove Deploy txn type after regenesis
        // We are keeping this type of transaction until regenesis
        // only to support older pre-0.11.0 blocks
        Deploy(DeployTransaction),
        DeployAccountV1(DeployAccountTransactionV1),
        DeployAccountV3(DeployAccountTransactionV3),
        InvokeV0(InvokeTransactionV0),
        InvokeV1(InvokeTransactionV1),
        InvokeV3(InvokeTransactionV3),
        L1HandlerV0(L1HandlerTransactionV0),
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct TransactionV1 {
        hash: MinimalFelt,
        variant: TransactionVariantV1,
    }

    impl TransactionV1 {
        /// Returns hash of the transaction
        pub fn hash(&self) -> TransactionHash {
            TransactionHash(self.hash.to_owned().into())
        }
    }

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub enum TransactionVariantV1 {
        DeclareV0(DeclareTransactionV0V1),
        DeclareV1(DeclareTransactionV0V1),
        DeclareV2(DeclareTransactionV2),
        DeclareV3(DeclareTransactionV3),
        // FIXME regenesis: remove Deploy txn type after regenesis
        // We are keeping this type of transaction until regenesis
        // only to support older pre-0.11.0 blocks
        DeployV0(DeployTransactionV0),
        DeployV1(DeployTransactionV1),
        DeployAccountV1(DeployAccountTransactionV1),
        DeployAccountV3(DeployAccountTransactionV3),
        InvokeV0(InvokeTransactionV0),
        InvokeV1(InvokeTransactionV1),
        InvokeV3(InvokeTransactionV3),
        L1HandlerV0(L1HandlerTransactionV0),
    }

    impl From<TransactionVariantV0> for TransactionVariantV1 {
        fn from(value: TransactionVariantV0) -> Self {
            match value {
                TransactionVariantV0::DeclareV0(tx) => Self::DeclareV0(tx),
                TransactionVariantV0::DeclareV1(tx) => Self::DeclareV1(tx),
                TransactionVariantV0::DeclareV2(tx) => Self::DeclareV2(tx),
                TransactionVariantV0::DeclareV3(tx) => Self::DeclareV3(tx),
                TransactionVariantV0::Deploy(tx) if tx.version.0 == Felt::ZERO => {
                    Self::DeployV0(DeployTransactionV0 {
                        contract_address: tx.contract_address,
                        contract_address_salt: tx.contract_address_salt,
                        class_hash: tx.class_hash,
                        constructor_calldata: tx.constructor_calldata,
                    })
                }
                TransactionVariantV0::Deploy(tx) if tx.version.0 == Felt::ONE => {
                    Self::DeployV1(DeployTransactionV1 {
                        contract_address: tx.contract_address,
                        contract_address_salt: tx.contract_address_salt,
                        class_hash: tx.class_hash,
                        constructor_calldata: tx.constructor_calldata,
                    })
                }
                TransactionVariantV0::Deploy(tx) => {
                    panic!("Unexpected deploy transaction version {}", tx.version.0)
                }
                TransactionVariantV0::DeployAccountV1(tx) => Self::DeployAccountV1(tx),
                TransactionVariantV0::DeployAccountV3(tx) => Self::DeployAccountV3(tx),
                TransactionVariantV0::InvokeV0(tx) => Self::InvokeV0(tx),
                TransactionVariantV0::InvokeV1(tx) => Self::InvokeV1(tx),
                TransactionVariantV0::InvokeV3(tx) => Self::InvokeV3(tx),
                TransactionVariantV0::L1HandlerV0(tx) => Self::L1HandlerV0(tx),
            }
        }
    }

    impl From<TransactionV0> for TransactionV1 {
        fn from(value: TransactionV0) -> Self {
            Self {
                hash: value.hash,
                variant: value.variant.into(),
            }
        }
    }

    impl From<&pathfinder_common::transaction::Transaction> for TransactionV1 {
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
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeclareV0(self::DeclareTransactionV0V1 {
                        class_hash: class_hash.as_inner().to_owned().into(),
                        max_fee: max_fee.as_inner().to_owned().into(),
                        nonce: nonce.as_inner().to_owned().into(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                DeclareV1(DeclareTransactionV0V1 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeclareV1(self::DeclareTransactionV0V1 {
                        class_hash: class_hash.as_inner().to_owned().into(),
                        max_fee: max_fee.as_inner().to_owned().into(),
                        nonce: nonce.as_inner().to_owned().into(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                DeclareV2(DeclareTransactionV2 {
                    class_hash,
                    max_fee,
                    nonce,
                    sender_address,
                    signature,
                    compiled_class_hash,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeclareV2(self::DeclareTransactionV2 {
                        class_hash: class_hash.as_inner().to_owned().into(),
                        max_fee: max_fee.as_inner().to_owned().into(),
                        nonce: nonce.as_inner().to_owned().into(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        compiled_class_hash: compiled_class_hash.as_inner().to_owned().into(),
                    }),
                },
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
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeclareV3(self::DeclareTransactionV3 {
                        class_hash: class_hash.as_inner().to_owned().into(),
                        nonce: nonce.as_inner().to_owned().into(),
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data: paymaster_data
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        compiled_class_hash: compiled_class_hash.as_inner().to_owned().into(),
                        account_deployment_data: account_deployment_data
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                DeployV0(DeployTransactionV0 {
                    contract_address,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeployV0(self::DeployTransactionV0 {
                        contract_address: contract_address.as_inner().to_owned().into(),
                        contract_address_salt: contract_address_salt.as_inner().to_owned().into(),
                        class_hash: class_hash.as_inner().to_owned().into(),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                DeployV1(DeployTransactionV1 {
                    contract_address,
                    contract_address_salt,
                    class_hash,
                    constructor_calldata,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeployV1(self::DeployTransactionV1 {
                        contract_address: contract_address.as_inner().to_owned().into(),
                        contract_address_salt: contract_address_salt.as_inner().to_owned().into(),
                        class_hash: class_hash.as_inner().to_owned().into(),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                DeployAccountV1(DeployAccountTransactionV1 {
                    contract_address,
                    max_fee,
                    signature,
                    nonce,
                    contract_address_salt,
                    constructor_calldata,
                    class_hash,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeployAccountV1(
                        self::DeployAccountTransactionV1 {
                            contract_address: contract_address.as_inner().to_owned().into(),
                            max_fee: max_fee.as_inner().to_owned().into(),
                            signature: signature
                                .into_iter()
                                .map(|x| x.as_inner().to_owned().into())
                                .collect(),
                            nonce: nonce.as_inner().to_owned().into(),
                            contract_address_salt: contract_address_salt
                                .as_inner()
                                .to_owned()
                                .into(),
                            constructor_calldata: constructor_calldata
                                .into_iter()
                                .map(|x| x.as_inner().to_owned().into())
                                .collect(),
                            class_hash: class_hash.as_inner().to_owned().into(),
                        },
                    ),
                },
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
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::DeployAccountV3(
                        self::DeployAccountTransactionV3 {
                            nonce: nonce.as_inner().to_owned().into(),
                            nonce_data_availability_mode: nonce_data_availability_mode.into(),
                            fee_data_availability_mode: fee_data_availability_mode.into(),
                            resource_bounds: resource_bounds.into(),
                            tip,
                            paymaster_data: paymaster_data
                                .into_iter()
                                .map(|x| x.as_inner().to_owned().into())
                                .collect(),
                            sender_address: contract_address.as_inner().to_owned().into(),
                            signature: signature
                                .into_iter()
                                .map(|x| x.as_inner().to_owned().into())
                                .collect(),
                            contract_address_salt: contract_address_salt
                                .as_inner()
                                .to_owned()
                                .into(),
                            constructor_calldata: constructor_calldata
                                .into_iter()
                                .map(|x| x.as_inner().to_owned().into())
                                .collect(),
                            class_hash: class_hash.as_inner().to_owned().into(),
                        },
                    ),
                },
                InvokeV0(InvokeTransactionV0 {
                    calldata,
                    sender_address,
                    entry_point_selector,
                    entry_point_type,
                    max_fee,
                    signature,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::InvokeV0(self::InvokeTransactionV0 {
                        calldata: calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        entry_point_selector: entry_point_selector.as_inner().to_owned().into(),
                        entry_point_type: entry_point_type.map(Into::into),
                        max_fee: max_fee.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                InvokeV1(InvokeTransactionV1 {
                    calldata,
                    sender_address,
                    max_fee,
                    signature,
                    nonce,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::InvokeV1(self::InvokeTransactionV1 {
                        calldata: calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        max_fee: max_fee.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        nonce: nonce.as_inner().to_owned().into(),
                    }),
                },
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
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::InvokeV3(self::InvokeTransactionV3 {
                        nonce: nonce.as_inner().to_owned().into(),
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data: paymaster_data
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        sender_address: sender_address.as_inner().to_owned().into(),
                        signature: signature
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        calldata: calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                        account_deployment_data: account_deployment_data
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
                L1Handler(L1HandlerTransaction {
                    contract_address,
                    entry_point_selector,
                    nonce,
                    calldata,
                }) => Self {
                    hash: transaction_hash.as_inner().to_owned().into(),
                    variant: TransactionVariantV1::L1HandlerV0(self::L1HandlerTransactionV0 {
                        contract_address: contract_address.as_inner().to_owned().into(),
                        entry_point_selector: entry_point_selector.as_inner().to_owned().into(),
                        nonce: nonce.as_inner().to_owned().into(),
                        calldata: calldata
                            .into_iter()
                            .map(|x| x.as_inner().to_owned().into())
                            .collect(),
                    }),
                },
            }
        }
    }

    impl From<TransactionV1> for pathfinder_common::transaction::Transaction {
        fn from(value: TransactionV1) -> Self {
            use pathfinder_common::transaction::TransactionVariant;

            let hash = value.hash();
            let variant = match value {
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeclareV0(DeclareTransactionV0V1 {
                            class_hash,
                            max_fee,
                            nonce,
                            sender_address,
                            signature,
                        }),
                } => TransactionVariant::DeclareV0(
                    pathfinder_common::transaction::DeclareTransactionV0V1 {
                        class_hash: ClassHash(class_hash.into()),
                        max_fee: Fee(max_fee.into()),
                        nonce: TransactionNonce(nonce.into()),
                        sender_address: ContractAddress::new_or_panic(sender_address.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeclareV1(DeclareTransactionV0V1 {
                            class_hash,
                            max_fee,
                            nonce,
                            sender_address,
                            signature,
                        }),
                } => TransactionVariant::DeclareV1(
                    pathfinder_common::transaction::DeclareTransactionV0V1 {
                        class_hash: ClassHash(class_hash.into()),
                        max_fee: Fee(max_fee.into()),
                        nonce: TransactionNonce(nonce.into()),
                        sender_address: ContractAddress(sender_address.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeclareV2(DeclareTransactionV2 {
                            class_hash,
                            max_fee,
                            nonce,
                            sender_address,
                            signature,
                            compiled_class_hash,
                        }),
                } => TransactionVariant::DeclareV2(
                    pathfinder_common::transaction::DeclareTransactionV2 {
                        class_hash: ClassHash(class_hash.into()),
                        max_fee: Fee(max_fee.into()),
                        nonce: TransactionNonce(nonce.into()),
                        sender_address: ContractAddress(sender_address.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        compiled_class_hash: CasmHash::new_or_panic(compiled_class_hash.into()),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeclareV3(DeclareTransactionV3 {
                            class_hash,
                            nonce,
                            nonce_data_availability_mode,
                            fee_data_availability_mode,
                            resource_bounds,
                            tip,
                            paymaster_data,
                            sender_address,
                            signature,
                            compiled_class_hash,
                            account_deployment_data,
                        }),
                } => TransactionVariant::DeclareV3(
                    pathfinder_common::transaction::DeclareTransactionV3 {
                        class_hash: ClassHash(class_hash.into()),
                        nonce: TransactionNonce(nonce.into()),
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data: paymaster_data
                            .into_iter()
                            .map(|x| PaymasterDataElem(x.into()))
                            .collect(),
                        sender_address: ContractAddress::new_or_panic(sender_address.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        compiled_class_hash: CasmHash::new_or_panic(compiled_class_hash.into()),
                        account_deployment_data: account_deployment_data
                            .into_iter()
                            .map(|x| AccountDeploymentDataElem(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeployV0(DeployTransactionV0 {
                            contract_address,
                            contract_address_salt,
                            class_hash,
                            constructor_calldata,
                        }),
                } => TransactionVariant::DeployV0(
                    pathfinder_common::transaction::DeployTransactionV0 {
                        contract_address: ContractAddress::new_or_panic(contract_address.into()),
                        contract_address_salt: ContractAddressSalt(contract_address_salt.into()),
                        class_hash: ClassHash(class_hash.into()),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| ConstructorParam(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeployV1(DeployTransactionV1 {
                            contract_address,
                            contract_address_salt,
                            class_hash,
                            constructor_calldata,
                        }),
                } => TransactionVariant::DeployV1(
                    pathfinder_common::transaction::DeployTransactionV1 {
                        contract_address: ContractAddress::new_or_panic(contract_address.into()),
                        contract_address_salt: ContractAddressSalt(contract_address_salt.into()),
                        class_hash: ClassHash(class_hash.into()),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| ConstructorParam(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeployAccountV1(DeployAccountTransactionV1 {
                            contract_address,
                            max_fee,
                            signature,
                            nonce,
                            contract_address_salt,
                            constructor_calldata,
                            class_hash,
                        }),
                } => TransactionVariant::DeployAccountV1(
                    pathfinder_common::transaction::DeployAccountTransactionV1 {
                        contract_address: ContractAddress::new_or_panic(contract_address.into()),
                        max_fee: Fee(max_fee.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        nonce: TransactionNonce(nonce.into()),
                        contract_address_salt: ContractAddressSalt(contract_address_salt.into()),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| CallParam(x.into()))
                            .collect(),
                        class_hash: ClassHash(class_hash.into()),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::DeployAccountV3(DeployAccountTransactionV3 {
                            nonce,
                            nonce_data_availability_mode,
                            fee_data_availability_mode,
                            resource_bounds,
                            tip,
                            paymaster_data,
                            sender_address,
                            signature,
                            contract_address_salt,
                            constructor_calldata,
                            class_hash,
                        }),
                } => TransactionVariant::DeployAccountV3(
                    pathfinder_common::transaction::DeployAccountTransactionV3 {
                        contract_address: ContractAddress::new_or_panic(sender_address.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        nonce: TransactionNonce(nonce.into()),
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data: paymaster_data
                            .into_iter()
                            .map(|x| PaymasterDataElem(x.into()))
                            .collect(),
                        contract_address_salt: ContractAddressSalt(contract_address_salt.into()),
                        constructor_calldata: constructor_calldata
                            .into_iter()
                            .map(|x| CallParam(x.into()))
                            .collect(),
                        class_hash: ClassHash(class_hash.into()),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::InvokeV0(InvokeTransactionV0 {
                            calldata,
                            sender_address,
                            entry_point_selector,
                            entry_point_type,
                            max_fee,
                            signature,
                        }),
                } => TransactionVariant::InvokeV0(
                    pathfinder_common::transaction::InvokeTransactionV0 {
                        calldata: calldata.into_iter().map(|x| CallParam(x.into())).collect(),
                        sender_address: ContractAddress::new_or_panic(sender_address.into()),
                        entry_point_selector: EntryPoint(entry_point_selector.into()),
                        entry_point_type: entry_point_type.map(Into::into),
                        max_fee: Fee(max_fee.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::InvokeV1(InvokeTransactionV1 {
                            calldata,
                            sender_address,
                            max_fee,
                            signature,
                            nonce,
                        }),
                } => TransactionVariant::InvokeV1(
                    pathfinder_common::transaction::InvokeTransactionV1 {
                        calldata: calldata.into_iter().map(|x| CallParam(x.into())).collect(),
                        sender_address: ContractAddress::new_or_panic(sender_address.into()),
                        max_fee: Fee(max_fee.into()),
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        nonce: TransactionNonce(nonce.into()),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::InvokeV3(InvokeTransactionV3 {
                            nonce,
                            nonce_data_availability_mode,
                            fee_data_availability_mode,
                            resource_bounds,
                            tip,
                            paymaster_data,
                            sender_address,
                            signature,
                            calldata,
                            account_deployment_data,
                        }),
                } => TransactionVariant::InvokeV3(
                    pathfinder_common::transaction::InvokeTransactionV3 {
                        signature: signature
                            .into_iter()
                            .map(|x| TransactionSignatureElem(x.into()))
                            .collect(),
                        nonce: TransactionNonce(nonce.into()),
                        nonce_data_availability_mode: nonce_data_availability_mode.into(),
                        fee_data_availability_mode: fee_data_availability_mode.into(),
                        resource_bounds: resource_bounds.into(),
                        tip,
                        paymaster_data: paymaster_data
                            .into_iter()
                            .map(|x| PaymasterDataElem(x.into()))
                            .collect(),
                        account_deployment_data: account_deployment_data
                            .into_iter()
                            .map(|x| AccountDeploymentDataElem(x.into()))
                            .collect(),
                        calldata: calldata.into_iter().map(|x| CallParam(x.into())).collect(),
                        sender_address: ContractAddress::new_or_panic(sender_address.into()),
                    },
                ),
                TransactionV1 {
                    hash: _,
                    variant:
                        TransactionVariantV1::L1HandlerV0(L1HandlerTransactionV0 {
                            contract_address,
                            entry_point_selector,
                            nonce,
                            calldata,
                        }),
                } => TransactionVariant::L1Handler(
                    pathfinder_common::transaction::L1HandlerTransaction {
                        contract_address: ContractAddress::new_or_panic(contract_address.into()),
                        entry_point_selector: EntryPoint(entry_point_selector.into()),
                        nonce: TransactionNonce(nonce.into()),
                        calldata: calldata.into_iter().map(|x| CallParam(x.into())).collect(),
                    },
                ),
            };

            pathfinder_common::transaction::Transaction { hash, variant }
        }
    }

    /// A version 0 or 1 declare transaction.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV0V1 {
        pub class_hash: MinimalFelt,
        pub max_fee: MinimalFelt,
        pub nonce: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
    }

    impl<T> Dummy<T> for DeclareTransactionV0V1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                class_hash: Faker.fake_with_rng(rng),
                max_fee: Faker.fake_with_rng(rng),
                nonce: TransactionNonce::ZERO.0.into(),
                sender_address: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
            }
        }
    }

    /// A version 2 declare transaction.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV2 {
        pub class_hash: MinimalFelt,
        pub max_fee: MinimalFelt,
        pub nonce: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
        pub compiled_class_hash: MinimalFelt,
    }

    /// A version 2 declare transaction.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV3 {
        pub class_hash: MinimalFelt,
        pub nonce: MinimalFelt,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<MinimalFelt>,
        pub signature: Vec<MinimalFelt>,
        pub account_deployment_data: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
        pub compiled_class_hash: MinimalFelt,
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
                compiled_class_hash: Faker.fake_with_rng(rng),
                account_deployment_data: vec![Faker.fake_with_rng(rng)], /* TODO p2p allows 1
                                                                          * elem only */
            }
        }
    }

    /// Represents deserialized L2 deploy transaction data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransaction {
        pub contract_address: MinimalFelt,
        pub version: MinimalFelt,
        pub contract_address_salt: MinimalFelt,
        pub class_hash: MinimalFelt,
        pub constructor_calldata: Vec<MinimalFelt>,
    }

    impl<T> Dummy<T> for DeployTransaction {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let class_hash: MinimalFelt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<MinimalFelt> = Faker.fake_with_rng(rng);
            let contract_address_salt: MinimalFelt = Faker.fake_with_rng(rng);

            let contract_address = ContractAddress::deployed_contract_address(
                constructor_calldata.iter().map(|f| CallParam(f.0)),
                &ContractAddressSalt(contract_address_salt.0),
                &ClassHash(class_hash.0),
            )
            .as_inner()
            .to_owned()
            .into();

            Self {
                version: Felt::from_u64(rng.gen_range(0..=1)).into(),
                contract_address,
                contract_address_salt,
                class_hash,
                constructor_calldata,
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransactionV0 {
        pub contract_address: MinimalFelt,
        pub contract_address_salt: MinimalFelt,
        pub class_hash: MinimalFelt,
        pub constructor_calldata: Vec<MinimalFelt>,
    }

    impl<T> Dummy<T> for DeployTransactionV0 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let class_hash: MinimalFelt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<MinimalFelt> = Faker.fake_with_rng(rng);
            let contract_address_salt: MinimalFelt = Faker.fake_with_rng(rng);

            let contract_address = ContractAddress::deployed_contract_address(
                constructor_calldata.iter().map(|f| CallParam(f.0)),
                &ContractAddressSalt(contract_address_salt.0),
                &ClassHash(class_hash.0),
            )
            .as_inner()
            .to_owned()
            .into();

            Self {
                contract_address,
                contract_address_salt,
                class_hash,
                constructor_calldata,
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransactionV1 {
        pub contract_address: MinimalFelt,
        pub contract_address_salt: MinimalFelt,
        pub class_hash: MinimalFelt,
        pub constructor_calldata: Vec<MinimalFelt>,
    }

    impl<T> Dummy<T> for DeployTransactionV1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let class_hash: MinimalFelt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<MinimalFelt> = Faker.fake_with_rng(rng);
            let contract_address_salt: MinimalFelt = Faker.fake_with_rng(rng);

            let contract_address = ContractAddress::deployed_contract_address(
                constructor_calldata.iter().map(|f| CallParam(f.0)),
                &ContractAddressSalt(contract_address_salt.0),
                &ClassHash(class_hash.0),
            )
            .as_inner()
            .to_owned()
            .into();

            Self {
                contract_address,
                contract_address_salt,
                class_hash,
                constructor_calldata,
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountTransactionV1 {
        pub contract_address: MinimalFelt,
        pub max_fee: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
        pub nonce: MinimalFelt,
        pub contract_address_salt: MinimalFelt,
        pub constructor_calldata: Vec<MinimalFelt>,
        pub class_hash: MinimalFelt,
    }

    impl<T> Dummy<T> for DeployAccountTransactionV1 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            let contract_address_salt = Faker.fake_with_rng(rng);
            let constructor_calldata: Vec<CallParam> = Faker.fake_with_rng(rng);
            let class_hash = Faker.fake_with_rng(rng);

            Self {
                contract_address: ContractAddress::deployed_contract_address(
                    constructor_calldata.iter().copied(),
                    &contract_address_salt,
                    &class_hash,
                )
                .as_inner()
                .to_owned()
                .into(),
                max_fee: Faker.fake_with_rng(rng),
                signature: Faker.fake_with_rng(rng),
                nonce: Faker.fake_with_rng(rng),
                contract_address_salt: contract_address_salt.as_inner().to_owned().into(),
                constructor_calldata: constructor_calldata
                    .into_iter()
                    .map(|x| x.as_inner().to_owned().into())
                    .collect(),
                class_hash: class_hash.as_inner().to_owned().into(),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountTransactionV3 {
        pub sender_address: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
        pub nonce: MinimalFelt,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<MinimalFelt>,
        pub contract_address_salt: MinimalFelt,
        pub constructor_calldata: Vec<MinimalFelt>,
        pub class_hash: MinimalFelt,
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
                )
                .as_inner()
                .to_owned()
                .into(),
                signature: Faker.fake_with_rng(rng),
                contract_address_salt: contract_address_salt.as_inner().to_owned().into(),
                constructor_calldata: constructor_calldata
                    .into_iter()
                    .map(|x| x.as_inner().to_owned().into())
                    .collect(),
                class_hash: class_hash.as_inner().to_owned().into(),
            }
        }
    }

    /// Represents deserialized L2 invoke transaction v0 data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV0 {
        pub calldata: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
        pub entry_point_selector: MinimalFelt,
        pub entry_point_type: Option<EntryPointType>,
        pub max_fee: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
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
            }
        }
    }

    /// Represents deserialized L2 invoke transaction v1 data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Dummy)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV1 {
        pub calldata: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
        pub max_fee: MinimalFelt,
        pub signature: Vec<MinimalFelt>,
        pub nonce: MinimalFelt,
    }

    /// Represents deserialized L2 invoke transaction v3 data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV3 {
        pub signature: Vec<MinimalFelt>,
        pub nonce: MinimalFelt,
        pub nonce_data_availability_mode: DataAvailabilityMode,
        pub fee_data_availability_mode: DataAvailabilityMode,
        pub resource_bounds: ResourceBounds,
        pub tip: Tip,
        pub paymaster_data: Vec<MinimalFelt>,
        pub account_deployment_data: Vec<MinimalFelt>,
        pub calldata: Vec<MinimalFelt>,
        pub sender_address: MinimalFelt,
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
                calldata: Faker.fake_with_rng(rng),
                account_deployment_data: vec![Faker.fake_with_rng(rng)], /* TODO p2p allows 1
                                                                          * elem only */
            }
        }
    }

    /// Represents deserialized L2 "L1 handler" transaction data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1HandlerTransactionV0 {
        pub contract_address: MinimalFelt,
        pub entry_point_selector: MinimalFelt,
        pub nonce: MinimalFelt,
        pub calldata: Vec<MinimalFelt>,
    }

    impl<T> Dummy<T> for L1HandlerTransactionV0 {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
            Self {
                contract_address: Faker.fake_with_rng(rng),
                entry_point_selector: Faker.fake_with_rng(rng),
                nonce: Faker.fake_with_rng(rng),
                calldata: Faker.fake_with_rng(rng),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::transaction::*;
    use pathfinder_common::{BlockHeader, TransactionIndex};

    use super::*;

    #[test]
    fn serialize_deserialize_transaction() {
        let transaction = pathfinder_common::transaction::Transaction {
            hash: transaction_hash_bytes!(b"pending tx hash 1"),
            variant: TransactionVariant::DeployV1(DeployTransactionV1 {
                contract_address: contract_address!("0x1122355"),
                contract_address_salt: contract_address_salt_bytes!(b"salty"),
                class_hash: class_hash_bytes!(b"pending class hash 1"),
                ..Default::default()
            }),
        };
        let dto = dto::TransactionV1::from(&transaction);
        let serialized = bincode::serde::encode_to_vec(&dto, bincode::config::standard()).unwrap();
        let deserialized: (dto::TransactionV1, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(deserialized.0, dto);
    }

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
                variant: TransactionVariant::DeployV0(DeployTransactionV0 {
                    contract_address: contract_address_bytes!(b"deploy contract address"),
                    contract_address_salt: contract_address_salt_bytes!(
                        b"deploy contract address salt"
                    ),
                    class_hash: class_hash_bytes!(b"deploy class hash"),
                    constructor_calldata: vec![
                        constructor_param_bytes!(b"deploy call data 0"),
                        constructor_param_bytes!(b"deploy call data 1"),
                    ],
                }),
            },
            StarknetTransaction {
                hash: transaction_hash_bytes!(b"deploy account tx hash"),
                variant: TransactionVariant::DeployAccountV1(DeployAccountTransactionV1 {
                    contract_address: contract_address_bytes!(b"deploy account contract address"),
                    max_fee: fee_bytes!(b"deploy account max fee"),
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

        // Generate a random receipt for each transaction. Note that these won't make
        // physical sense but its enough for the tests.
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

        let mut db = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let db_tx = db.transaction().unwrap();

        db_tx.insert_block_header(&header).unwrap();
        db_tx
            .insert_transaction_data(
                header.number,
                &body,
                Some(&body.iter().map(|(..)| vec![]).collect::<Vec<_>>()),
            )
            .unwrap();

        db_tx.commit().unwrap();

        (db, header, body)
    }

    #[test]
    fn transaction() {
        let (mut db, _, body) = setup();
        let tx = db.transaction().unwrap();

        let (expected, _) = body.first().unwrap().clone();

        let result = tx.transaction(expected.hash).unwrap().unwrap();
        assert_eq!(result, expected);

        let invalid = tx.transaction(transaction_hash_bytes!(b"invalid")).unwrap();
        assert_eq!(invalid, None);
    }

    #[test]
    fn transaction_with_receipt() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let (transaction, receipt) = body.first().unwrap().clone();

        let result = tx
            .transaction_with_receipt(transaction.hash)
            .unwrap()
            .unwrap();
        assert_eq!(result.0, transaction);
        assert_eq!(result.1, receipt);
        assert_eq!(result.2, vec![]);
        assert_eq!(result.3, header.number);

        let invalid = tx
            .transaction_with_receipt(transaction_hash_bytes!(b"invalid"))
            .unwrap();
        assert_eq!(invalid, None);
    }

    #[test]
    fn transaction_at_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let idx = 5;
        let expected = Some(body[idx].0.clone());

        let by_number = tx.transaction_at_block(header.number.into(), idx).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = tx.transaction_at_block(header.hash.into(), idx).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = tx.transaction_at_block(BlockId::Latest, idx).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_index = tx
            .transaction_at_block(header.number.into(), body.len() + 1)
            .unwrap();
        assert_eq!(invalid_index, None);

        let invalid_index = tx
            .transaction_at_block(BlockNumber::MAX.into(), idx)
            .unwrap();
        assert_eq!(invalid_index, None);
    }

    #[test]
    fn transaction_count() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let by_latest = tx.transaction_count(BlockId::Latest).unwrap();
        assert_eq!(by_latest, body.len());
        let by_number = tx.transaction_count(header.number.into()).unwrap();
        assert_eq!(by_number, body.len());
        let by_hash = tx.transaction_count(header.hash.into()).unwrap();
        assert_eq!(by_hash, body.len());
    }

    #[test]
    fn transaction_data_for_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let expected = Some(
            body.into_iter()
                .map(|(tx, receipt)| (tx, receipt, vec![]))
                .collect(),
        );

        let by_number = tx.transaction_data_for_block(header.number.into()).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = tx.transaction_data_for_block(header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = tx.transaction_data_for_block(BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block = tx
            .transaction_data_for_block(BlockNumber::MAX.into())
            .unwrap();
        assert_eq!(invalid_block, None);
    }

    #[test]
    fn transactions_for_block() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let expected = Some(body.into_iter().map(|(t, _)| t).collect::<Vec<_>>());

        let by_number = tx.transactions_for_block(header.number.into()).unwrap();
        assert_eq!(by_number, expected);
        let by_hash = tx.transactions_for_block(header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = tx.transactions_for_block(BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block = tx
            .transaction_data_for_block(BlockNumber::MAX.into())
            .unwrap();
        assert_eq!(invalid_block, None);

        let invalid_block = tx
            .transaction_data_for_block(block_hash!("0x123").into())
            .unwrap();
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

        let by_number = tx
            .transaction_hashes_for_block(header.number.into())
            .unwrap();
        assert_eq!(by_number, expected);
        let by_hash = tx.transaction_hashes_for_block(header.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
        let by_latest = tx.transaction_hashes_for_block(BlockId::Latest).unwrap();
        assert_eq!(by_latest, expected);

        let invalid_block = tx
            .transaction_hashes_for_block(BlockNumber::MAX.into())
            .unwrap();
        assert_eq!(invalid_block, None);
    }

    #[test]
    fn transaction_block_hash() {
        let (mut db, header, body) = setup();
        let tx = db.transaction().unwrap();

        let target = body.first().unwrap().0.hash;
        let valid = tx.transaction_block_hash(target).unwrap().unwrap();
        assert_eq!(valid, header.hash);

        let invalid = tx
            .transaction_block_hash(transaction_hash_bytes!(b"invalid hash"))
            .unwrap();
        assert_eq!(invalid, None);
    }
}
