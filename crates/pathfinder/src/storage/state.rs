use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{named_params, params, Connection, OptionalExtension, Transaction};
use web3::types::H256;

use crate::{
    core::{
        ContractHash, ContractRoot, ContractStateHash, EthereumBlockHash, EthereumBlockNumber,
        EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex, GlobalRoot,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash,
    },
    ethereum::{log::StateUpdateLog, BlockOrigin, EthOrigin, TransactionOrigin},
    sequencer::reply::transaction,
};

/// Contains the [L1 Starknet update logs](StateUpdateLog).
pub struct L1StateTable {}

/// Identifies block in some [L1StateTable] queries.
pub enum L1TableBlockId {
    Number(StarknetBlockNumber),
    Latest,
}

impl From<StarknetBlockNumber> for L1TableBlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        L1TableBlockId::Number(number)
    }
}

impl L1StateTable {
    /// Inserts a new [update](StateUpdateLog), fails if it already exists.
    pub fn insert(connection: &Connection, update: &StateUpdateLog) -> anyhow::Result<()> {
        connection
            .execute(
                r"INSERT INTO l1_state (
                        starknet_block_number,
                        starknet_global_root,
                        ethereum_block_hash,
                        ethereum_block_number,
                        ethereum_transaction_hash,
                        ethereum_transaction_index,
                        ethereum_log_index
                    ) VALUES (
                        :starknet_block_number,
                        :starknet_global_root,
                        :ethereum_block_hash,
                        :ethereum_block_number,
                        :ethereum_transaction_hash,
                        :ethereum_transaction_index,
                        :ethereum_log_index
                    )",
                named_params! {
                    ":starknet_block_number": update.block_number.0,
                    ":starknet_global_root": &update.global_root.0.as_be_bytes()[..],
                    ":ethereum_block_hash": &update.origin.block.hash.0[..],
                    ":ethereum_block_number": update.origin.block.number.0,
                    ":ethereum_transaction_hash": &update.origin.transaction.hash.0[..],
                    ":ethereum_transaction_index": update.origin.transaction.index.0,
                    ":ethereum_log_index": update.origin.log_index.0,
                },
            )
            .context("Insert L1 state update")?;

        Ok(())
    }

    /// Deletes all rows from __head down-to reorg_tail__
    /// i.e. it deletes all rows where `block number >= reorg_tail`.
    pub fn reorg(connection: &Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
        connection.execute(
            "DELETE FROM l1_state WHERE starknet_block_number >= ?",
            params![reorg_tail.0],
        )?;
        Ok(())
    }

    /// Returns the [root](GlobalRoot) of the given block.
    pub fn get_root(
        connection: &Connection,
        block: L1TableBlockId,
    ) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = match block {
            L1TableBlockId::Number(_) => {
                connection.prepare("SELECT starknet_global_root FROM l1_state WHERE starknet_block_number = ?")
            }
            L1TableBlockId::Latest => connection
                .prepare("SELECT starknet_global_root FROM l1_state ORDER BY starknet_block_number DESC LIMIT 1"),
        }?;

        let mut rows = match block {
            L1TableBlockId::Number(number) => statement.query(params![number.0]),
            L1TableBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next()?;
        let row = match row {
            Some(row) => row,
            None => return Ok(None),
        };

        let starknet_global_root = row
            .get_ref_unwrap("starknet_global_root")
            .as_blob()
            .unwrap();
        let starknet_global_root = StarkHash::from_be_slice(starknet_global_root).unwrap();
        let starknet_global_root = GlobalRoot(starknet_global_root);

        Ok(Some(starknet_global_root))
    }

    /// Returns the [update](StateUpdateLog) of the given block.
    pub fn get(
        connection: &Connection,
        block: L1TableBlockId,
    ) -> anyhow::Result<Option<StateUpdateLog>> {
        let mut statement = match block {
            L1TableBlockId::Number(_) => connection.prepare(
                r"SELECT starknet_block_number,
                    starknet_global_root,
                    ethereum_block_hash,
                    ethereum_block_number,
                    ethereum_transaction_hash,
                    ethereum_transaction_index,
                    ethereum_log_index
                FROM l1_state WHERE starknet_block_number = ?",
            ),
            L1TableBlockId::Latest => connection.prepare(
                r"SELECT starknet_block_number,
                    starknet_global_root,
                    ethereum_block_hash,
                    ethereum_block_number,
                    ethereum_transaction_hash,
                    ethereum_transaction_index,
                    ethereum_log_index
                FROM l1_state ORDER BY starknet_block_number DESC LIMIT 1",
            ),
        }?;

        let mut rows = match block {
            L1TableBlockId::Number(number) => statement.query(params![number.0]),
            L1TableBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next()?;
        let row = match row {
            Some(row) => row,
            None => return Ok(None),
        };

        let starknet_block_number = row
            .get_ref_unwrap("starknet_block_number")
            .as_i64()
            .unwrap() as u64;
        let starknet_block_number = StarknetBlockNumber(starknet_block_number);

        let starknet_global_root = row
            .get_ref_unwrap("starknet_global_root")
            .as_blob()
            .unwrap();
        let starknet_global_root = StarkHash::from_be_slice(starknet_global_root).unwrap();
        let starknet_global_root = GlobalRoot(starknet_global_root);

        let ethereum_block_hash = row.get_ref_unwrap("ethereum_block_hash").as_blob().unwrap();
        let ethereum_block_hash = EthereumBlockHash(H256(ethereum_block_hash.try_into().unwrap()));

        let ethereum_block_number = row
            .get_ref_unwrap("ethereum_block_number")
            .as_i64()
            .unwrap() as u64;
        let ethereum_block_number = EthereumBlockNumber(ethereum_block_number);

        let ethereum_transaction_hash = row
            .get_ref_unwrap("ethereum_transaction_hash")
            .as_blob()
            .unwrap();
        let ethereum_transaction_hash =
            EthereumTransactionHash(H256(ethereum_transaction_hash.try_into().unwrap()));

        let ethereum_transaction_index = row
            .get_ref_unwrap("ethereum_transaction_index")
            .as_i64()
            .unwrap() as u64;
        let ethereum_transaction_index = EthereumTransactionIndex(ethereum_transaction_index);

        let ethereum_log_index = row.get_ref_unwrap("ethereum_log_index").as_i64().unwrap() as u64;
        let ethereum_log_index = EthereumLogIndex(ethereum_log_index);

        Ok(Some(StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: ethereum_block_hash,
                    number: ethereum_block_number,
                },
                transaction: TransactionOrigin {
                    hash: ethereum_transaction_hash,
                    index: ethereum_transaction_index,
                },
                log_index: ethereum_log_index,
            },
            global_root: starknet_global_root,
            block_number: starknet_block_number,
        }))
    }
}

pub struct RefsTable {}
impl RefsTable {
    /// Returns the current L1-L2 head. This indicates the latest block for which L1 and L2 agree.
    pub fn get_l1_l2_head(connection: &Connection) -> anyhow::Result<Option<StarknetBlockNumber>> {
        // This table always contains exactly one row.
        let block_number =
            connection.query_row("SELECT l1_l2_head FROM refs WHERE idx = 1", [], |row| {
                let block_number = row
                    .get_ref_unwrap(0)
                    .as_i64_or_null()
                    .unwrap()
                    .map(|x| StarknetBlockNumber(x as u64));

                Ok(block_number)
            })?;

        Ok(block_number)
    }

    /// Sets the current L1-L2 head. This should indicate the latest block for which L1 and L2 agree.
    pub fn set_l1_l2_head(
        connection: &Connection,
        head: Option<StarknetBlockNumber>,
    ) -> anyhow::Result<()> {
        match head {
            Some(number) => {
                connection.execute("UPDATE refs SET l1_l2_head = ? WHERE idx = 1", [number.0])
            }
            None => connection.execute("UPDATE refs SET l1_l2_head = NULL WHERE idx = 1", []),
        }?;

        Ok(())
    }
}
/// Stores all known [StarknetBlocks][StarknetBlock].
pub struct StarknetBlocksTable {}
impl StarknetBlocksTable {
    /// Insert a new [StarknetBlock]. Fails if the block number is not unique.
    pub fn insert(connection: &Connection, block: &StarknetBlock) -> anyhow::Result<()> {
        connection.execute(
            r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp)
                                   VALUES (:number, :hash, :root, :timestamp)",
            named_params! {
                ":number": block.number.0,
                ":hash": &block.hash.0.as_be_bytes()[..],
                ":root": &block.root.0.as_be_bytes()[..],
                ":timestamp": block.timestamp.0,
            },
        )?;

        Ok(())
    }

    /// Returns the requested [StarknetBlock].
    pub fn get(
        connection: &Connection,
        block: StarknetBlocksBlockId,
    ) -> anyhow::Result<Option<StarknetBlock>> {
        let mut statement = match block {
            StarknetBlocksBlockId::Number(_) => {
                connection.prepare("SELECT hash, number, root, timestamp FROM starknet_blocks WHERE number = ?")
            }
            StarknetBlocksBlockId::Hash(_) => {
                connection.prepare("SELECT hash, number, root, timestamp FROM starknet_blocks WHERE hash = ?")
            }
            StarknetBlocksBlockId::Latest => {
                connection.prepare("SELECT hash, number, root, timestamp FROM starknet_blocks ORDER BY number DESC LIMIT 1")
            }
        }?;

        let mut rows = match block {
            StarknetBlocksBlockId::Number(number) => statement.query(params![number.0]),
            StarknetBlocksBlockId::Hash(hash) => {
                statement.query(params![&hash.0.as_be_bytes()[..]])
            }
            StarknetBlocksBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next().context("Iterate rows")?;

        match row {
            Some(row) => {
                let number = row.get_ref_unwrap("number").as_i64().unwrap() as u64;
                let number = StarknetBlockNumber(number);

                let hash = row.get_ref_unwrap("hash").as_blob().unwrap();
                let hash = StarkHash::from_be_slice(hash).unwrap();
                let hash = StarknetBlockHash(hash);

                let root = row.get_ref_unwrap("root").as_blob().unwrap();
                let root = StarkHash::from_be_slice(root).unwrap();
                let root = GlobalRoot(root);

                let timestamp = row.get_ref_unwrap("timestamp").as_i64().unwrap() as u64;
                let timestamp = StarknetBlockTimestamp(timestamp);

                let block = StarknetBlock {
                    number,
                    hash,
                    root,
                    timestamp,
                };

                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Returns the [root](GlobalRoot) of the given block.
    pub fn get_root(
        connection: &Connection,
        block: StarknetBlocksBlockId,
    ) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = match block {
            StarknetBlocksBlockId::Number(_) => {
                connection.prepare("SELECT root FROM starknet_blocks WHERE number = ?")
            }
            StarknetBlocksBlockId::Hash(_) => {
                connection.prepare("SELECT root FROM starknet_blocks WHERE hash = ?")
            }
            StarknetBlocksBlockId::Latest => {
                connection.prepare("SELECT root FROM starknet_blocks ORDER BY number DESC LIMIT 1")
            }
        }?;

        let mut rows = match block {
            StarknetBlocksBlockId::Number(number) => statement.query(params![number.0]),
            StarknetBlocksBlockId::Hash(hash) => {
                statement.query(params![&hash.0.as_be_bytes()[..]])
            }
            StarknetBlocksBlockId::Latest => statement.query([]),
        }?;

        let row = rows.next().context("Iterate rows")?;
        match row {
            Some(row) => {
                let root = row.get_ref_unwrap("root").as_blob().unwrap();
                let root = StarkHash::from_be_slice(root).unwrap();
                let root = GlobalRoot(root);
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }

    /// Deletes all rows from __head down-to reorg_tail__
    /// i.e. it deletes all rows where `block number >= reorg_tail`.
    pub fn reorg(connection: &Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
        connection.execute(
            "DELETE FROM starknet_blocks WHERE number >= ?",
            params![reorg_tail.0],
        )?;
        Ok(())
    }
}

/// Identifies block in some [StarknetBlocksTable] queries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StarknetBlocksBlockId {
    Number(StarknetBlockNumber),
    Hash(StarknetBlockHash),
    Latest,
}

impl From<StarknetBlockNumber> for StarknetBlocksBlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        StarknetBlocksBlockId::Number(number)
    }
}

impl From<StarknetBlockHash> for StarknetBlocksBlockId {
    fn from(hash: StarknetBlockHash) -> Self {
        StarknetBlocksBlockId::Hash(hash)
    }
}

/// Stores all known starknet transactions
pub struct StarknetTransactionsTable {}
impl StarknetTransactionsTable {
    /// Inserts a Starknet block's transactions and transaction receipts into the [StarknetTransactionsTable].
    pub fn insert_block_transactions(
        connection: &Connection,
        block: StarknetBlockHash,
        transaction_data: &[(transaction::Transaction, transaction::Receipt)],
    ) -> anyhow::Result<()> {
        if transaction_data.is_empty() {
            return Ok(());
        }

        let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
        for (i, (transaction, receipt)) in transaction_data.iter().enumerate() {
            // Serialize and compress transaction data.
            let tx_data =
                serde_json::ser::to_vec(&transaction).context("Serialize Starknet transaction")?;
            let tx_data = compressor
                .compress(&tx_data)
                .context("Compress Starknet transaction")?;

            let receipt = serde_json::ser::to_vec(&receipt)
                .context("Serialize Starknet transaction receipt")?;
            let receipt = compressor
                .compress(&receipt)
                .context("Compress Starknet transaction receipt")?;

            connection.execute(r"INSERT INTO starknet_transactions ( hash,  idx,  block_hash,  tx,  receipt)
                                                            VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
        named_params![
                    ":hash": &transaction.transaction_hash.0.as_be_bytes()[..],
                    ":idx": i,
                    ":block_hash": &block.0.as_be_bytes()[..],
                    ":tx": &tx_data,
                    ":receipt": &receipt,
                ]).context("Insert transaction data into transactions table")?;
        }

        Ok(())
    }

    pub fn get_transaction_data_for_block(
        connection: &Connection,
        block: StarknetBlocksBlockId,
    ) -> anyhow::Result<Vec<(transaction::Transaction, transaction::Receipt)>> {
        // Identify block hash
        let block_hash = match block {
            StarknetBlocksBlockId::Number(number) => {
                match StarknetBlocksTable::get(connection, number.into())? {
                    Some(block) => block.hash,
                    None => return Ok(Vec::new()),
                }
            }
            StarknetBlocksBlockId::Hash(hash) => hash,
            StarknetBlocksBlockId::Latest => {
                match StarknetBlocksTable::get(connection, StarknetBlocksBlockId::Latest)? {
                    Some(block) => block.hash,
                    None => return Ok(Vec::new()),
                }
            }
        };

        let mut stmt = connection
            .prepare(
                "SELECT tx, receipt FROM starknet_transactions WHERE hash = ? ORDER BY idx ASC",
            )
            .context("Preparing statement")?;

        let mut rows = stmt
            .query(params![&block_hash.0.as_be_bytes()[..]])
            .context("Executing query")?;

        let mut decompressor = zstd::bulk::Decompressor::new().context("Creating decompressor")?;
        let mut data = Vec::new();
        while let Some(row) = rows.next()? {
            let receipt = row
                .get_ref_unwrap("receipt")
                .as_blob_or_null()?
                .context("Receipt data missing")?;
            let receipt = decompressor
                .decompress(receipt, 1000 * 1000 * 10)
                .context("Decompressing transaction receipt")?;
            let receipt = serde_json::de::from_slice(&receipt)
                .context("Deserializing transaction receipt")?;

            let transaction = row
                .get_ref_unwrap("tx")
                .as_blob_or_null()?
                .context("Transaction data missing")?;
            let transaction = decompressor
                .decompress(transaction, 1000 * 1000 * 10)
                .context("Decompressing transaction")?;
            let transaction =
                serde_json::de::from_slice(&transaction).context("Deserializing transaction")?;

            data.push((transaction, receipt));
        }

        Ok(data)
    }

    pub fn get_transaction_at_block(
        connection: &Connection,
        block: StarknetBlocksBlockId,
        index: usize,
    ) -> anyhow::Result<Option<transaction::Transaction>> {
        // Identify block hash
        let block_hash = match block {
            StarknetBlocksBlockId::Number(number) => {
                match StarknetBlocksTable::get(connection, number.into())? {
                    Some(block) => block.hash,
                    None => return Ok(None),
                }
            }
            StarknetBlocksBlockId::Hash(hash) => hash,
            StarknetBlocksBlockId::Latest => {
                match StarknetBlocksTable::get(connection, StarknetBlocksBlockId::Latest)? {
                    Some(block) => block.hash,
                    None => return Ok(None),
                }
            }
        };

        let mut stmt = connection
            .prepare("SELECT tx FROM starknet_transactions WHERE hash = ? AND idx = ?")
            .context("Preparing statement")?;

        let mut rows = stmt
            .query(params![&block_hash.0.as_be_bytes()[..], index])
            .context("Executing query")?;

        let row = match rows.next()? {
            Some(row) => row,
            None => return Ok(None),
        };

        let transaction = match row.get_ref_unwrap(0).as_blob_or_null()? {
            Some(data) => data,
            None => return Ok(None),
        };

        let transaction = zstd::bulk::decompress(transaction, 1000 * 1000 * 10)
            .context("Decompressing transaction")?;
        let transaction =
            serde_json::de::from_slice(&transaction).context("Deserializing transaction")?;

        Ok(Some(transaction))
    }

    pub fn get_receipt(
        connection: &Connection,
        transaction: StarknetTransactionHash,
    ) -> anyhow::Result<Option<(transaction::Receipt, StarknetBlockHash)>> {
        let mut stmt = connection
            .prepare("SELECT receipt, block_hash FROM starknet_transactions WHERE hash = ?1")
            .context("Preparing statement")?;

        let mut rows = stmt
            .query(params![&transaction.0.as_be_bytes()[..]])
            .context("Executing query")?;

        let row = match rows.next()? {
            Some(row) => row,
            None => return Ok(None),
        };

        let receipt = match row.get_ref_unwrap("receipt").as_blob_or_null()? {
            Some(data) => data,
            None => return Ok(None),
        };
        let receipt = zstd::bulk::decompress(receipt, 1000 * 1000 * 10)
            .context("Decompressing transaction")?;
        let receipt = serde_json::de::from_slice(&receipt).context("Deserializing transaction")?;

        let block_hash = row.get_ref_unwrap("block_hash").as_blob()?;
        let block_hash =
            StarkHash::from_be_slice(block_hash).context("Deserializing block hash")?;
        let block_hash = StarknetBlockHash(block_hash);

        Ok(Some((receipt, block_hash)))
    }

    pub fn get_transaction(
        connection: &Connection,
        transaction: StarknetTransactionHash,
    ) -> anyhow::Result<Option<transaction::Transaction>> {
        let mut stmt = connection
            .prepare("SELECT tx FROM starknet_transactions WHERE hash = ?1")
            .context("Preparing statement")?;

        let mut rows = stmt
            .query(params![&transaction.0.as_be_bytes()[..]])
            .context("Executing query")?;

        let row = match rows.next()? {
            Some(row) => row,
            None => return Ok(None),
        };

        let transaction = match row.get_ref_unwrap(0).as_blob_or_null()? {
            Some(data) => data,
            None => return Ok(None),
        };

        let transaction = zstd::bulk::decompress(transaction, 1000 * 1000 * 10)
            .context("Decompressing transaction")?;
        let transaction =
            serde_json::de::from_slice(&transaction).context("Deserializing transaction")?;

        Ok(Some(transaction))
    }

    pub fn get_transaction_count(
        connection: &Connection,
        block: StarknetBlocksBlockId,
    ) -> anyhow::Result<usize> {
        match block {
            StarknetBlocksBlockId::Number(number) => connection
                .query_row(
                    "SELECT COUNT(*) FROM starknet_transactions WHERE number = ?1",
                    params![number.0],
                    |row| row.get(0),
                )
                .context("Counting transactions"),
            StarknetBlocksBlockId::Hash(hash) => connection
                .query_row(
                    "SELECT COUNT(*) FROM starknet_transactions WHERE hash = ?1",
                    params![&hash.0.as_be_bytes()[..]],
                    |row| row.get(0),
                )
                .context("Counting transactions"),
            StarknetBlocksBlockId::Latest => {
                // First get the latest block
                let block =
                    match StarknetBlocksTable::get(connection, StarknetBlocksBlockId::Latest)? {
                        Some(block) => block.number,
                        None => return Ok(0),
                    };

                Self::get_transaction_count(connection, block.into())
            }
        }
    }
}

/// Describes a Starknet block.
#[derive(Debug, Clone, PartialEq)]
pub struct StarknetBlock {
    pub number: StarknetBlockNumber,
    pub hash: StarknetBlockHash,
    pub root: GlobalRoot,
    pub timestamp: StarknetBlockTimestamp,
}

/// Stores the contract state hash along with its preimage. This is useful to
/// map between the global state tree and the contracts tree.
///
/// Specifically it stores
///
/// - [contract state hash](ContractStateHash)
/// - [contract hash](ContractHash)
/// - [contract root](ContractRoot)
pub struct ContractsStateTable {}

impl ContractsStateTable {
    /// Insert a state hash into the table. Does nothing if the state hash already exists.
    pub fn insert(
        transaction: &Transaction,
        state_hash: ContractStateHash,
        hash: ContractHash,
        root: ContractRoot,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO contract_states ( state_hash,  hash,  root)
                                       VALUES (:state_hash, :hash, :root)
                                       ON CONFLICT DO NOTHING",
            named_params! {
                ":state_hash": &state_hash.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
                ":root": &root.0.to_be_bytes()[..],
            },
        )?;
        Ok(())
    }

    /// Gets the root associated with the given state hash, or [None]
    /// if it does not exist.
    pub fn get_root(
        transaction: &Transaction,
        state_hash: ContractStateHash,
    ) -> anyhow::Result<Option<ContractRoot>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT root FROM contract_states WHERE state_hash = :state_hash",
                named_params! {
                    ":state_hash": &state_hash.0.to_be_bytes()[..]
                },
                |row| row.get("root"),
            )
            .optional()?;

        let bytes = match bytes {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let bytes: [u8; 32] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => anyhow::bail!("Bad contract root length: {}", bytes.len()),
        };

        let root = StarkHash::from_be_bytes(bytes)?;
        let root = ContractRoot(root);

        Ok(Some(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    mod contracts {
        use super::*;

        #[test]
        fn get_root() {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let transaction = connection.transaction().unwrap();

            let state_hash = ContractStateHash(StarkHash::from_hex_str("abc").unwrap());
            let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
            let root = ContractRoot(StarkHash::from_hex_str("def").unwrap());

            ContractsStateTable::insert(&transaction, state_hash, hash, root).unwrap();

            let result = ContractsStateTable::get_root(&transaction, state_hash).unwrap();

            assert_eq!(result, Some(root));
        }
    }

    mod refs {
        use super::*;

        mod l1_l2_head {
            use super::*;

            #[test]
            fn fresh_is_none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let l1_l2_head = RefsTable::get_l1_l2_head(&connection).unwrap();
                assert_eq!(l1_l2_head, None);
            }

            #[test]
            fn set_get() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let expected = Some(StarknetBlockNumber(22));
                RefsTable::set_l1_l2_head(&connection, expected).unwrap();
                assert_eq!(expected, RefsTable::get_l1_l2_head(&connection).unwrap());

                let expected = Some(StarknetBlockNumber(25));
                RefsTable::set_l1_l2_head(&connection, expected).unwrap();
                assert_eq!(expected, RefsTable::get_l1_l2_head(&connection).unwrap());

                RefsTable::set_l1_l2_head(&connection, None).unwrap();
                assert_eq!(None, RefsTable::get_l1_l2_head(&connection).unwrap());
            }
        }
    }

    mod l1_state_table {
        use super::*;

        /// Creates a set of consecutive [StateUpdateLog]s starting from L2 genesis,
        /// with arbitrary other values.
        fn create_updates() -> [StateUpdateLog; 3] {
            (0..3)
                .map(|i| StateUpdateLog {
                    origin: EthOrigin {
                        block: BlockOrigin {
                            hash: EthereumBlockHash(H256::from_low_u64_le(i + 33)),
                            number: EthereumBlockNumber(i + 12_000),
                        },
                        transaction: TransactionOrigin {
                            hash: EthereumTransactionHash(H256::from_low_u64_le(i + 999)),
                            index: EthereumTransactionIndex(i + 20_000),
                        },
                        log_index: EthereumLogIndex(i + 500),
                    },
                    global_root: GlobalRoot(
                        StarkHash::from_hex_str(&"3".repeat(i as usize + 1)).unwrap(),
                    ),
                    block_number: StarknetBlockNumber::GENESIS + i,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }

        mod get {
            use super::*;

            #[test]
            fn none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let non_existent = updates.last().unwrap().block_number + 1;
                assert_eq!(
                    L1StateTable::get(&connection, non_existent.into()).unwrap(),
                    None
                );
            }

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                for (idx, update) in updates.iter().enumerate() {
                    assert_eq!(
                        L1StateTable::get(&connection, update.block_number.into())
                            .unwrap()
                            .as_ref(),
                        Some(update),
                        "Update {}",
                        idx
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    assert_eq!(
                        L1StateTable::get(&connection, L1TableBlockId::Latest).unwrap(),
                        None
                    );
                }

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let updates = create_updates();
                    for update in &updates {
                        L1StateTable::insert(&connection, update).unwrap();
                    }

                    assert_eq!(
                        L1StateTable::get(&connection, L1TableBlockId::Latest)
                            .unwrap()
                            .as_ref(),
                        updates.last()
                    );
                }
            }
        }

        mod get_root {
            use super::*;

            #[test]
            fn none() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let non_existent = updates.last().unwrap().block_number + 1;
                assert_eq!(
                    L1StateTable::get_root(&connection, non_existent.into()).unwrap(),
                    None
                );
            }

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                for (idx, update) in updates.iter().enumerate() {
                    assert_eq!(
                        L1StateTable::get_root(&connection, update.block_number.into()).unwrap(),
                        Some(update.global_root),
                        "Update {}",
                        idx
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    assert_eq!(
                        L1StateTable::get_root(&connection, L1TableBlockId::Latest).unwrap(),
                        None
                    );
                }

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let updates = create_updates();
                    for update in &updates {
                        L1StateTable::insert(&connection, update).unwrap();
                    }

                    assert_eq!(
                        L1StateTable::get_root(&connection, L1TableBlockId::Latest).unwrap(),
                        Some(updates.last().unwrap().global_root)
                    );
                }
            }
        }

        mod reorg {
            use super::*;

            #[test]
            fn full() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                L1StateTable::reorg(&connection, StarknetBlockNumber::GENESIS).unwrap();

                assert_eq!(
                    L1StateTable::get(&connection, L1TableBlockId::Latest).unwrap(),
                    None
                );
            }

            #[test]
            fn partial() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let updates = create_updates();
                for update in &updates {
                    L1StateTable::insert(&connection, update).unwrap();
                }

                let reorg_tail = updates[1].block_number;
                L1StateTable::reorg(&connection, reorg_tail).unwrap();

                assert_eq!(
                    L1StateTable::get(&connection, L1TableBlockId::Latest)
                        .unwrap()
                        .as_ref(),
                    Some(&updates[0])
                );
            }
        }
    }

    mod starknet_blocks {
        use super::*;

        /// Creates a set of consecutive [StarknetBlock]s starting from L2 genesis,
        /// with arbitrary other values.
        fn create_blocks() -> [StarknetBlock; 3] {
            (0..3)
                .map(|i| StarknetBlock {
                    number: StarknetBlockNumber::GENESIS + i,
                    hash: StarknetBlockHash(
                        StarkHash::from_hex_str(&"a".repeat(i as usize + 3)).unwrap(),
                    ),
                    root: GlobalRoot(StarkHash::from_hex_str(&"f".repeat(i as usize + 3)).unwrap()),
                    timestamp: StarknetBlockTimestamp(i + 500),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }

        mod get {
            use super::*;

            mod by_number {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    for block in blocks {
                        let result = StarknetBlocksTable::get(&connection, block.number.into())
                            .unwrap()
                            .unwrap();

                        assert_eq!(result, block);
                    }
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let non_existent = blocks.last().unwrap().number + 1;
                    assert_eq!(
                        StarknetBlocksTable::get(&connection, non_existent.into()).unwrap(),
                        None
                    );
                }
            }

            mod by_hash {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    for block in blocks {
                        let result = StarknetBlocksTable::get(&connection, block.hash.into())
                            .unwrap()
                            .unwrap();

                        assert_eq!(result, block);
                    }
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let non_existent =
                        StarknetBlockHash(StarkHash::from_hex_str(&"b".repeat(10)).unwrap());
                    assert_eq!(
                        StarknetBlocksTable::get(&connection, non_existent.into()).unwrap(),
                        None
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let expected = blocks.last().unwrap();

                    let latest =
                        StarknetBlocksTable::get(&connection, StarknetBlocksBlockId::Latest)
                            .unwrap()
                            .unwrap();
                    assert_eq!(&latest, expected);
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let latest =
                        StarknetBlocksTable::get(&connection, StarknetBlocksBlockId::Latest)
                            .unwrap();
                    assert_eq!(latest, None);
                }
            }
        }

        mod get_root {
            use super::*;

            mod by_number {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    for block in blocks {
                        let root = StarknetBlocksTable::get_root(&connection, block.number.into())
                            .unwrap()
                            .unwrap();

                        assert_eq!(root, block.root);
                    }
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let non_existent = blocks.last().unwrap().number + 1;
                    assert_eq!(
                        StarknetBlocksTable::get_root(&connection, non_existent.into()).unwrap(),
                        None
                    );
                }
            }

            mod by_hash {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    for block in blocks {
                        let root = StarknetBlocksTable::get_root(&connection, block.hash.into())
                            .unwrap()
                            .unwrap();

                        assert_eq!(root, block.root);
                    }
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let non_existent =
                        StarknetBlockHash(StarkHash::from_hex_str(&"b".repeat(10)).unwrap());
                    assert_eq!(
                        StarknetBlocksTable::get_root(&connection, non_existent.into()).unwrap(),
                        None
                    );
                }
            }

            mod latest {
                use super::*;

                #[test]
                fn some() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let blocks = create_blocks();
                    for block in &blocks {
                        StarknetBlocksTable::insert(&connection, block).unwrap();
                    }

                    let expected = blocks.last().map(|block| block.root).unwrap();

                    let latest =
                        StarknetBlocksTable::get_root(&connection, StarknetBlocksBlockId::Latest)
                            .unwrap()
                            .unwrap();
                    assert_eq!(latest, expected);
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let latest_root =
                        StarknetBlocksTable::get_root(&connection, StarknetBlocksBlockId::Latest)
                            .unwrap();
                    assert_eq!(latest_root, None);
                }
            }
        }

        mod reorg {
            use super::*;

            #[test]
            fn full() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                StarknetBlocksTable::reorg(&connection, StarknetBlockNumber::GENESIS).unwrap();

                assert_eq!(
                    StarknetBlocksTable::get(&connection, StarknetBlocksBlockId::Latest).unwrap(),
                    None
                );
            }

            #[test]
            fn partial() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                let reorg_tail = blocks[1].number;
                StarknetBlocksTable::reorg(&connection, reorg_tail).unwrap();

                let expected = StarknetBlock {
                    number: blocks[0].number,
                    hash: blocks[0].hash,
                    root: blocks[0].root,
                    timestamp: blocks[0].timestamp,
                };

                assert_eq!(
                    StarknetBlocksTable::get(&connection, StarknetBlocksBlockId::Latest).unwrap(),
                    Some(expected)
                );
            }
        }
    }
}
