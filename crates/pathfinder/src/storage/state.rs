use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{named_params, params, Connection, OptionalExtension, Params, Transaction};
use web3::types::H256;

use crate::{
    core::{
        ContractHash, ContractRoot, ContractStateHash, EthereumBlockHash, EthereumBlockNumber,
        EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex, GlobalRoot,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
    },
    ethereum::{log::StateUpdateLog, BlockOrigin, EthOrigin, TransactionOrigin},
    sequencer::reply::transaction,
};

/// Contains the [L1 Starknet update logs](StateUpdateLog).
pub struct L1StateTable {}

impl L1StateTable {
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

    pub fn get_root(connection: &Connection, block: BlockId) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = match block {
            BlockId::Number(_) => {
                connection.prepare("SELECT starknet_global_root FROM l1_state WHERE starknet_block_number = ?")
            }
            BlockId::Latest => connection
                .prepare("SELECT starknet_global_root FROM l1_state ORDER BY starknet_block_number DESC LIMIT 1"),
        }?;

        let mut rows = match block {
            BlockId::Number(number) => statement.query(params![number.0]),
            BlockId::Latest => statement.query([]),
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

    pub fn get(connection: &Connection, block: BlockId) -> anyhow::Result<Option<StateUpdateLog>> {
        let mut statement = match block {
            BlockId::Number(_) => connection.prepare(
                r"SELECT starknet_block_number,
                    starknet_global_root,
                    ethereum_block_hash,
                    ethereum_block_number,
                    ethereum_transaction_hash,
                    ethereum_transaction_index,
                    ethereum_log_index
                FROM l1_state WHERE starknet_block_number = ?",
            ),
            BlockId::Latest => connection.prepare(
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
            BlockId::Number(number) => statement.query(params![number.0]),
            BlockId::Latest => statement.query([]),
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
    pub fn get_l1_l2_head(connection: &Connection) -> anyhow::Result<Option<StarknetBlockNumber>> {
        // This table always contains exactly one row.
        let block_number =
            connection.query_row("SELECT l1_l2_head FROM refs WHERE rowid = 1", [], |row| {
                let block_number = row
                    .get_ref_unwrap(0)
                    .as_i64_or_null()
                    .unwrap()
                    .map(|x| StarknetBlockNumber(x as u64));

                Ok(block_number)
            })?;

        Ok(block_number)
    }

    pub fn set_l1_l2_head(
        connection: &Connection,
        head: Option<StarknetBlockNumber>,
    ) -> anyhow::Result<()> {
        match head {
            Some(number) => {
                connection.execute("UPDATE refs SET l1_l2_head = ? WHERE rowid = 1", [number.0])
            }
            None => connection.execute("UPDATE refs SET l1_l2_head = NULL WHERE rowid = 1", []),
        }?;

        Ok(())
    }
}
/// Stores all knowm [StarknetBlocks][StarknetBlock].
pub struct StarknetBlocksTable {}
impl StarknetBlocksTable {
    pub fn insert(connection: &Connection, block: &StarknetBlock) -> anyhow::Result<()> {
        let transactions =
            serde_json::ser::to_vec(&block.transactions).context("Serialize transactions")?;
        let receipts = serde_json::ser::to_vec(&block.transaction_receipts)
            .context("Serialize transaction receipts")?;

        // TODO: compress transactions...

        connection.execute(
        r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp,  transactions,  transaction_receipts)
                               VALUES (:number, :hash, :root, :timestamp, :transactions, :transaction_receipts)",
        named_params! {
                ":number": block.number.0,
                ":hash": &block.hash.0.as_be_bytes()[..],
                ":root": &block.root.0.as_be_bytes()[..],
                ":timestamp": block.timestamp.0,
                ":transactions": &transactions,
                ":transaction_receipts": &receipts,
            },
        )?;

        Ok(())
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

    pub fn get_hash(
        connection: &Connection,
        block: BlockId,
    ) -> anyhow::Result<Option<StarknetBlockHash>> {
        let mut statement = match block {
            BlockId::Number(_) => {
                connection.prepare("SELECT hash FROM starknet_blocks WHERE number = ?")
            }
            BlockId::Latest => {
                connection.prepare("SELECT hash FROM starknet_blocks ORDER BY number DESC LIMIT 1")
            }
        }?;

        let mut rows = match block {
            BlockId::Number(number) => statement.query(params![number.0]),
            BlockId::Latest => statement.query([]),
        }?;

        let root = rows.next().context("Iterate rows")?;

        match root {
            Some(row) => {
                // unwrap is safe as the first column must exist from the query.
                let hash = row.get_ref_unwrap(0).as_blob()?;
                // unwrap is safe, unless database is corrupted.
                let hash = StarkHash::from_be_slice(hash).unwrap();
                let hash = StarknetBlockHash(hash);
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    pub fn get_root(connection: &Connection, block: BlockId) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = match block {
            BlockId::Number(_) => {
                connection.prepare("SELECT root FROM starknet_blocks WHERE number = ?")
            }
            BlockId::Latest => {
                connection.prepare("SELECT root FROM starknet_blocks ORDER BY number DESC LIMIT 1")
            }
        }?;

        let mut rows = match block {
            BlockId::Number(number) => statement.query(params![number.0]),
            BlockId::Latest => statement.query([]),
        }?;

        let root = rows.next().context("Iterate rows")?;

        match root {
            Some(row) => {
                // unwrap is safe as the first column must exist from the query.
                let root = row.get_ref_unwrap(0).as_blob()?;
                // unwrap is safe, unless database is corrupted.
                let root = StarkHash::from_be_slice(root).unwrap();
                let root = GlobalRoot(root);
                Ok(Some(root))
            }
            None => Ok(None),
        }
    }
}

pub enum BlockId {
    Number(StarknetBlockNumber),
    Latest,
}

impl From<StarknetBlockNumber> for BlockId {
    fn from(number: StarknetBlockNumber) -> Self {
        BlockId::Number(number)
    }
}

/// Describes a Starknet block.
#[derive(Debug, Clone)]
pub struct StarknetBlock {
    pub number: StarknetBlockNumber,
    pub hash: StarknetBlockHash,
    pub root: GlobalRoot,
    pub timestamp: StarknetBlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
}

/// Stores descriptions of the global StarkNet state. This data contains
/// StarkNet block metadata as well as the origin point on Ethereum.
///
/// For more specific information, see [GlobalStateTable].
pub struct GlobalStateTable {}

/// A StarkNet global state record from [GlobalStateTable] along with the Ethereum
/// point of origin for this record.
///
/// Essentially this represents a Starknet block and its meta-data.
#[derive(Debug, Clone, PartialEq)]
pub struct GlobalStateRecord {
    /// The StarkNet block number of this state.
    pub block_number: StarknetBlockNumber,
    /// The StarkNet block hash of this state.
    pub block_hash: StarknetBlockHash,
    /// The timestamp of this block.
    pub block_timestamp: StarknetBlockTimestamp,
    /// The StarkNet global root of this state.
    pub global_root: GlobalRoot,
    /// The Ethereum block number this StarkNet state was confirmed on.
    pub eth_block_number: EthereumBlockNumber,
    /// The Ethereum block hash this StarkNet state was confirmed on.
    pub eth_block_hash: EthereumBlockHash,
    /// The Ethereum transaction's hash this StarkNet state was confirmed on.
    pub eth_tx_hash: EthereumTransactionHash,
    /// The Ethereum transaction's index this StarkNet state was confirmed on.
    pub eth_tx_index: EthereumTransactionIndex,
    /// StarkNet state updates are emitted as log events by the Ethereum StarkNet core contract.
    /// This is the log index linked to this StarkNet state.
    pub eth_log_index: EthereumLogIndex,
}

impl GlobalStateTable {
    /// Inserts a new StarkNet global state.
    ///
    /// Does nothing if the [StarkNet block hash](StarknetBlockHash) already exists.
    ///
    /// Note that the [EthereumTransactionHash] must reference a valid transaction hash
    /// stored in [EthereumTransactionsTable](crate::storage::EthereumTransactionsTable).
    pub fn insert(
        transaction: &Transaction,
        block_number: StarknetBlockNumber,
        block_hash: StarknetBlockHash,
        block_timestamp: StarknetBlockTimestamp,
        global_root: GlobalRoot,
        eth_transaction: EthereumTransactionHash,
        eth_log_index: EthereumLogIndex,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO global_state (
                    starknet_block_number,
                    starknet_block_hash,
                    starknet_block_timestamp,
                    starknet_global_root,
                    ethereum_transaction_hash,
                    ethereum_log_index
                ) VALUES (
                    :starknet_block_number,
                    :starknet_block_hash,
                    :starknet_block_timestamp,
                    :starknet_global_root,
                    :ethereum_transaction_hash,
                    :ethereum_log_index
                )
            ",
            named_params! {
                    ":starknet_block_number": block_number.0,
                    ":starknet_block_hash": &block_hash.0.to_be_bytes()[..],
                    ":starknet_block_timestamp": block_timestamp.0,
                    ":starknet_global_root": &global_root.0.to_be_bytes()[..],
                    ":ethereum_transaction_hash": eth_transaction.0.as_bytes(),
                    ":ethereum_log_index": eth_log_index.0,
            },
        )?;
        Ok(())
    }

    pub fn get_state_at_block_number(
        transaction: &Transaction,
        block: StarknetBlockNumber,
    ) -> anyhow::Result<Option<GlobalStateRecord>> {
        Self::state_query_row(
            transaction,
            r"SELECT
                global_state.starknet_block_number      as starknet_block_number,
                global_state.starknet_block_hash        as starknet_block_hash,
                global_state.starknet_global_root       as starknet_global_root,
                global_state.starknet_block_timestamp   as starknet_block_timestamp,
                global_state.ethereum_log_index         as ethereum_log_index,
                ethereum_transactions.hash              as ethereum_transaction_hash,
                ethereum_transactions.idx               as ethereum_transaction_index,
                ethereum_blocks.number                  as ethereum_block_number,
                ethereum_blocks.hash                    as ethereum_block_hash
            FROM global_state
            JOIN ethereum_transactions ON global_state.ethereum_transaction_hash = ethereum_transactions.hash
            JOIN ethereum_blocks ON ethereum_transactions.block_hash = ethereum_blocks.hash
            WHERE starknet_block_number = :starknet_block_number
            LIMIT 1",
            named_params! { ":starknet_block_number": block.0 },
        )
    }

    fn state_query_row<P: Params>(
        transaction: &Transaction,
        sql_query: &str,
        params: P,
    ) -> anyhow::Result<Option<GlobalStateRecord>> {
        let row = transaction
            .query_row(sql_query, params, |row| {
                let block_number = StarknetBlockNumber(row.get("starknet_block_number")?);
                let block_timestamp = StarknetBlockTimestamp(row.get("starknet_block_timestamp")?);
                let eth_block_number = EthereumBlockNumber(row.get("ethereum_block_number")?);
                let tx_index = EthereumTransactionIndex(row.get("ethereum_transaction_index")?);
                let log_index = EthereumLogIndex(row.get("ethereum_log_index")?);

                // Unfortunately there is no way to return a non-rusqlite error here so can't convert these yet.
                let block_hash: Vec<u8> = row.get("starknet_block_hash")?;
                let root: Vec<u8> = row.get("starknet_global_root")?;
                let eth_block_hash: Vec<u8> = row.get("ethereum_block_hash")?;
                let tx_hash: Vec<u8> = row.get("ethereum_transaction_hash")?;

                Ok((
                    block_number,
                    block_hash,
                    block_timestamp,
                    root,
                    eth_block_number,
                    eth_block_hash,
                    tx_hash,
                    tx_index,
                    log_index,
                ))
            })
            .optional()?;

        let row = row.map(
            |(
                block_number,
                block_hash,
                block_timestamp,
                global_root,
                eth_block_number,
                eth_block_hash,
                eth_tx_hash,
                eth_tx_index,
                eth_log_index,
            )|
             -> anyhow::Result<GlobalStateRecord> {
                let block_hash = StarkHash::from_be_slice(&block_hash)
                    .context("Failed to parse StarkNet block hash")?;
                let global_root = StarkHash::from_be_slice(&global_root)
                    .context("Failed to parse StarkNet global state root")?;

                fn vec_to_h256(bytes: Vec<u8>) -> anyhow::Result<H256> {
                    let bytes: [u8; 32] = match bytes.try_into() {
                        Ok(bytes) => bytes,
                        Err(bad_len) => {
                            anyhow::bail!("Expected exactly 32 bytes but got {}", bad_len.len())
                        }
                    };
                    Ok(H256(bytes))
                }

                let eth_tx_hash = vec_to_h256(eth_tx_hash)
                    .context("Failed to parse Ethereum transaction hash")?;
                let eth_block_hash =
                    vec_to_h256(eth_block_hash).context("Failed to parse Ethereum block hash")?;

                Ok(GlobalStateRecord {
                    block_number,
                    block_hash: StarknetBlockHash(block_hash),
                    block_timestamp,
                    global_root: GlobalRoot(global_root),
                    eth_block_number,
                    eth_block_hash: EthereumBlockHash(eth_block_hash),
                    eth_tx_hash: EthereumTransactionHash(eth_tx_hash),
                    eth_tx_index,
                    eth_log_index,
                })
            },
        );

        row.transpose()
    }

    /// Retrieves the latest global StarkNet state from the [GlobalStateTable]. Latest is defined as the
    /// record with the largest [StarknetBlockNumber].
    pub fn get_latest_state(
        transaction: &Transaction,
    ) -> anyhow::Result<Option<GlobalStateRecord>> {
        Self::state_query_row(
            transaction,
            r"SELECT
                global_state.starknet_block_number      as starknet_block_number,
                global_state.starknet_block_hash        as starknet_block_hash,
                global_state.starknet_global_root       as starknet_global_root,
                global_state.starknet_block_timestamp   as starknet_block_timestamp,
                global_state.ethereum_log_index         as ethereum_log_index,
                ethereum_transactions.hash              as ethereum_transaction_hash,
                ethereum_transactions.idx               as ethereum_transaction_index,
                ethereum_blocks.number                  as ethereum_block_number,
                ethereum_blocks.hash                    as ethereum_block_hash
            FROM global_state
            JOIN ethereum_transactions ON global_state.ethereum_transaction_hash = ethereum_transactions.hash
            JOIN ethereum_blocks ON ethereum_transactions.block_hash = ethereum_blocks.hash
            ORDER BY starknet_block_number DESC
            LIMIT 1",
            [],
        )
    }

    /// Gets globabl state root for particular block hash.
    pub fn get_root_at_block_hash(
        transaction: &Transaction,
        block: StarknetBlockHash,
    ) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = transaction.prepare(
            r"SELECT starknet_global_root FROM global_state
            WHERE starknet_block_hash = :starknet_block_hash
            LIMIT 1",
        )?;
        let mut rows = statement
            .query(named_params! { ":starknet_block_hash": &block.0.to_be_bytes()[..] })?;
        let row = rows
            .next()
            .with_context(|| format!("Get global root for block {}", block.0))?;
        match row {
            Some(row) => {
                let bytes = row
                    .get_ref_unwrap(0)
                    .as_blob()
                    .with_context(|| format!("Parse global root for block {}", block.0))?;
                Ok(Some(GlobalRoot(StarkHash::from_be_slice(bytes)?)))
            }
            None => Ok(None),
        }
    }

    /// Gets globabl state root for the latest block.
    pub fn get_latest_root(transaction: &Transaction) -> anyhow::Result<Option<GlobalRoot>> {
        let mut statement = transaction.prepare(
            r"SELECT starknet_global_root FROM global_state
            ORDER BY starknet_block_number DESC
            LIMIT 1",
        )?;
        let mut rows = statement.query([])?;
        let row = rows.next().context("Get global root for latest block")?;
        match row {
            Some(row) => {
                let bytes = row
                    .get_ref_unwrap(0)
                    .as_blob()
                    .context("Parse global root for latest block")?;
                Ok(Some(GlobalRoot(StarkHash::from_be_slice(bytes)?)))
            }
            None => Ok(None),
        }
    }
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

    mod global {
        use std::str::FromStr;

        use crate::storage::{self};

        use super::*;

        mod insert {
            use super::*;

            #[test]
            fn fails_if_eth_origin_missing() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                // The table is joined with the Ethereum block and transaction tables,
                // so we have to create the full database.
                storage::migrate_database(&transaction).unwrap();

                GlobalStateTable::insert(
                    &transaction,
                    StarknetBlockNumber(10),
                    StarknetBlockHash(StarkHash::from_hex_str("123").unwrap()),
                    StarknetBlockTimestamp(22),
                    GlobalRoot(StarkHash::from_hex_str("111").unwrap()),
                    EthereumTransactionHash(H256::from_str(&"abca".repeat(64 / 4)).unwrap()),
                    EthereumLogIndex(99),
                )
                .unwrap_err();
            }
        }

        mod get_state_at_block_number {
            use super::*;

            #[test]
            fn none() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                storage::migrate_database(&transaction).unwrap();

                let latest = GlobalStateTable::get_state_at_block_number(
                    &transaction,
                    StarknetBlockNumber(0),
                )
                .unwrap();
                assert_eq!(latest, None);
            }

            #[test]
            fn some() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();
                storage::migrate_database(&transaction).unwrap();

                // Data to insert
                let record = GlobalStateRecord {
                    block_number: StarknetBlockNumber(10),
                    block_hash: StarknetBlockHash(StarkHash::from_hex_str("123").unwrap()),
                    block_timestamp: StarknetBlockTimestamp(22),
                    global_root: GlobalRoot(StarkHash::from_hex_str("111").unwrap()),
                    eth_block_number: EthereumBlockNumber(2003),
                    eth_block_hash: EthereumBlockHash(
                        H256::from_str(&"abca".repeat(64 / 4)).unwrap(),
                    ),
                    eth_tx_hash: EthereumTransactionHash(
                        H256::from_str(&"defa".repeat(64 / 4)).unwrap(),
                    ),
                    eth_tx_index: EthereumTransactionIndex(14),
                    eth_log_index: EthereumLogIndex(99),
                };

                storage::EthereumBlocksTable::insert(
                    &transaction,
                    record.eth_block_hash,
                    record.eth_block_number,
                )
                .unwrap();

                storage::EthereumTransactionsTable::insert(
                    &transaction,
                    record.eth_block_hash,
                    record.eth_tx_hash,
                    record.eth_tx_index,
                )
                .unwrap();

                GlobalStateTable::insert(
                    &transaction,
                    record.block_number,
                    record.block_hash,
                    record.block_timestamp,
                    record.global_root,
                    record.eth_tx_hash,
                    record.eth_log_index,
                )
                .unwrap();

                let result =
                    GlobalStateTable::get_state_at_block_number(&transaction, record.block_number)
                        .unwrap();
                assert_eq!(result, Some(record));
            }
        }

        mod get_latest {
            use super::*;

            #[test]
            fn some() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                // Data to insert
                let first = GlobalStateRecord {
                    block_number: StarknetBlockNumber(10),
                    block_hash: StarknetBlockHash(StarkHash::from_hex_str("123").unwrap()),
                    block_timestamp: StarknetBlockTimestamp(22),
                    global_root: GlobalRoot(StarkHash::from_hex_str("111").unwrap()),
                    eth_block_number: EthereumBlockNumber(2003),
                    eth_block_hash: EthereumBlockHash(
                        H256::from_str(&"abca".repeat(64 / 4)).unwrap(),
                    ),
                    eth_tx_hash: EthereumTransactionHash(
                        H256::from_str(&"defa".repeat(64 / 4)).unwrap(),
                    ),
                    eth_tx_index: EthereumTransactionIndex(14),
                    eth_log_index: EthereumLogIndex(99),
                };

                let second = GlobalStateRecord {
                    block_number: StarknetBlockNumber(11),
                    block_hash: StarknetBlockHash(StarkHash::from_hex_str("3512234").unwrap()),
                    block_timestamp: StarknetBlockTimestamp(33),
                    global_root: GlobalRoot(StarkHash::from_hex_str("9371").unwrap()),
                    eth_block_number: EthereumBlockNumber(98123),
                    eth_block_hash: EthereumBlockHash(
                        H256::from_str(&"267ddfec".repeat(64 / 8)).unwrap(),
                    ),
                    eth_tx_hash: EthereumTransactionHash(
                        H256::from_str(&"897ffeda".repeat(64 / 8)).unwrap(),
                    ),
                    eth_tx_index: EthereumTransactionIndex(84),
                    eth_log_index: EthereumLogIndex(31004),
                };

                let third = GlobalStateRecord {
                    block_number: StarknetBlockNumber(12),
                    block_hash: StarknetBlockHash(StarkHash::from_hex_str("35aac12234").unwrap()),
                    block_timestamp: StarknetBlockTimestamp(44),
                    global_root: GlobalRoot(StarkHash::from_hex_str("937addd1").unwrap()),
                    eth_block_number: EthereumBlockNumber(11298123),
                    eth_block_hash: EthereumBlockHash(
                        H256::from_str(&"333eefec".repeat(64 / 8)).unwrap(),
                    ),
                    eth_tx_hash: EthereumTransactionHash(
                        H256::from_str(&"333ffeda".repeat(64 / 8)).unwrap(),
                    ),
                    eth_tx_index: EthereumTransactionIndex(84),
                    eth_log_index: EthereumLogIndex(31004),
                };

                // The table is joined with the Ethereum block and transaction tables,
                // so we have to create the full database.
                storage::migrate_database(&transaction).unwrap();

                // Insert Ethereum data
                storage::EthereumBlocksTable::insert(
                    &transaction,
                    first.eth_block_hash,
                    first.eth_block_number,
                )
                .unwrap();
                storage::EthereumBlocksTable::insert(
                    &transaction,
                    second.eth_block_hash,
                    second.eth_block_number,
                )
                .unwrap();
                storage::EthereumBlocksTable::insert(
                    &transaction,
                    third.eth_block_hash,
                    third.eth_block_number,
                )
                .unwrap();

                storage::EthereumTransactionsTable::insert(
                    &transaction,
                    first.eth_block_hash,
                    first.eth_tx_hash,
                    first.eth_tx_index,
                )
                .unwrap();
                storage::EthereumTransactionsTable::insert(
                    &transaction,
                    second.eth_block_hash,
                    second.eth_tx_hash,
                    second.eth_tx_index,
                )
                .unwrap();
                storage::EthereumTransactionsTable::insert(
                    &transaction,
                    third.eth_block_hash,
                    third.eth_tx_hash,
                    third.eth_tx_index,
                )
                .unwrap();

                // Insert StarkNet state data out of order.
                GlobalStateTable::insert(
                    &transaction,
                    first.block_number,
                    first.block_hash,
                    first.block_timestamp,
                    first.global_root,
                    first.eth_tx_hash,
                    first.eth_log_index,
                )
                .unwrap();
                GlobalStateTable::insert(
                    &transaction,
                    third.block_number,
                    third.block_hash,
                    third.block_timestamp,
                    third.global_root,
                    third.eth_tx_hash,
                    third.eth_log_index,
                )
                .unwrap();
                GlobalStateTable::insert(
                    &transaction,
                    second.block_number,
                    second.block_hash,
                    second.block_timestamp,
                    second.global_root,
                    second.eth_tx_hash,
                    second.eth_log_index,
                )
                .unwrap();

                let latest = GlobalStateTable::get_latest_state(&transaction).unwrap();
                assert_eq!(latest, Some(third));
            }

            #[test]
            fn none() {
                let mut conn = rusqlite::Connection::open_in_memory().unwrap();
                let transaction = conn.transaction().unwrap();

                storage::migrate_database(&transaction).unwrap();

                let latest = GlobalStateTable::get_latest_state(&transaction).unwrap();
                assert_eq!(latest, None);
            }
        }
    }

    mod contracts {
        use super::*;

        #[test]
        fn get_root() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            crate::storage::migrate_to_1(&transaction).unwrap();

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
                        L1StateTable::get(&connection, BlockId::Latest).unwrap(),
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
                        L1StateTable::get(&connection, BlockId::Latest)
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
                        L1StateTable::get_root(&connection, BlockId::Latest).unwrap(),
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
                        L1StateTable::get_root(&connection, BlockId::Latest).unwrap(),
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
                    L1StateTable::get(&connection, BlockId::Latest).unwrap(),
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
                    L1StateTable::get(&connection, BlockId::Latest)
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
                    transaction_receipts: Vec::new(),
                    transactions: Vec::new(),
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }

        mod get {
            use super::*;

            #[test]
            fn some() {
                let storage = Storage::in_memory().unwrap();
                let connection = storage.connection().unwrap();

                let blocks = create_blocks();
                for block in &blocks {
                    StarknetBlocksTable::insert(&connection, block).unwrap();
                }

                for (idx, block) in blocks.iter().enumerate() {
                    assert_eq!(
                        StarknetBlocksTable::get_root(&connection, block.number.into()).unwrap(),
                        Some(block.root),
                        "Update {}",
                        idx
                    );

                    assert_eq!(
                        StarknetBlocksTable::get_hash(&connection, block.number.into()).unwrap(),
                        Some(block.hash),
                        "Update {}",
                        idx
                    );
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
                assert_eq!(
                    StarknetBlocksTable::get_hash(&connection, non_existent.into()).unwrap(),
                    None
                );
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

                    let latest_root = StarknetBlocksTable::get_root(&connection, BlockId::Latest)
                        .unwrap()
                        .unwrap();
                    assert_eq!(latest_root, blocks.last().unwrap().root);

                    let latest_hash = StarknetBlocksTable::get_hash(&connection, BlockId::Latest)
                        .unwrap()
                        .unwrap();
                    assert_eq!(latest_hash, blocks.last().unwrap().hash);
                }

                #[test]
                fn none() {
                    let storage = Storage::in_memory().unwrap();
                    let connection = storage.connection().unwrap();

                    let latest_root =
                        StarknetBlocksTable::get_root(&connection, BlockId::Latest).unwrap();
                    assert_eq!(latest_root, None);

                    let latest_hash =
                        StarknetBlocksTable::get_hash(&connection, BlockId::Latest).unwrap();
                    assert_eq!(latest_hash, None);
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
                    StarknetBlocksTable::get_root(&connection, BlockId::Latest).unwrap(),
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

                assert_eq!(
                    StarknetBlocksTable::get_root(&connection, BlockId::Latest)
                        .unwrap()
                        .as_ref(),
                    Some(&blocks[0].root)
                );
            }
        }
    }
}
