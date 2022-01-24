use anyhow::Context;
use rusqlite::{named_params, Transaction};

use crate::{
    core::{
        EthereumBlockHash, EthereumBlockNumber, EthereumTransactionHash, EthereumTransactionIndex,
    },
    storage::{DB_VERSION_CURRENT, DB_VERSION_EMPTY},
};

/// Migrates [GlobalStateTable] and [ContractsStateTable] to the [current version](DB_VERSION_CURRENT).
pub fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
    EthereumBlocksTable::migrate(transaction, from_version)
        .context("Failed to migrate the Ethereum blocks table")?;
    EthereumTransactionsTable::migrate(transaction, from_version)
        .context("Failed to migrate the Ethereum transactionns table")
}

/// Stores basic information about an Ethereum block, enough to descibe it as a unique point
/// of origin. This lets us link StarkNet information to a point in Ethereum's history.
///
/// Specifically, this stores an Ethereum block's
/// - [block hash](EthereumBlockHash)
/// - [block number](EthereumBlockNumber)
pub struct EthereumBlocksTable {}

impl EthereumBlocksTable {
    /// Migrates the [EthereumBlocksTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {} // Fresh database, continue to create table.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        transaction.execute(
            r"CREATE TABLE ethereum_blocks (
                    ethereum_block_hash   BLOB PRIMARY KEY,
                    ethereum_block_number INTEGER NOT NULL
                )",
            [],
        )?;

        Ok(())
    }

    /// Inserts a new Ethereum block with the given [hash](EthereumBlockHash) and [number](EthereumBlockNumber).
    ///
    /// Does nothing if the hash already exists.
    pub fn insert(
        transaction: &Transaction,
        hash: EthereumBlockHash,
        number: EthereumBlockNumber,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO ethereum_blocks ( ethereum_block_hash,  ethereum_block_number)
                                       VALUES (:ethereum_block_hash, :ethereum_block_number)
                                       ON CONFLICT DO NOTHING",
            named_params! {
                ":ethereum_block_hash": hash.0.as_bytes(),
                ":ethereum_block_number": number.0,
            },
        )?;
        Ok(())
    }
}

/// Stores basic information about an Ethereum transaction, enough to descibe it as a unique point
/// of origin. This lets us link StarkNet information to a point in Ethereum's history.
///
/// Specifically, this stores an Ethereum transactions
/// - [transaction hash](EthereumTransactionHash)
/// - [transaction index](EthereumTransactionIndex)
/// - [block hash](EthereumBlockHash)
pub struct EthereumTransactionsTable {}

impl EthereumTransactionsTable {
    /// Migrates the [EthereumTransactionsTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {} // Fresh database, continue to create table.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        // TODO: consider ON DELETE CASCADE when we start cleaning up. Don't forget to document if we use it.
        transaction.execute(
            r"CREATE TABLE ethereum_transactions (
                    ethereum_transaction_hash    BLOB PRIMARY KEY,
                    ethereum_transaction_index   INTEGER NOT NULL,
                    ethereum_block_hash          BLOB NOT NULL,

                    FOREIGN KEY(ethereum_block_hash) REFERENCES ethereum_blocks(ethereum_block_hash)
                )",
            [],
        )?;

        Ok(())
    }

    /// Insert a new Ethereum transaction.
    ///
    /// Does nothing if the ethereum hash already exists.
    ///
    /// Note that [block_hash](EthereumBlockHash) must reference an
    /// Ethereum block stored in [EthereumBlocksTable].
    pub fn insert(
        transaction: &Transaction,
        block_hash: EthereumBlockHash,
        tx_hash: EthereumTransactionHash,
        tx_index: EthereumTransactionIndex,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO ethereum_transactions ( ethereum_transaction_hash,  ethereum_transaction_index,  ethereum_block_hash)
                                             VALUES (:ethereum_transaction_hash, :ethereum_transaction_index, :ethereum_block_hash)
                                             ON CONFLICT DO NOTHING",
            named_params! {
                ":ethereum_transaction_hash": tx_hash.0.as_bytes(),
                ":ethereum_transaction_index": tx_index.0,
                ":ethereum_block_hash": block_hash.0.as_bytes(),
            },
        )?;
        Ok(())
    }
}
