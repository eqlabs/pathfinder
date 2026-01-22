//! Note that functions in this module fail on normal pathfinder
//! storage (because they use a consensus-specific table).

use std::num::NonZeroU32;
use std::path::Path;

use anyhow::Context;
use pathfinder_common::ContractAddress;
use rusqlite::TransactionBehavior;

use crate::error::StorageError;
use crate::prelude::*;
use crate::pruning::BlockchainHistoryMode;
use crate::{Connection, JournalMode, Storage, StorageBuilder, TriePruneMode};

/// The inner storage is not pub on purpose because we want to disallow
/// utilization of non-consensus specific database APIs.
#[derive(Clone)]
pub struct ConsensusStorage(Storage);

/// The inner connection is not pub on purpose because we want to disallow
/// creation of non-consensus specific database connections.
pub struct ConsensusConnection(Connection);

/// The inner transaction is not pub on purpose because we want to disallow
/// creation of non-consensus specific database transactions.
pub struct ConsensusTransaction<'inner>(Transaction<'inner>);

/// To avoid API bloat and code duplication, we reuse the normal storage
/// internally, which means the consensus storage also undergoes the same
/// migrations, which results in creating tables that are main storage specific
/// and are not utilized at all. The same applies to the running event filter,
/// trie prune mode and blockchain history mode, which all remain unused in this
/// database. This is acceptable for now, since consensus-specific tables will
/// be at some point merged into the main storage and consensus storage will
/// be removed altogether.
pub fn open_consensus_storage(data_directory: &Path) -> anyhow::Result<ConsensusStorage> {
    let storage_manager = StorageBuilder::file(data_directory.join("consensus.sqlite")) // TODO: https://github.com/eqlabs/pathfinder/issues/3047
        .journal_mode(JournalMode::WAL)
        .trie_prune_mode(Some(TriePruneMode::Archive))
        .blockchain_history_mode(Some(BlockchainHistoryMode::Archive))
        .migrate()?;
    let consensus_storage = storage_manager.create_pool(NonZeroU32::new(5).unwrap())?;

    let consensus_storage = ConsensusStorage(consensus_storage);
    let mut db_conn = consensus_storage
        .connection()
        .context("Creating database connection")?;
    let db_tx = db_conn
        .transaction()
        .context("Creating database transaction")?;
    db_tx.ensure_consensus_proposals_table_exists()?;
    db_tx.ensure_consensus_finalized_blocks_table_exists()?;
    db_tx.commit()?;
    Ok(consensus_storage)
}

pub fn open_consensus_storage_readonly(data_directory: &Path) -> anyhow::Result<ConsensusStorage> {
    let storage_manager =
        StorageBuilder::file(data_directory.join("consensus.sqlite")).readonly()?;
    let consensus_storage = storage_manager.create_read_only_pool(NonZeroU32::new(5).unwrap())?;
    Ok(ConsensusStorage(consensus_storage))
}

impl ConsensusStorage {
    pub fn in_tempdir() -> anyhow::Result<ConsensusStorage> {
        let tempdir = tempfile::tempdir()?.keep();
        let consensus_storage = open_consensus_storage(&tempdir)?;
        Ok(consensus_storage)
    }

    pub fn connection(&self) -> Result<ConsensusConnection, StorageError> {
        let conn = self.0.connection()?;
        Ok(ConsensusConnection(conn))
    }
}

impl ConsensusConnection {
    pub fn transaction(&mut self) -> Result<ConsensusTransaction<'_>, StorageError> {
        let tx = self.0.transaction()?;
        Ok(ConsensusTransaction(tx))
    }

    pub fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> Result<ConsensusTransaction<'_>, StorageError> {
        let tx = self.0.transaction_with_behavior(behavior)?;
        Ok(ConsensusTransaction(tx))
    }
}

impl ConsensusTransaction<'_> {
    pub fn commit(self) -> Result<(), StorageError> {
        Ok(self.0.transaction.commit()?)
    }

    pub fn ensure_consensus_proposals_table_exists(&self) -> Result<(), StorageError> {
        self.0.inner().execute(
            r"CREATE TABLE IF NOT EXISTS consensus_proposals (
                    height      INTEGER NOT NULL,
                    round       INTEGER NOT NULL,
                    proposer    BLOB NOT NULL,
                    parts       BLOB NOT NULL,
                    UNIQUE(height, round, proposer)
            )",
            [],
        )?;
        Ok(())
    }

    pub fn persist_consensus_proposal_parts(
        &self,
        height: u64,
        round: u32,
        proposer: &ContractAddress,
        parts: &[u8], // repeated ProposalPart
    ) -> Result<bool, StorageError> {
        let count = self.0.inner().query_row(
            r"SELECT count(*)
            FROM consensus_proposals
            WHERE height = :height AND round = :round AND proposer = :proposer",
            named_params! {
                ":height": &height,
                ":round": &round,
                ":proposer": proposer,
            },
            |row| row.get_i64(0),
        )?;

        if count == 0 {
            self.0
                .inner()
                .execute(
                    r"
                    INSERT INTO consensus_proposals
                    (height, round, proposer, parts)
                    VALUES (:height, :round, :proposer, :parts)
                    ",
                    named_params! {
                        ":height": &height,
                        ":round": &round,
                        ":proposer": proposer,
                        ":parts": &parts,
                    },
                )
                .context("Inserting consensus proposal parts")?;
        } else {
            self.0
                .inner()
                .execute(
                    r"
                    UPDATE consensus_proposals
                    SET parts = :parts
                    WHERE height = :height AND round = :round AND proposer = :proposer",
                    named_params! {
                        ":height": &height,
                        ":round": &round,
                        ":proposer": proposer,
                        ":parts": &parts,
                    },
                )
                .context("Updating consensus proposal parts")?;
        }

        Ok(count > 0)
    }

    pub fn own_consensus_proposal_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT parts
                FROM consensus_proposals
                WHERE height = :height AND round = :round AND proposer = :proposer",
                named_params! {
                    ":height": &height,
                    ":round": &round,
                    ":proposer": validator,
                },
                |row| row.get_blob(0).map(|x| x.to_vec()),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn foreign_consensus_proposal_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT parts
                FROM consensus_proposals
                WHERE height = :height AND round = :round AND proposer <> :proposer",
                named_params! {
                    ":height": &height,
                    ":round": &round,
                    ":proposer": validator,
                },
                |row| row.get_blob(0).map(|x| x.to_vec()),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn last_consensus_proposal_parts(
        &self,
        height: u64,
        validator: &ContractAddress,
    ) -> Result<Option<(i64, Vec<u8>)>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"
                SELECT parts, round
                FROM consensus_proposals
                WHERE height = :height AND proposer <> :proposer
                ORDER BY round DESC
                LIMIT 1",
                named_params! {
                    ":height": &height,
                    ":proposer": validator,
                },
                |row| {
                    let buf = row.get_blob(0).map(|x| x.to_vec())?;
                    let round = row.get_i64(1)?;
                    Ok((round, buf))
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Get all proposal parts from foreign proposers for the last rounds in all
    /// heights.
    pub fn all_last_foreign_consensus_proposal_parts(
        &self,
        validator: &ContractAddress,
    ) -> anyhow::Result<Vec<(i64, i64, Vec<u8>)>> {
        let mut stmt = self.0.inner().prepare_cached(
            r"
                SELECT
                    cp.height,
                    cp.round,
                    cp.parts
                FROM consensus_proposals AS cp
                JOIN (
                    SELECT
                        height,
                        MAX(round) AS max_round
                    FROM consensus_proposals
                    WHERE proposer <> :proposer
                    GROUP BY height
                ) AS m
                    ON cp.height = m.height
                AND cp.round = m.max_round
                WHERE cp.proposer <> :proposer
                ORDER BY cp.height ASC",
        )?;
        let mut rows = stmt.query(named_params! {
            ":proposer": validator,
        })?;

        let mut results = Vec::new();

        while let Some(row) = rows.next()? {
            let height = row.get_i64(0)?;
            let round = row.get_i64(1)?;
            let buf = row.get_blob(2).map(|x| x.to_vec())?;

            results.push((height, round, buf));
        }

        Ok(results)
    }

    /// Always all proposers
    pub fn remove_consensus_proposal_parts(
        &self,
        height: u64,
        round: Option<u32>,
    ) -> Result<(), StorageError> {
        if let Some(r) = round {
            self.0
                .inner()
                .execute(
                    r"
                    DELETE FROM consensus_proposals
                    WHERE height = :height AND round = :round",
                    named_params! {
                        ":height": &height,
                        ":round": &r,
                    },
                )
                .context("Deleting consensus proposal parts")?;
        } else {
            self.0
                .inner()
                .execute(
                    r"
                    DELETE FROM consensus_proposals
                    WHERE height = :height",
                    named_params! {
                        ":height": &height,
                    },
                )
                .context("Deleting consensus proposal parts")?;
        }

        Ok(())
    }

    pub fn ensure_consensus_finalized_blocks_table_exists(&self) -> Result<(), StorageError> {
        self.0.inner().execute(
            r"CREATE TABLE IF NOT EXISTS consensus_finalized_blocks (
                    height      INTEGER NOT NULL,
                    round       INTEGER NOT NULL,
                    block       BLOB NOT NULL,
                    is_decided  INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(height, round)
            )",
            [],
        )?;
        Ok(())
    }

    pub fn persist_consensus_finalized_block(
        &self,
        height: u64,
        round: u32,
        block: &[u8], // FinalizedBlock
    ) -> Result<bool, StorageError> {
        let count = self.0.inner().query_row(
            r"SELECT count(*)
            FROM consensus_finalized_blocks
            WHERE height = :height AND round = :round",
            named_params! {
                ":height": &height,
                ":round": &round,
            },
            |row| row.get_i64(0),
        )?;

        if count == 0 {
            self.0
                .inner()
                .execute(
                    r"
                    INSERT INTO consensus_finalized_blocks
                    (height, round, block)
                    VALUES (:height, :round, :block)
                    ",
                    named_params! {
                        ":height": &height,
                        ":round": &round,
                        ":block": &block,
                    },
                )
                .context("Inserting consensus finalized block")?;
        } else {
            self.0
                .inner()
                .execute(
                    r"
                    UPDATE consensus_finalized_blocks
                    SET block = :block
                    WHERE height = :height AND round = :round",
                    named_params! {
                        ":height": &height,
                        ":round": &round,
                        ":block": &block,
                    },
                )
                .context("Updating consensus finalized blocks")?;
        }

        Ok(count > 0)
    }

    pub fn mark_consensus_finalized_block_as_decided(
        &self,
        height: u64,
        round: u32,
    ) -> Result<(), StorageError> {
        self.0
            .inner()
            .execute(
                r"
                UPDATE consensus_finalized_blocks
                SET is_decided = 1
                WHERE height = :height AND round = :round",
                named_params! {
                    ":height": &height,
                    ":round": &round,
                },
            )
            .map(|updated_rows| assert_eq!(updated_rows, 1))
            .map_err(StorageError::from)
    }

    pub fn read_consensus_finalized_block(
        &self,
        height: u64,
        round: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT block
                FROM consensus_finalized_blocks
                WHERE height = :height AND round = :round",
                named_params! {
                    ":height": &height,
                    ":round": &round,
                },
                |row| row.get_blob(0).map(|x| x.to_vec()),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Read the decided finalized block for the given height.
    pub fn read_consensus_finalized_and_decided_block(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT block
                FROM consensus_finalized_blocks
                WHERE height = :height AND is_decided = 1
                ORDER BY round DESC
                LIMIT 1",
                named_params! {
                    ":height": &height,
                },
                |row| row.get_blob(0).map(|x| x.to_vec()),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Get the highest finalized block height from the consensus database.
    /// This represents the latest height that consensus has decided upon,
    /// which may be ahead of what's committed to the main database.
    pub fn latest_finalized_height(&self) -> Result<Option<u64>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT height
                FROM consensus_finalized_blocks
                ORDER BY height DESC
                LIMIT 1",
                [],
                |row| row.get_i64(0).map(|h| h as u64),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Remove all finalized blocks for the given height **except** the one from
    /// `commit_round`.
    pub fn remove_undecided_consensus_finalized_blocks(
        &self,
        height: u64,
    ) -> Result<(), StorageError> {
        self.0
            .inner()
            .execute(
                r"
                DELETE FROM consensus_finalized_blocks
                WHERE height = :height AND is_decided <> 1",
                named_params! {
                    ":height": &height,
                },
            )
            .context("Deleting consensus finalized blocks which will not be committed to the DB")?;
        Ok(())
    }

    /// Always all rounds
    pub fn remove_consensus_finalized_blocks(&self, height: u64) -> Result<(), StorageError> {
        self.0
            .inner()
            .execute(
                r"
                DELETE FROM consensus_finalized_blocks
                WHERE height = :height",
                named_params! {
                    ":height": &height,
                },
            )
            .context("Deleting consensus finalized blocks")?;
        Ok(())
    }

    pub fn consensus_proposal_parts(
        &self,
        height: u64,
    ) -> Result<Vec<(u32, ContractAddress, Vec<u8>)>, StorageError> {
        let mut stmt = self.0.inner().prepare(
            r"SELECT round, proposer, parts
            FROM consensus_proposals
            WHERE height = :height",
        )?;

        let row_iter = stmt.query_map(
            named_params! {
                ":height": &height,
            },
            |row| {
                let round: u32 = row.get_i64(0).map(|x| x as u32)?;
                let proposer: ContractAddress = row.get_contract_address(1)?;
                let parts_blob: Vec<u8> = row.get_blob(2)?.to_vec();
                Ok((round, proposer, parts_blob))
            },
        )?;

        let mut results = Vec::new();
        for row_result in row_iter {
            results.push(row_result?);
        }

        Ok(results)
    }

    pub fn consensus_finalized_blocks(
        &self,
        height: u64,
    ) -> Result<Vec<(u32, bool, Vec<u8>)>, StorageError> {
        let mut stmt = self.0.inner().prepare(
            r"SELECT round, is_decided, block
            FROM consensus_finalized_blocks
            WHERE height = :height",
        )?;

        let row_iter = stmt.query_map(
            named_params! {
                ":height": &height,
            },
            |row| {
                let round: u32 = row.get_i64(0).map(|x| x as u32)?;
                let is_decided: bool = row.get_i64(1).map(|x| x != 0)?;
                let block_blob: Vec<u8> = row.get_blob(2)?.to_vec();
                Ok((round, is_decided, block_blob))
            },
        )?;

        let mut results = Vec::new();
        for row_result in row_iter {
            results.push(row_result?);
        }

        Ok(results)
    }
}
