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

impl ConsensusStorage {
    pub fn in_tempdir() -> anyhow::Result<ConsensusStorage> {
        let storage = StorageBuilder::in_tempdir()?;
        Ok(ConsensusStorage(storage))
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

    /// Read the finalized block for the given height with the highest round. In
    /// practice this should be the only round left in the DB for that height.
    pub fn read_consensus_finalized_block_for_last_round(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.0
            .inner()
            .query_row(
                r"SELECT block
                FROM consensus_finalized_blocks
                WHERE height = :height
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
    pub fn remove_uncommitted_consensus_finalized_blocks(
        &self,
        height: u64,
        commit_round: u32,
    ) -> Result<(), StorageError> {
        self.0
            .inner()
            .execute(
                r"
                DELETE FROM consensus_finalized_blocks
                WHERE height = :height AND round <> :commit_round",
                named_params! {
                    ":height": &height,
                    ":commit_round": &commit_round,
                },
            )
            .context("Deleting consensus finalized blocks which will not be committed to the DB")?;
        Ok(())
    }

    /// Remove a finalized block for the given height and round.
    pub fn remove_consensus_finalized_block(
        &self,
        height: u64,
        round: u32,
    ) -> Result<(), StorageError> {
        self.0
            .inner()
            .execute(
                r"
                DELETE FROM consensus_finalized_blocks
                WHERE height = :height AND round = :round",
                named_params! {
                    ":height": &height,
                    ":round": &round,
                },
            )
            .context("Deleting consensus finalized block")?;
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
}
