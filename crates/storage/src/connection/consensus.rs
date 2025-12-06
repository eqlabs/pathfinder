//! Note that functions in this module fail on normal pathfinder
//! storage (because they use a consensus-specific table).

use anyhow::Context;
use pathfinder_common::ContractAddress;

use crate::prelude::*;

impl Transaction<'_> {
    pub fn ensure_consensus_proposals_table_exists(&self) -> anyhow::Result<()> {
        self.inner().execute(
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
    ) -> anyhow::Result<bool> {
        let count = self.inner().query_row(
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
            self.inner()
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
            self.inner()
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
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner()
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
            .map_err(|e| e.into())
    }

    pub fn foreign_consensus_proposal_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner()
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
            .map_err(|e| e.into())
    }

    pub fn last_consensus_proposal_parts(
        &self,
        height: u64,
        validator: &ContractAddress,
    ) -> anyhow::Result<Option<(i64, Vec<u8>)>> {
        self.inner()
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
            .map_err(|e| e.into())
    }

    pub fn all_last_consensus_proposal_parts(
        &self,
        validator: &ContractAddress,
    ) -> anyhow::Result<Vec<(i64, i64, Vec<u8>)>> {
        let mut stmt = self.inner().prepare_cached(
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
    ) -> anyhow::Result<()> {
        if let Some(r) = round {
            self.inner()
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
            self.inner()
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

    pub fn ensure_consensus_finalized_blocks_table_exists(&self) -> anyhow::Result<()> {
        self.inner().execute(
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
    ) -> anyhow::Result<bool> {
        let count = self.inner().query_row(
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
            self.inner()
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
            self.inner()
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
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner()
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
            .map_err(|e| e.into())
    }

    /// Always all rounds
    pub fn remove_consensus_finalized_blocks(&self, height: u64) -> anyhow::Result<()> {
        self.inner()
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
