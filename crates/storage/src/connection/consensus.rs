use anyhow::Context;
use pathfinder_common::ContractAddress;

use crate::prelude::*;

impl Transaction<'_> {
    pub fn insert_consensus_proposal_parts(
        &self,
        height: u64,
        round: u32,
        proposer: &ContractAddress,
        parts: &[u8], // Vec<ProposalPart>
    ) -> anyhow::Result<()> {
        self.inner()
            .execute(
                r"
                INSERT OR REPLACE INTO consensus_proposals
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

        Ok(())
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
}
