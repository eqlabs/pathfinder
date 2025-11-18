use anyhow::Context;
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::ContractAddress;
use pathfinder_storage::Transaction;

use crate::consensus::inner::conv::{IntoModel, TryIntoDto};
use crate::consensus::inner::dto;
use crate::validator::FinalizedBlock;

/// A wrapper around a consensus database transaction that provides
/// methods for persisting and retrieving proposal parts and finalized blocks.
pub struct ConsensusProposals<'tx> {
    tx: &'tx Transaction<'tx>,
}

impl<'tx> ConsensusProposals<'tx> {
    /// Create a new `ConsensusProposals` wrapper around a transaction.
    pub fn new(tx: &'tx Transaction<'tx>) -> Self {
        Self { tx }
    }

    /// Persist proposal parts for a given height, round, and proposer.
    /// Returns `true` if an existing entry was updated, `false` if a new entry
    /// was created.
    pub fn persist_parts(
        &self,
        height: u64,
        round: u32,
        proposer: &ContractAddress,
        parts: &[ProposalPart],
    ) -> anyhow::Result<bool> {
        let serde_parts = parts
            .iter()
            .map(|p| dto::ProposalPart::try_into_dto(p.clone()))
            .collect::<Result<Vec<dto::ProposalPart>, _>>()?;
        let proposal_parts = dto::ProposalParts::V0(serde_parts);
        let buf = bincode::serde::encode_to_vec(proposal_parts, bincode::config::standard())
            .context("Serializing proposal parts")?;
        let updated =
            self.tx
                .persist_consensus_proposal_parts(height, round, proposer, &buf[..])?;
        Ok(updated)
    }

    /// Retrieve proposal parts that we created (where proposer == validator).
    pub fn own_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> anyhow::Result<Option<Vec<ProposalPart>>> {
        if let Some(buf) = self
            .tx
            .own_consensus_proposal_parts(height, round, validator)?
        {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            Ok(Some(parts))
        } else {
            Ok(None)
        }
    }

    /// Retrieve proposal parts from other validators (where proposer !=
    /// validator).
    pub fn foreign_parts(
        &self,
        height: u64,
        round: u32,
        validator: &ContractAddress,
    ) -> anyhow::Result<Option<Vec<ProposalPart>>> {
        if let Some(buf) = self
            .tx
            .foreign_consensus_proposal_parts(height, round, validator)?
        {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            Ok(Some(parts))
        } else {
            Ok(None)
        }
    }

    /// Retrieve the last proposal parts for a given height from other
    /// validators. Returns the round number and the proposal parts.
    pub fn last_parts(
        &self,
        height: u64,
        validator: &ContractAddress,
    ) -> anyhow::Result<Option<(u32, Vec<ProposalPart>)>> {
        if let Some((round, buf)) = self.tx.last_consensus_proposal_parts(height, validator)? {
            let parts = Self::decode_proposal_parts(&buf[..])?;
            let last_round = round.try_into().context("Invalid round")?;
            Ok(Some((last_round, parts)))
        } else {
            Ok(None)
        }
    }

    /// Remove proposal parts for a given height and optionally a specific
    /// round. If `round` is `None`, all rounds for that height are removed.
    pub fn remove_parts(&self, height: u64, round: Option<u32>) -> anyhow::Result<()> {
        self.tx.remove_consensus_proposal_parts(height, round)
    }

    /// Persist a finalized block for a given height and round.
    /// Returns `true` if an existing entry was updated, `false` if a new entry
    /// was created.
    pub fn persist_finalized_block(
        &self,
        height: u64,
        round: u32,
        block: FinalizedBlock,
    ) -> anyhow::Result<bool> {
        let serde_block = dto::FinalizedBlock::try_into_dto(block)?;
        let finalized_block = dto::PersistentFinalizedBlock::V0(serde_block);
        let buf = bincode::serde::encode_to_vec(finalized_block, bincode::config::standard())
            .context("Serializing finalized block")?;
        let updated = self
            .tx
            .persist_consensus_finalized_block(height, round, &buf[..])?;
        Ok(updated)
    }

    /// Read a finalized block for a given height and round.
    pub fn read_finalized_block(
        &self,
        height: u64,
        round: u32,
    ) -> anyhow::Result<Option<FinalizedBlock>> {
        if let Some(buf) = self.tx.read_consensus_finalized_block(height, round)? {
            let block = Self::decode_finalized_block(&buf[..])?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Remove all finalized blocks for a given height.
    pub fn remove_finalized_blocks(&self, height: u64) -> anyhow::Result<()> {
        self.tx.remove_consensus_finalized_blocks(height)
    }

    fn decode_proposal_parts(buf: &[u8]) -> anyhow::Result<Vec<ProposalPart>> {
        let proposal_parts: dto::ProposalParts =
            bincode::serde::decode_from_slice(buf, bincode::config::standard())
                .context("Deserializing proposal parts")?
                .0;
        let dto::ProposalParts::V0(serde_parts) = proposal_parts;
        let parts = serde_parts.into_iter().map(|p| p.into_model()).collect();
        Ok(parts)
    }

    fn decode_finalized_block(buf: &[u8]) -> anyhow::Result<FinalizedBlock> {
        let persistent_block: dto::PersistentFinalizedBlock =
            bincode::serde::decode_from_slice(buf, bincode::config::standard())
                .context("Deserializing finalized block")?
                .0;
        let dto::PersistentFinalizedBlock::V0(dto_block) = persistent_block;
        Ok(dto_block.into_model())
    }
}
