use anyhow::Context;
use p2p_proto::consensus::ProposalPart;
use pathfinder_common::ContractAddress;
use pathfinder_storage::Transaction;

use crate::consensus::inner::conv::{IntoProto, TryIntoDto};
use crate::consensus::inner::dto;
use crate::validator::FinalizedBlock;

pub fn persist_proposal_parts(
    db_tx: Transaction<'_>,
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
    let updated = db_tx.persist_consensus_proposal_parts(height, round, proposer, &buf[..])?;
    db_tx.commit()?;
    Ok(updated)
}

pub fn own_proposal_parts(
    db_tx: &Transaction<'_>,
    height: u64,
    round: u32,
    validator: &ContractAddress,
) -> anyhow::Result<Option<Vec<ProposalPart>>> {
    if let Some(buf) = db_tx.own_consensus_proposal_parts(height, round, validator)? {
        let parts = decode_proposal_parts(&buf[..])?;
        Ok(Some(parts))
    } else {
        Ok(None)
    }
}

pub fn foreign_proposal_parts(
    db_tx: &Transaction<'_>,
    height: u64,
    round: u32,
    validator: &ContractAddress,
) -> anyhow::Result<Option<Vec<ProposalPart>>> {
    if let Some(buf) = db_tx.foreign_consensus_proposal_parts(height, round, validator)? {
        let parts = decode_proposal_parts(&buf[..])?;
        Ok(Some(parts))
    } else {
        Ok(None)
    }
}

pub fn last_proposal_parts(
    db_tx: &Transaction<'_>,
    height: u64,
    validator: &ContractAddress,
) -> anyhow::Result<Option<(u32, Vec<ProposalPart>)>> {
    if let Some((round, buf)) = db_tx.last_consensus_proposal_parts(height, validator)? {
        let parts = decode_proposal_parts(&buf[..])?;
        let last_round = round.try_into().context("Invalid round")?;
        Ok(Some((last_round, parts)))
    } else {
        Ok(None)
    }
}

fn decode_proposal_parts(buf: &[u8]) -> anyhow::Result<Vec<ProposalPart>> {
    let proposal_parts: dto::ProposalParts =
        bincode::serde::decode_from_slice(buf, bincode::config::standard())
            .context("Deserializing proposal parts")?
            .0;
    let dto::ProposalParts::V0(serde_parts) = proposal_parts;
    let parts = serde_parts.into_iter().map(|p| p.into_proto()).collect();
    Ok(parts)
}

pub fn remove_proposal_parts(
    db_tx: Transaction<'_>,
    height: u64,
    round: Option<u32>,
) -> anyhow::Result<()> {
    db_tx.remove_consensus_proposal_parts(height, round)?;
    db_tx.commit()
}

pub fn persist_finalized_block(
    db_tx: Transaction<'_>,
    height: u64,
    round: u32,
    block: FinalizedBlock,
) -> anyhow::Result<bool> {
    let serde_block = dto::FinalizedBlock::try_into_dto(block)?;
    let finalized_block = dto::PersistentFinalizedBlock::V0(serde_block);
    let buf = bincode::serde::encode_to_vec(finalized_block, bincode::config::standard())
        .context("Serializing finalized block")?;
    let updated = db_tx.persist_consensus_finalized_block(height, round, &buf[..])?;
    db_tx.commit()?;
    Ok(updated)
}

pub fn read_finalized_block(
    db_tx: Transaction<'_>,
    height: u64,
    round: u32,
) -> anyhow::Result<Option<FinalizedBlock>> {
    if let Some(buf) = db_tx.read_consensus_finalized_block(height, round)? {
        let block = decode_finalized_block(&buf[..])?;
        Ok(Some(block))
    } else {
        Ok(None)
    }
}

fn decode_finalized_block(buf: &[u8]) -> anyhow::Result<FinalizedBlock> {
    let persistent_block: dto::PersistentFinalizedBlock =
        bincode::serde::decode_from_slice(buf, bincode::config::standard())
            .context("Deserializing finalized block")?
            .0;
    let dto::PersistentFinalizedBlock::V0(dto_block) = persistent_block;
    Ok(dto_block.into_proto())
}

pub fn remove_finalized_blocks(db_tx: Transaction<'_>, height: u64) -> anyhow::Result<()> {
    db_tx.remove_consensus_finalized_blocks(height)?;
    db_tx.commit()
}
