use anyhow::Context;
use p2p_proto::consensus::ProposalPart;
use p2p_proto::{ToProtobuf, TryFromProtobuf};
use pathfinder_common::ContractAddress;
use pathfinder_storage::Transaction;
use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct ProposalParts {
    #[prost(message, repeated, tag = "1")]
    pub parts: ::prost::alloc::vec::Vec<p2p_proto::proto::consensus::consensus::ProposalPart>,
}

pub fn persist_proposal_parts(
    db_tx: Transaction<'_>,
    height: u64,
    round: u32,
    proposer: &ContractAddress,
    parts: &[ProposalPart],
) -> anyhow::Result<bool> {
    let prost_parts = ProposalParts {
        parts: parts.iter().map(|p| p.clone().to_protobuf()).collect(),
    };
    let mut buf = vec![];
    prost_parts.encode(&mut buf)?;
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
    let prost_parts: ProposalParts = Message::decode(buf)?;
    let parts = prost_parts
        .parts
        .iter()
        .map(|p| ProposalPart::try_from_protobuf(p.clone(), "parts"))
        .collect::<Result<Vec<ProposalPart>, _>>()?;
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
