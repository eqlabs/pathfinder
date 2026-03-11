use std::collections::BTreeMap;

use pathfinder_common::consensus_info::{CachedAtHeight, Decision, FinalizedBlock, ProposalParts};

use crate::context::RpcContext;

#[derive(Debug, Default, PartialEq)]
pub struct Output {
    highest_decided: Option<Decision>,
    application_peer_scores: BTreeMap<String, f64>,
    cached: BTreeMap<u64, CachedAtHeight>,
}

crate::error::generate_rpc_error_subset!(Error);

pub async fn consensus_info(context: RpcContext) -> Result<Output, Error> {
    Ok(if let Some(watch) = context.consensus_info_watch {
        let info = watch.borrow().clone();

        Output {
            highest_decided: info.highest_decision,
            application_peer_scores: info.application_peer_scores,
            cached: info.cached,
        }
    } else {
        Output::default()
    })
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_optional("highest_decided", self.highest_decided.as_ref())?;
        serializer.serialize_iter(
            "application_peer_scores",
            self.application_peer_scores.len(),
            &mut self.application_peer_scores.iter(),
        )?;
        serializer.serialize_iter("cached", self.cached.len(), &mut self.cached.iter())?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &Decision {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("height", &self.height)?;
        serializer.serialize_field("round", &self.round)?;
        serializer.serialize_field("value", &self.value)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for (&String, &f64) {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("peer_id", self.0)?;
        serializer.serialize_field("score", self.1)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for (&u64, &CachedAtHeight) {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("height", self.0)?;
        serializer.serialize_iter(
            "proposals",
            self.1.proposals.len(),
            &mut self.1.proposals.iter(),
        )?;
        serializer.serialize_iter("blocks", self.1.blocks.len(), &mut self.1.blocks.iter())?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &ProposalParts {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("round", &self.round)?;
        serializer.serialize_field("proposer", &self.proposer)?;
        serializer.serialize_field("parts_len", &self.parts_len)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &FinalizedBlock {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("round", &self.round)?;
        serializer.serialize_field("is_decided", &self.is_decided)?;
        serializer.end()
    }
}
