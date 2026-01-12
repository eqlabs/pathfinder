use crate::context::RpcContext;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    highest_decided: Option<DecisionMeta>,
    peer_score_change_counter: Option<u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DecisionMeta {
    pub height: pathfinder_common::BlockNumber,
    pub round: u32,
    pub value: pathfinder_common::ProposalCommitment,
}

crate::error::generate_rpc_error_subset!(Error);

pub async fn consensus_info(context: RpcContext) -> Result<Output, Error> {
    Ok(if let Some(watch) = context.consensus_info_watch {
        let borrow_ref = watch.borrow();
        let info = *borrow_ref;
        drop(borrow_ref);

        Output {
            highest_decided: info.highest_decision.map(|decision| DecisionMeta {
                height: decision.height,
                round: decision.round,
                value: decision.value,
            }),
            peer_score_change_counter: Some(info.peer_score_change_counter),
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
        serializer
            .serialize_optional("peer_score_change_counter", self.peer_score_change_counter)?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for &DecisionMeta {
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
