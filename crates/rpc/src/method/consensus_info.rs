use crate::context::RpcContext;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    highest_decided_height: Option<pathfinder_common::BlockNumber>,
    highest_decided_value: Option<pathfinder_common::ProposalCommitment>,
    peer_score_change_counter: Option<u64>,
}

crate::error::generate_rpc_error_subset!(Error);

pub async fn consensus_info(context: RpcContext) -> Result<Output, Error> {
    Ok(if let Some(watch) = context.consensus_info_watch {
        let borrow_ref = watch.borrow();
        let info = *borrow_ref;
        drop(borrow_ref);

        if let Some((height, value)) = info.highest_decision {
            Output {
                highest_decided_height: Some(height),
                highest_decided_value: Some(value),
                peer_score_change_counter: Some(info.peer_score_change_counter),
            }
        } else {
            Output {
                peer_score_change_counter: Some(info.peer_score_change_counter),
                ..Output::default()
            }
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
        serializer.serialize_optional("highest_decided_height", self.highest_decided_height)?;
        serializer.serialize_optional("highest_decided_value", self.highest_decided_value)?;
        serializer
            .serialize_optional("peer_score_change_counter", self.peer_score_change_counter)?;
        serializer.end()
    }
}
