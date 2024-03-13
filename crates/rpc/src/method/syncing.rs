use crate::{context::RpcContext, v02::types::syncing::Syncing};

crate::error::generate_rpc_error_subset!(Error);

pub struct Output(Syncing);

pub async fn syncing(context: RpcContext) -> Result<Output, Error> {
    // Scoped so I don't have to think too hard about mutex guard drop semantics.
    let value = { context.sync_status.status.read().await.clone() };

    Ok(Output(value))
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        match self.0 {
            Syncing::False(_) => serializer.serialize_bool(false),
            Syncing::Status(status) => serializer.serialize(&crate::dto::SyncStatus(&status)),
        }
    }
}
