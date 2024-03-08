use crate::context::RpcContext;

crate::error::generate_rpc_error_subset!(Error);

pub struct Output(pathfinder_common::ChainId);

pub async fn chain_id(context: RpcContext) -> Result<Output, Error> {
    Ok(Output(context.chain_id))
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize(&crate::dto::ChainId(&self.0))
    }
}
