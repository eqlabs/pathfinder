use crate::context::RpcContext;

crate::error::generate_rpc_error_subset!(Error);

pub struct Output(pathfinder_common::ChainId);

/// Get the chain ID.
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

#[cfg(test)]
mod tests {
    use pathfinder_common::ChainId;
    use pathfinder_crypto::Felt;

    #[tokio::test]
    async fn encoding() {
        let value = "some_chain_id";
        let chain_id = Felt::from_be_slice(value.as_bytes()).unwrap();
        let chain_id = ChainId(chain_id);

        let encoded = serde_json::to_string(&chain_id).unwrap();

        let expected = hex::encode(value);
        let expected = format!(r#""0x{expected}""#);

        assert_eq!(encoded, expected);
    }
}
