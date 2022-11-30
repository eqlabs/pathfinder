use pathfinder_common::ChainId;

use crate::rpc::v02::RpcContext;

crate::rpc::error::generate_rpc_error_subset!(ChainIdError);

#[allow(dead_code)]
pub async fn chain_id(context: RpcContext) -> Result<ChainId, ChainIdError> {
    Ok(context.chain_id)
}

#[cfg(test)]
mod tests {
    use pathfinder_common::ChainId;
    use stark_hash::StarkHash;

    #[tokio::test]
    async fn encoding() {
        let value = "example ID";
        let chain_id = StarkHash::from_be_slice(value.as_bytes()).unwrap();
        let chain_id = ChainId(chain_id);

        let encoded = serde_json::to_string(&chain_id).unwrap();

        let expected = hex::encode(value);
        let expected = format!(r#""0x{expected}""#);

        assert_eq!(encoded, expected);
    }
}
