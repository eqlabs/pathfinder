use pathfinder_common::ChainId;

use crate::felt::RpcFelt;
use crate::v02::RpcContext;

crate::error::generate_rpc_error_subset!(ChainIdError);

#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct ChainIdOutput(#[serde_as(as = "RpcFelt")] ChainId);

pub async fn chain_id(context: RpcContext) -> Result<ChainIdOutput, ChainIdError> {
    Ok(ChainIdOutput(context.chain_id))
}

#[cfg(test)]
mod tests {
    use pathfinder_common::ChainId;
    use stark_hash::Felt;

    #[tokio::test]
    async fn encoding() {
        let value = "example ID";
        let chain_id = Felt::from_be_slice(value.as_bytes()).unwrap();
        let chain_id = ChainId(chain_id);

        let encoded = serde_json::to_string(&chain_id).unwrap();

        let expected = hex::encode(value);
        let expected = format!(r#""0x{expected}""#);

        assert_eq!(encoded, expected);
    }
}
