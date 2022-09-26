use crate::rpc::v02::RpcContext;

crate::rpc::error::generate_rpc_error_subset!(ChainIdError);

#[allow(dead_code)]
pub async fn chain_id(context: std::sync::Arc<RpcContext>) -> Result<String, ChainIdError> {
    Ok(context.chain.starknet_chain_id().to_hex_str().into_owned())
}

#[cfg(test)]
mod tests {
    use crate::core::Chain;
    use crate::rpc::v02::RpcContext;

    use super::chain_id;

    #[tokio::test]
    async fn mainnet() {
        let mut context = (*RpcContext::for_tests()).clone();
        context.chain = Chain::Mainnet;

        let result = chain_id(std::sync::Arc::new(context)).await.unwrap();
        let expected = format!("0x{}", hex::encode("SN_MAIN"));
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn testnet() {
        let mut context = (*RpcContext::for_tests()).clone();
        context.chain = Chain::Testnet;

        let result = chain_id(std::sync::Arc::new(context)).await.unwrap();
        let expected = format!("0x{}", hex::encode("SN_GOERLI"));
        assert_eq!(result, expected);
    }
}
