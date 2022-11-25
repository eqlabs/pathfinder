use crate::rpc::v02::RpcContext;

crate::rpc::error::generate_rpc_error_subset!(ChainIdError);

#[allow(dead_code)]
pub async fn chain_id(context: RpcContext) -> Result<String, ChainIdError> {
    Ok(context.chain.starknet_chain_id().to_hex_str().into_owned())
}

#[cfg(test)]
mod tests {
    use super::chain_id;
    use crate::rpc::v02::RpcContext;
    use pathfinder_common::Chain;

    #[tokio::test]
    async fn test_chain_id() {
        let cases = vec![
            (Chain::Mainnet, "SN_MAIN"),
            (Chain::Testnet, "SN_GOERLI"),
            (Chain::Testnet2, "SN_GOERLI2"),
            (Chain::Integration, "SN_INTEGRATION"),
        ];

        for (chain, label) in cases {
            let mut context = RpcContext::for_tests();
            context.chain = chain;

            let returned = chain_id(context).await.unwrap();
            let expected = format!("0x{}", hex::encode(label));
            assert_eq!(returned, expected, "{}", label);
        }
    }
}
