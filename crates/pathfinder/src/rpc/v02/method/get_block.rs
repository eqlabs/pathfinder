use crate::core::BlockId;
use crate::rpc::v02::RpcContext;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetBlockInput {
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetBlockError: BlockNotFound);

#[allow(dead_code)]
pub async fn get_block_with_transaction_hashes(
    _context: RpcContext,
    _input: GetBlockInput,
) -> Result<(), GetBlockError> {
    todo!()
}

#[allow(dead_code)]
pub async fn get_block_with_transactions(
    _context: RpcContext,
    _input: GetBlockInput,
) -> Result<(), GetBlockError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{StarknetBlockHash, StarknetBlockNumber};
    use crate::starkhash;
    use jsonrpsee::types::Params;

    #[test]
    fn parsing() {
        let number = BlockId::Number(StarknetBlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(StarknetBlockHash(starkhash!("beef")));

        [
            (r#"["pending"]"#, BlockId::Pending),
            (r#"{"block_id": "pending"}"#, BlockId::Pending),
            (r#"["latest"]"#, BlockId::Latest),
            (r#"{"block_id": "latest"}"#, BlockId::Latest),
            (r#"[{"block_number":123}]"#, number),
            (r#"{"block_id": {"block_number":123}}"#, number),
            (r#"[{"block_hash": "0xbeef"}]"#, hash),
            (r#"{"block_id": {"block_hash": "0xbeef"}}"#, hash),
        ]
        .into_iter()
        .enumerate()
        .for_each(|(i, (input, expected))| {
            let actual = Params::new(Some(input))
                .parse::<GetBlockInput>()
                .unwrap_or_else(|_| panic!("test case {i}: {input}"));
            assert_eq!(
                actual,
                GetBlockInput { block_id: expected },
                "test case {i}: {input}"
            );
        });
    }
}
