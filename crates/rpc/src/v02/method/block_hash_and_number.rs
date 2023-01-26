use crate::felt::RpcFelt;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};
use pathfinder_storage::StarknetBlocksTable;

#[serde_with::serde_as]
#[derive(serde::Serialize)]
pub struct BlockHashAndNumber {
    #[serde_as(as = "RpcFelt")]
    pub block_hash: StarknetBlockHash,
    pub block_number: StarknetBlockNumber,
}

crate::error::generate_rpc_error_subset!(BlockNumberError: NoBlocks);

pub async fn block_hash_and_number(
    context: RpcContext,
) -> Result<BlockHashAndNumber, BlockNumberError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Creating database transaction")?;

        StarknetBlocksTable::get_latest_hash_and_number(&tx)
            .context("Reading latest block hash and number from database")?
            .map(|(block_hash, block_number)| BlockHashAndNumber {
                block_hash,
                block_number,
            })
            .ok_or(BlockNumberError::NoBlocks)
    });

    jh.await.context("Database read panic or shutting down")?
}

pub async fn block_number(context: RpcContext) -> Result<StarknetBlockNumber, BlockNumberError> {
    block_hash_and_number(context)
        .await
        .map(|result| result.block_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_hash_and_number() {
        let context = RpcContext::for_tests();
        let result = block_hash_and_number(context).await.unwrap();

        assert_eq!(result.block_number, StarknetBlockNumber::new_or_panic(2));
        assert_eq!(
            result.block_hash,
            StarknetBlockHash(pathfinder_common::felt_bytes!(b"latest"))
        );
    }
}
