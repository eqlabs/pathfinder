use anyhow::Context;
use pathfinder_storage::BlockId;

use crate::context::RpcContext;

pub struct Output(pathfinder_common::BlockNumber);

crate::error::generate_rpc_error_subset!(Error: NoBlocks);

/// Get the latest block number.
pub async fn block_number(context: RpcContext) -> Result<Output, Error> {
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Opening database transaction")?;

        tx.block_id(BlockId::Latest)
            .context("Reading latest block number from database")?
            .map(|(block_number, _)| Output(block_number))
            .ok_or(Error::NoBlocks)
    });

    jh.await.context("Database read panic or shutting down")?
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize(&crate::dto::BlockNumber(self.0))
    }
}
