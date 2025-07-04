use anyhow::Context;
use pathfinder_common::FinalizedBlockId;

use crate::context::RpcContext;

pub struct Output(pathfinder_common::BlockNumber);

crate::error::generate_rpc_error_subset!(Error: NoBlocks);

/// Get the latest block number.
pub async fn block_number(context: RpcContext) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Opening database transaction")?;

        tx.block_id(FinalizedBlockId::Latest)
            .context("Reading latest block number from database")?
            .map(|(block_number, _)| Output(block_number))
            .ok_or(Error::NoBlocks)
    });

    jh.await.context("Database read panic or shutting down")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize(&self.0)
    }
}
