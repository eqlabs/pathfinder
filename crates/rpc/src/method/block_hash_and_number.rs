use anyhow::Context;
use pathfinder_storage::BlockId;

use crate::context::RpcContext;

pub struct Output {
    number: pathfinder_common::BlockNumber,
    hash: pathfinder_common::BlockHash,
}

crate::error::generate_rpc_error_subset!(Error: NoBlocks);

/// Get the latest block hash and number.
pub async fn block_hash_and_number(context: RpcContext) -> Result<Output, Error> {
    let span = tracing::Span::current();
    let jh = util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;
        let tx = db.transaction().context("Opening database transaction")?;

        tx.block_id(BlockId::Latest)
            .context("Reading latest block number and hash from database")?
            .map(|(number, hash)| Output { number, hash })
            .ok_or(Error::NoBlocks)
    });

    jh.await.context("Database read panic or shutting down")?
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("block_hash", &self.hash)?;
        serializer.serialize_field("block_number", &self.number)?;
        serializer.end()
    }
}
