use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber};

use crate::{prelude::*, BlockId};

pub(crate) fn block_hash(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<BlockHash>> {
    match block {
        BlockId::Latest => tx
            .query_row(
                "SELECT hash FROM canonical_blocks ORDER BY number DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("Querying latest block hash"),
        BlockId::Number(number) => tx
            .query_row(
                "SELECT hash FROM canonical_blocks WHERE number = ?",
                params![&number],
                |row| row.get(0),
            )
            .optional()
            .context("Querying block hash by number"),
        BlockId::Hash(hash) => Ok(Some(hash)),
    }
}

pub(crate) fn block_is_l1_accepted(
    tx: &Transaction<'_>,
    block: BlockNumber,
) -> anyhow::Result<bool> {
    let l1_l2 = tx.l1_l2_pointer().context("Querying L1-L2 pointer")?;

    let result = match l1_l2 {
        Some(number) => number >= block,
        None => false,
    };

    Ok(result)
}
