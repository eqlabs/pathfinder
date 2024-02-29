use anyhow::Context;
use pathfinder_common::BlockNumber;
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

/// Returns the first block number whose state update is missing in storage, counting from genesis
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        if let Some(highest) = db
            .highest_state_update()
            .context("Querying highest state update")?
        {
            Ok((highest < head).then_some(highest + 1))
        } else {
            Ok(Some(BlockNumber::GENESIS))
        }
    })
    .await
    .context("Joining blocking task")?
}
