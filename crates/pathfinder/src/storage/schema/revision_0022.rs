/// This migration adds an extra index to `starknet_events` to speed up some look-ups.
///
/// The Sqlite query optimizer can use only a single index per table. It
/// turns out that the choice the optimizer makes is sub-optimal for
/// getEvents queries where the filter specifies both a block range and
/// a from address (both of these are turned into where claused on rows in
/// the starknet_events table). In this case the query optimizer chooses
/// to use the index for from_address, leading to a huge table scan on
/// the block number range even if the block range is just a few blocks.
///
/// This migration adds a composite index on (from_address, block_number) which
/// is then used by queries filtering on both. Note that the order of the
/// columns matters here, since only the right-most column of the index can
/// be used for range queries.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tracing::info!("Adding composite index to starknet_events table");

    tx.execute(
        r"CREATE INDEX starknet_events_from_address_block_number ON starknet_events(from_address, block_number)",
        [],
    )
    .context("Adding 'starknet_events_from_address_block_number' index")?;

    Ok(())
}
