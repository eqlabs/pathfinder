use anyhow::Context;
use pathfinder_common::BlockNumber;

use crate::bloom::{AggregateBloom, BloomFilter};
use crate::params::params;

#[allow(dead_code)]
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Creating starknet_events_filters_aggregate table and migrating filters");

    tx.execute(
        r"
        CREATE TABLE starknet_events_filters_aggregate (
            from_block  INTEGER NOT NULL,
            to_block    INTEGER NOT NULL,
            bitmap      BLOB NOT NULL,
            UNIQUE(from_block, to_block)
        )
        ",
        params![],
    )
    .context("Creating starknet_events_filters_aggregate table")?;

    migrate_individual_filters(tx)?;

    // TODO:
    // Delete old filters table

    Ok(())
}

/// Migrate individual bloom filters to the new aggregate table. We only need to
/// migrate all of the [BLOCK_RANGE_LEN](AggregateBloom::BLOCK_RANGE_LEN) sized
/// chunks. The remainder will be reconstructed by the
/// [StorageManager](crate::StorageManager) as the running aggregate.
fn migrate_individual_filters(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let mut select_old_bloom_stmt =
        tx.prepare("SELECT bloom FROM starknet_events_filters ORDER BY block_number")?;
    let bloom_filters: Vec<BloomFilter> = select_old_bloom_stmt
        .query_and_then(params![], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(BloomFilter::from_compressed_bytes(&bytes))
        })
        .context("Querying old Bloom filters")?
        .collect::<anyhow::Result<_>>()?;

    if bloom_filters.is_empty() {
        // There are no bloom filters to migrate.
        return Ok(());
    }

    let mut insert_aggregate_stmt = tx.prepare(
        r"
        INSERT INTO starknet_events_filters_aggregate
        (from_block, to_block, bitmap)
        VALUES (?, ?, ?)
        ",
    )?;
    let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);
    bloom_filters
        .iter()
        .enumerate()
        .try_for_each(|(i, bloom_filter)| -> anyhow::Result<()> {
            let block_number = BlockNumber::new_or_panic(i as u64);

            aggregate.add_bloom(bloom_filter, block_number);
            if block_number == aggregate.to_block {
                insert_aggregate_stmt
                    .execute(params![
                        &aggregate.from_block,
                        &aggregate.to_block,
                        &aggregate.compress_bitmap()
                    ])
                    .context("Inserting aggregate bloom filter")?;

                aggregate = AggregateBloom::new(block_number + 1);
            }

            Ok(())
        })?;

    Ok(())
}
