use std::time::Instant;

use anyhow::Context;
use pathfinder_common::BlockNumber;

use crate::bloom::{AggregateBloom, BloomFilter};
use crate::params::params;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Creating event_filters table and migrating event Bloom filters");

    tx.execute(
        r"
        CREATE TABLE event_filters (
            from_block  INTEGER NOT NULL,
            to_block    INTEGER NOT NULL,
            bitmap      BLOB NOT NULL,
            UNIQUE(from_block, to_block)
        )
        ",
        [],
    )
    .context("Creating event_filters table")?;

    migrate_event_filters(tx).context("Migrating event Bloom filters")?;

    tx.execute("DROP TABLE starknet_events_filters", [])
        .context("Dropping starknet_events_filters table")?;

    Ok(())
}

/// Migrate individual event bloom filters to the new aggregate table. We only
/// need to migrate all of the [crate::bloom::AGGREGATE_BLOOM_BLOCK_RANGE_LEN]
/// sized chunks. The remainder will be reconstructed by the
/// [crate::StorageManager] as the
/// [RunningEventFilter](crate::connection::event::RunningEventFilter).
fn migrate_event_filters(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let bloom_filter_count = tx
        .query_row("SELECT COUNT(*) FROM starknet_events_filters", [], |row| {
            row.get::<_, u64>(0)
        })
        .context("Counting existing event Bloom filters")?;

    if bloom_filter_count == 0 {
        // No event Bloom filters to migrate.
        return Ok(());
    }

    let mut fetch_bloom_stmt =
        tx.prepare("SELECT bloom FROM starknet_events_filters ORDER BY block_number")?;

    let mut insert_aggregate_stmt = tx.prepare_cached(
        r"
        INSERT INTO event_filters (from_block, to_block, bitmap)
        VALUES (?, ?, ?)
        ",
    )?;

    let mut bloom_filters = fetch_bloom_stmt
        .query_map([], |row| {
            let bloom: Vec<u8> = row.get(0)?;
            Ok(BloomFilter::from_compressed_bytes(&bloom))
        })
        .context("Querying old Bloom filters")?;

    let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);
    let mut migrated_count: u64 = 0;
    let mut last_progress_report = Instant::now();

    tracing::info!(
        "Migrating event Bloom filters: 0.00% (0/{})",
        bloom_filter_count
    );
    while let Some(bloom_filter) = bloom_filters.next().transpose()? {
        let current_block = BlockNumber::new_or_panic(migrated_count);

        aggregate.insert(&bloom_filter, current_block);

        if current_block == aggregate.to_block {
            insert_aggregate_stmt
                .execute(params![
                    &aggregate.from_block,
                    &aggregate.to_block,
                    &aggregate.compress_bitmap()
                ])
                .context("Inserting aggregate bloom filter")?;

            aggregate = AggregateBloom::new(current_block + 1);
        }

        migrated_count += 1;

        if last_progress_report.elapsed().as_secs() >= 10 {
            tracing::info!(
                "Migrating event Bloom filters: {:.2}% ({}/{})",
                migrated_count as f64 / bloom_filter_count as f64 * 100.0,
                migrated_count,
                bloom_filter_count
            );
            last_progress_report = Instant::now();
        }
    }
    tracing::info!(
        "Migrating event Bloom filters: 100.00% ({count}/{count})",
        count = bloom_filter_count,
    );

    Ok(())
}
