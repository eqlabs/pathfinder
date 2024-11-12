use anyhow::Context;
use pathfinder_common::BlockNumber;
use rusqlite::params;

use crate::bloom::{AggregateBloom, BloomFilter};

#[allow(dead_code)]
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::warn!("Creating starknet_event_filters table with aggregate bloom filters");

    let mut select_old_filters_query =
        tx.prepare("SELECT bloom FROM starknet_events_filters ORDER BY block_number")?;

    let mut bloom_filters_bytes = select_old_filters_query
        .query_map(params![], |row| {
            let bytes = row.get::<_, Vec<u8>>(0)?;

            Ok(bytes)
        })
        .context("Selecting old filters")?;

    let mut bloom_filters = vec![];
    loop {
        let Some(bloom) = bloom_filters_bytes.next().transpose()? else {
            break;
        };

        bloom_filters.push(BloomFilter::from_compressed_bytes(&bloom));
    }

    tx.execute(
        "CREATE TABLE starknet_event_filters_aggregate (
            from_block INTEGER NOT NULL,
            to_block   INTEGER NOT NULL,
            bloom      BLOB,
            UNIQUE(from_block, to_block)
        )",
        params![],
    )
    .context("Creating starknet_event_filters_aggregate table")?;

    bloom_filters
        .chunks(AggregateBloom::BLOCK_RANGE_LEN as usize)
        .enumerate()
        .try_for_each(|(i, bloom_filter_chunk)| -> anyhow::Result<()> {
            let from_block = i as u64 * AggregateBloom::BLOCK_RANGE_LEN;
            let to_block = from_block + AggregateBloom::BLOCK_RANGE_LEN - 1;
            let from_block = BlockNumber::new_or_panic(from_block);
            let to_block = BlockNumber::new_or_panic(to_block);

            let mut aggregate = AggregateBloom::new(from_block);

            for (j, bloom_filter) in bloom_filter_chunk.iter().enumerate() {
                let block_number = from_block + j as u64;

                aggregate.add_bloom(bloom_filter, block_number);
            }

            tx.execute(
                "INSERT INTO starknet_event_filters_aggregate (from_block, to_block, bloom)
                VALUES (?, ?, ?)",
                params![
                    &from_block.get(),
                    &to_block.get(),
                    &aggregate.compress_bitmap()
                ],
            )
            .context("Inserting aggregate bloom filter")?;

            Ok(())
        })?;

    // TODO:
    // Delete old filters table

    Ok(())
}
