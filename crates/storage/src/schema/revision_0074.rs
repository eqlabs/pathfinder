//! The purpose if this migration is to repair any database instances that were
//! affected by a combination of a bug in the code that rebuilds the
//! [running event filter](crate::connection::event::RunningEventFilter) and a
//! reorg happened on the Sepolia testnet.
//!
//! More info [here](https://github.com/eqlabs/pathfinder/issues/2925).

use anyhow::Context;
use pathfinder_common::event::Event;
use pathfinder_common::BlockNumber;

use crate::bloom::{AggregateBloom, BloomFilter};
use crate::prelude::*;
use crate::{transaction, AGGREGATE_BLOOM_BLOCK_RANGE_LEN};

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Repairing aggregate Bloom filter left corrupted after Sepolia reorg");

    let mut load_events_stmt = tx
        .prepare(
            r"
            SELECT block_number, events
            FROM transactions
            WHERE block_number >= :from_block AND block_number <= :to_block
            ",
        )
        .context("Preparing load_events_stmt")?;

    let latest = tx
        .query_row(
            "SELECT number FROM block_headers ORDER BY number DESC LIMIT 1",
            [],
            |row| row.get_block_number(0),
        )
        .context("Querying latest block number")?;

    // Known aggregate Bloom filter range affected by the reorg.
    let corrupted_aggregate_filter_from_block = BlockNumber::new_or_panic(1490944);
    let corrupted_aggregate_filter_to_block =
        corrupted_aggregate_filter_from_block + AGGREGATE_BLOOM_BLOCK_RANGE_LEN - 1;

    if corrupted_aggregate_filter_from_block > latest {
        // This DB instance has not reached the corrupted aggregate filter range.
        // No need to repair it.
        return Ok(());
    }

    // Correctly reconstruct the corrupted aggregate filter.
    let repaired_aggregate_filter = {
        let rebuilt_filters: Vec<Option<(BlockNumber, BloomFilter)>> = load_events_stmt
            .query_and_then(
                named_params![":from_block": &corrupted_aggregate_filter_from_block, ":to_block": &corrupted_aggregate_filter_to_block],
                |row| {
                    let block_number = row.get_block_number(0)?;
                    let events = row
                        .get_optional_blob(1)?
                        .map(|events_blob| -> anyhow::Result<_> {
                            let events = transaction::compression::decompress_events(events_blob)
                                .context("Decompressing events")?;
                            let events: transaction::dto::EventsForBlock =
                                bincode::serde::decode_from_slice(&events, bincode::config::standard())
                                    .context("Deserializing events")?
                                    .0;

                            Ok(events)
                        })
                        .transpose()?
                        .map(|efb| {
                            efb.events()
                                .into_iter()
                                .flatten()
                                .map(Event::from)
                                .collect::<Vec<_>>()
                        });
                    let Some(events) = events else {
                        return Ok(None);
                    };

                    let mut bloom = BloomFilter::new();
                    for event in events {
                        bloom.set_keys(&event.keys);
                        bloom.set_address(&event.from_address);
                    }

                    Ok(Some((block_number, bloom)))
                },
            )
            .context("Querying events to rebuild")?
            .collect::<anyhow::Result<_>>()?;

        let mut repaired_filter = AggregateBloom::new(corrupted_aggregate_filter_from_block);

        for block_bloom_filter in rebuilt_filters {
            let Some((block_number, bloom)) = block_bloom_filter else {
                // Reached the end of P2P (checkpoint) synced events.
                break;
            };

            repaired_filter.insert(&bloom, block_number);
        }

        repaired_filter
    };

    let running_event_filter_from_block = tx
        .query_row("SELECT from_block FROM running_event_filter", [], |row| {
            row.get_block_number(0)
        })
        .context("Querying running event filter from block")?;

    if running_event_filter_from_block == corrupted_aggregate_filter_from_block {
        // This DB instance's running event filter is currently in the range
        // that is corrupted.
        tx.execute(
            r"
            UPDATE running_event_filter
            SET bitmap = ?, next_block = ?
            WHERE id = 1
            ",
            params![&repaired_aggregate_filter.compress_bitmap(), &(latest + 1)],
        )
        .context("Updating corrupted running event filter")?;
    } else {
        // This DB instance has already stored the corrupted aggregate filter.
        tx.execute(
            r"
            UPDATE event_filters
            SET bitmap = ?
            WHERE from_block = ? AND to_block = ?
            ",
            params![
                &repaired_aggregate_filter.compress_bitmap(),
                &repaired_aggregate_filter.from_block,
                &repaired_aggregate_filter.to_block,
            ],
        )
        .context("Updating corrupted stored aggregate filter")?;
    }

    Ok(())
}
