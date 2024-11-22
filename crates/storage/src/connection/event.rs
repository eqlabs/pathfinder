use std::num::NonZeroUsize;

#[cfg(feature = "aggregate_bloom")]
use anyhow::Context;
use anyhow::Result;
use pathfinder_common::event::Event;
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    ContractAddress,
    EventData,
    EventKey,
    TransactionHash,
};

#[cfg(feature = "aggregate_bloom")]
use crate::bloom::AggregateBloom;
use crate::bloom::BloomFilter;
use crate::prelude::*;
use crate::ReorgCounter;

pub const PAGE_SIZE_LIMIT: usize = 1_024;

#[derive(Debug, Default)]
pub struct EventFilter {
    pub from_block: Option<BlockNumber>,
    pub to_block: Option<BlockNumber>,
    pub contract_address: Option<ContractAddress>,
    pub keys: Vec<Vec<EventKey>>,
    pub page_size: usize,
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmittedEvent {
    pub from_address: ContractAddress,
    pub data: Vec<EventData>,
    pub keys: Vec<EventKey>,
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,
    pub transaction_hash: TransactionHash,
}

#[derive(Debug, thiserror::Error)]
pub enum EventFilterError {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("requested page size is too small, supported minimum is 1")]
    PageSizeTooSmall,
}

impl From<rusqlite::Error> for EventFilterError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.into())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContinuationToken {
    pub block_number: BlockNumber,
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageOfEvents {
    pub events: Vec<EmittedEvent>,
    pub continuation_token: Option<ContinuationToken>,
}

impl Transaction<'_> {
    #[cfg(feature = "aggregate_bloom")]
    pub fn reconstruct_running_aggregate(&self) -> anyhow::Result<()> {
        let aggregate = reconstruct_running_aggregate(self.inner())?;
        let mut running_aggregate = match self.running_aggregate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("Poisoned lock in reconstruct_running_aggregate");
                poisoned.into_inner()
            }
        };

        *running_aggregate = aggregate;

        Ok(())
    }

    /// Upsert the [aggregate event bloom filter](AggregateBloom) for the given
    /// block number. This function operates under the assumption that
    /// blocks are _never_ skipped so even if there are no events for a
    /// block, this function should still be called with an empty iterator.
    /// When testing it is fine to skip blocks, as long as the block at the end
    /// of the current range is not skipped.
    #[cfg(feature = "aggregate_bloom")]
    pub(super) fn upsert_block_events_aggregate<'a>(
        &self,
        block_number: BlockNumber,
        events: impl Iterator<Item = &'a Event>,
    ) -> anyhow::Result<()> {
        let mut stmt = self.inner().prepare_cached(
            r"
            INSERT INTO starknet_events_filters_aggregate
            (from_block, to_block, bitmap)
            VALUES (?, ?, ?)
            ON CONFLICT DO UPDATE SET bitmap=excluded.bitmap
            ",
        )?;

        let mut running_aggregate = self.running_aggregate.lock().unwrap();

        let mut bloom = BloomFilter::new();
        for event in events {
            bloom.set_keys(&event.keys);
            bloom.set_address(&event.from_address);
        }

        running_aggregate.add_bloom(&bloom, block_number);
        // This check is the reason that blocks cannot be skipped, if they were we would
        // risk missing the last block of the current aggregate's range.
        if block_number == running_aggregate.to_block {
            stmt.execute(params![
                &running_aggregate.from_block,
                &running_aggregate.to_block,
                &running_aggregate.compress_bitmap()
            ])?;

            *running_aggregate = AggregateBloom::new(running_aggregate.to_block + 1);
        }

        Ok(())
    }

    pub(super) fn upsert_block_events<'a>(
        &self,
        block_number: BlockNumber,
        events: impl Iterator<Item = &'a Event>,
    ) -> anyhow::Result<()> {
        #[rustfmt::skip]
        let mut stmt = self.inner().prepare_cached(
            "INSERT INTO starknet_events_filters (block_number, bloom) VALUES (?, ?) \
            ON CONFLICT DO UPDATE SET bloom=excluded.bloom",
        )?;

        let mut bloom = BloomFilter::new();
        for event in events {
            bloom.set_keys(&event.keys);
            bloom.set_address(&event.from_address);
        }

        stmt.execute(params![&block_number, &bloom.to_compressed_bytes()])?;

        Ok(())
    }

    /// Return all of the events in the given block range, filtered by the given
    /// keys and contract address. Along with the events, return the last
    /// block number that was scanned, which may be smaller than `to_block`
    /// if there are no more blocks in the database.
    pub fn events_in_range(
        &self,
        from_block: BlockNumber,
        to_block: BlockNumber,
        contract_address: Option<ContractAddress>,
        keys: Vec<Vec<EventKey>>,
    ) -> anyhow::Result<(Vec<EmittedEvent>, Option<BlockNumber>)> {
        let key_filter_is_empty = keys.iter().flatten().count() == 0;
        let reorg_counter = self.reorg_counter()?;
        let mut emitted_events = Vec::new();
        let mut block_number = from_block;
        let filter = EventFilter {
            contract_address,
            keys,
            page_size: usize::MAX - 1,
            ..Default::default()
        };
        loop {
            // Stop if we're past the last block.
            if block_number > to_block {
                return Ok((emitted_events, Some(to_block)));
            }

            // Check bloom filter
            if !key_filter_is_empty || contract_address.is_some() {
                let bloom = self.load_bloom(reorg_counter, block_number)?;
                match bloom {
                    Filter::Missing => {}
                    Filter::Cached(bloom) => {
                        if !bloom.check_filter(&filter) {
                            tracing::trace!("Bloom filter did not match");
                            block_number += 1;
                            continue;
                        }
                    }
                    Filter::Loaded(bloom) => {
                        if !bloom.check_filter(&filter) {
                            tracing::trace!("Bloom filter did not match");
                            block_number += 1;
                            continue;
                        }
                    }
                }
            }

            match self.scan_block_into(
                block_number,
                &filter,
                key_filter_is_empty,
                0,
                &mut emitted_events,
            )? {
                BlockScanResult::NoSuchBlock if block_number == from_block => {
                    return Ok((emitted_events, None));
                }
                BlockScanResult::NoSuchBlock => {
                    return Ok((emitted_events, Some(block_number.parent().unwrap())));
                }
                BlockScanResult::Done { .. } => {}
            }

            block_number += 1;
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn events(
        &self,
        filter: &EventFilter,
        max_blocks_to_scan: NonZeroUsize,
        max_uncached_bloom_filters_to_load: NonZeroUsize,
    ) -> Result<PageOfEvents, EventFilterError> {
        if filter.page_size < 1 {
            return Err(EventFilterError::PageSizeTooSmall);
        }

        let reorg_counter = self.reorg_counter()?;

        let from_block = filter.from_block.unwrap_or(BlockNumber::GENESIS);
        let to_block = filter.to_block.unwrap_or(BlockNumber::MAX);
        let key_filter_is_empty = filter.keys.iter().flatten().count() == 0;

        let mut emitted_events = Vec::new();
        let mut bloom_filters_loaded: usize = 0;
        let mut blocks_scanned: usize = 0;
        let mut block_number = from_block;
        let mut offset = filter.offset;

        enum ScanResult {
            Done,
            PageFull,
            ContinueFrom(BlockNumber),
        }

        let result = loop {
            // Stop if we're past the last block.
            if block_number > to_block {
                break ScanResult::Done;
            }

            // Check bloom filter
            if !key_filter_is_empty || filter.contract_address.is_some() {
                let bloom = self.load_bloom(reorg_counter, block_number)?;
                match bloom {
                    Filter::Missing => {}
                    Filter::Cached(bloom) => {
                        if !bloom.check_filter(filter) {
                            tracing::trace!("Bloom filter did not match");
                            block_number += 1;
                            continue;
                        }
                    }
                    Filter::Loaded(bloom) => {
                        bloom_filters_loaded += 1;
                        if !bloom.check_filter(filter) {
                            tracing::trace!("Bloom filter did not match");
                            block_number += 1;
                            continue;
                        }
                    }
                }
            }

            // Check if we've reached our block scan limit
            blocks_scanned += 1;
            if blocks_scanned > max_blocks_to_scan.get() {
                tracing::trace!("Block scan limit reached");
                break ScanResult::ContinueFrom(block_number);
            }

            match self.scan_block_into(
                block_number,
                filter,
                key_filter_is_empty,
                offset,
                &mut emitted_events,
            )? {
                BlockScanResult::NoSuchBlock => break ScanResult::Done,
                BlockScanResult::Done { new_offset } => {
                    offset = new_offset;
                }
            }

            // Stop if we have a page of events plus an extra one to decide if we're on
            // the last page.
            if emitted_events.len() > filter.page_size {
                break ScanResult::PageFull;
            }

            block_number += 1;

            // Check if we've reached our Bloom filter load limit
            if bloom_filters_loaded >= max_uncached_bloom_filters_to_load.get() {
                tracing::trace!("Bloom filter limit reached");
                break ScanResult::ContinueFrom(block_number);
            }
        };

        match result {
            ScanResult::Done => {
                return Ok(PageOfEvents {
                    events: emitted_events,
                    continuation_token: None,
                })
            }
            ScanResult::PageFull => {
                assert!(emitted_events.len() > filter.page_size);
                let continuation_token = continuation_token(
                    &emitted_events,
                    ContinuationToken {
                        block_number: from_block,
                        offset: filter.offset,
                    },
                )
                .unwrap();
                emitted_events.truncate(filter.page_size);

                return Ok(PageOfEvents {
                    events: emitted_events,
                    continuation_token: Some(ContinuationToken {
                        block_number: continuation_token.block_number,
                        // account for the extra event
                        offset: continuation_token.offset - 1,
                    }),
                });
            }
            ScanResult::ContinueFrom(block_number) => {
                // We've reached a search limit without filling the page.
                // We'll need to continue from the next block.
                return Ok(PageOfEvents {
                    events: emitted_events,
                    continuation_token: Some(ContinuationToken {
                        block_number,
                        offset: 0,
                    }),
                });
            }
        }
    }

    #[cfg(feature = "aggregate_bloom")]
    pub fn events_from_aggregate(
        &self,
        filter: &EventFilter,
        max_blocks_to_scan: NonZeroUsize,
        max_bloom_filters_to_load: NonZeroUsize,
    ) -> Result<PageOfEvents, EventFilterError> {
        if filter.page_size < 1 {
            return Err(EventFilterError::PageSizeTooSmall);
        }

        let from_block = filter.from_block.unwrap_or(BlockNumber::GENESIS);
        let to_block = filter.to_block.unwrap_or(BlockNumber::MAX);

        let (aggregates, load_limit_reached) = self.load_limited_aggregate_bloom_range(
            from_block,
            to_block,
            max_bloom_filters_to_load,
        )?;

        let blocks_to_scan = aggregates
            .iter()
            .flat_map(|aggregate| aggregate.blocks_for_filter(filter))
            .filter(|&block| (from_block..=to_block).contains(&block));

        let keys: Vec<std::collections::HashSet<_>> = filter
            .keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let key_filter_is_empty = filter.keys.iter().flatten().count() == 0;
        let mut offset = filter.offset;

        let mut emitted_events = vec![];

        for (blocks_scanned, block) in blocks_to_scan.enumerate() {
            if blocks_scanned >= max_blocks_to_scan.get() {
                tracing::trace!("Reached block scan limit");
                return Ok(PageOfEvents {
                    events: emitted_events,
                    continuation_token: Some(ContinuationToken {
                        block_number: block,
                        offset: 0,
                    }),
                });
            }

            let events_required = filter.page_size + 1 - emitted_events.len();
            tracing::trace!(%block, %events_required, "Processing block");

            let Some(block_header) = self.block_header(crate::BlockId::Number(block))? else {
                break;
            };

            let events = match self.events_for_block(block.into())? {
                Some(events) => events,
                // Reached the end of P2P synced events.
                None => {
                    return Ok(PageOfEvents {
                        events: emitted_events,
                        continuation_token: None,
                    })
                }
            };

            let events = events
                .into_iter()
                .flat_map(|(transaction_hash, events)| {
                    events.into_iter().zip(std::iter::repeat(transaction_hash))
                })
                .filter(|(event, _)| match filter.contract_address {
                    Some(address) => event.from_address == address,
                    None => true,
                })
                .filter(|(event, _)| {
                    if key_filter_is_empty {
                        return true;
                    }

                    if event.keys.len() < keys.len() {
                        return false;
                    }

                    event
                        .keys
                        .iter()
                        .zip(keys.iter())
                        .all(|(key, filter)| filter.is_empty() || filter.contains(key))
                })
                .skip_while(|_| {
                    let should_skip = offset > 0;
                    offset = offset.saturating_sub(1);
                    should_skip
                })
                .take(events_required)
                .map(|(event, tx_hash)| EmittedEvent {
                    data: event.data.clone(),
                    keys: event.keys.clone(),
                    from_address: event.from_address,
                    block_hash: block_header.hash,
                    block_number: block_header.number,
                    transaction_hash: tx_hash,
                });

            emitted_events.extend(events);

            // Stop if we have a page of events plus an extra one to decide if we're on
            // the last page.
            if emitted_events.len() > filter.page_size {
                let continuation_token = continuation_token(
                    &emitted_events,
                    ContinuationToken {
                        block_number: from_block,
                        offset: filter.offset,
                    },
                )
                .unwrap();

                emitted_events.truncate(filter.page_size);

                return Ok(PageOfEvents {
                    events: emitted_events,
                    continuation_token: Some(ContinuationToken {
                        block_number: continuation_token.block_number,
                        // Account for the extra event.
                        offset: continuation_token.offset - 1,
                    }),
                });
            }
        }

        if load_limit_reached {
            let last_loaded_block = aggregates
                .last()
                .expect("At least one filter is present")
                .to_block;

            Ok(PageOfEvents {
                events: emitted_events,
                continuation_token: Some(ContinuationToken {
                    // Bloom filter range is inclusive so + 1.
                    block_number: last_loaded_block + 1,
                    offset: 0,
                }),
            })
        } else {
            Ok(PageOfEvents {
                events: emitted_events,
                continuation_token: None,
            })
        }
    }

    fn scan_block_into(
        &self,
        block_number: BlockNumber,
        filter: &EventFilter,
        key_filter_is_empty: bool,
        mut offset: usize,
        emitted_events: &mut Vec<EmittedEvent>,
    ) -> Result<BlockScanResult, EventFilterError> {
        let events_required = filter.page_size + 1 - emitted_events.len();

        tracing::trace!(%block_number, %events_required, "Processing block");

        let block_header = self.block_header(crate::BlockId::Number(block_number))?;
        let Some(block_header) = block_header else {
            return Ok(BlockScanResult::NoSuchBlock);
        };

        let events = self.events_for_block(block_number.into())?;
        let Some(events) = events else {
            return Ok(BlockScanResult::NoSuchBlock);
        };

        let keys: Vec<std::collections::HashSet<_>> = filter
            .keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let events = events
            .into_iter()
            .flat_map(|(transaction_hash, events)| {
                events.into_iter().zip(std::iter::repeat(transaction_hash))
            })
            .filter(|(event, _)| match filter.contract_address {
                Some(address) => event.from_address == address,
                None => true,
            })
            .filter(|(event, _)| {
                if key_filter_is_empty {
                    return true;
                }

                if event.keys.len() < keys.len() {
                    return false;
                }

                event
                    .keys
                    .iter()
                    .zip(keys.iter())
                    .all(|(key, filter)| filter.is_empty() || filter.contains(key))
            })
            .skip_while(|_| {
                let skip = offset > 0;
                offset = offset.saturating_sub(1);
                skip
            })
            .take(events_required)
            .map(|(event, tx_hash)| EmittedEvent {
                data: event.data.clone(),
                keys: event.keys.clone(),
                from_address: event.from_address,
                block_hash: block_header.hash,
                block_number: block_header.number,
                transaction_hash: tx_hash,
            });

        emitted_events.extend(events);

        Ok(BlockScanResult::Done { new_offset: offset })
    }

    fn load_bloom(
        &self,
        reorg_counter: ReorgCounter,
        block_number: BlockNumber,
    ) -> Result<Filter, EventFilterError> {
        if let Some(bloom) = self.bloom_filter_cache.get(reorg_counter, block_number) {
            return Ok(Filter::Cached(bloom));
        }

        let mut stmt = self
            .inner()
            .prepare_cached("SELECT bloom FROM starknet_events_filters WHERE block_number = ?")?;

        let bloom = stmt
            .query_row(params![&block_number], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(BloomFilter::from_compressed_bytes(&bytes))
            })
            .optional()?;

        Ok(match bloom {
            Some(bloom) => {
                self.bloom_filter_cache
                    .set(reorg_counter, block_number, bloom.clone());
                Filter::Loaded(bloom)
            }
            None => Filter::Missing,
        })
    }

    // TODO:
    // Use this for `SubscribeEvents`
    #[cfg(feature = "aggregate_bloom")]
    #[allow(dead_code)]
    fn load_aggregate_bloom_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> anyhow::Result<Vec<AggregateBloom>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT from_block, to_block, bitmap
            FROM starknet_events_filters_aggregate
            WHERE from_block <= :end_block AND to_block >= :start_block
            ORDER BY from_block
            ",
        )?;

        let mut aggregates = stmt
            .query_map(
                named_params![
                    ":end_block": &end_block,
                    ":start_block": &start_block,
                ],
                |row| {
                    let from_block = row.get_block_number(0)?;
                    let to_block = row.get_block_number(1)?;
                    let compressed_bitmap: Vec<u8> = row.get(2)?;

                    Ok(AggregateBloom::from_existing_compressed(
                        from_block,
                        to_block,
                        compressed_bitmap,
                    ))
                },
            )
            .context("Querying bloom filter range")?
            .collect::<Result<Vec<_>, _>>()?;

        // There are no aggregates in the database yet or the loaded aggregates
        // don't cover the requested range.
        let should_include_running = aggregates.last().map_or(true, |a| end_block > a.to_block);

        if should_include_running {
            let running_aggregate = match self.running_aggregate.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("Poisoned lock in load_aggregate_bloom_range");
                    poisoned.into_inner()
                }
            };
            aggregates.push(running_aggregate.clone());
        }

        Ok(aggregates)
    }

    #[cfg(feature = "aggregate_bloom")]
    fn load_limited_aggregate_bloom_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        max_bloom_filters_to_load: NonZeroUsize,
    ) -> anyhow::Result<(Vec<AggregateBloom>, bool)> {
        let mut select_filters_stmt = self.inner().prepare_cached(
            r"
            SELECT from_block, to_block, bitmap
            FROM starknet_events_filters_aggregate
            WHERE from_block <= :end_block AND to_block >= :start_block
            ORDER BY from_block
            LIMIT :max_bloom_filters_to_load
            ",
        )?;
        let mut total_filters_stmt = self.inner().prepare_cached(
            r"
            SELECT COUNT(*)
            FROM starknet_events_filters_aggregate
            WHERE from_block <= :end_block AND to_block >= :start_block
            ",
        )?;

        let mut aggregates = select_filters_stmt
            .query_map(
                named_params![
                    ":end_block": &end_block,
                    ":start_block": &start_block,
                    ":max_bloom_filters_to_load": &max_bloom_filters_to_load.get(),
                ],
                |row| {
                    let from_block = row.get_block_number(0)?;
                    let to_block = row.get_block_number(1)?;
                    let compressed_bitmap: Vec<u8> = row.get(2)?;

                    Ok(AggregateBloom::from_existing_compressed(
                        from_block,
                        to_block,
                        compressed_bitmap,
                    ))
                },
            )
            .context("Querying bloom filter range")?
            .collect::<Result<Vec<_>, _>>()?;

        // There are no aggregates in the database yet or the loaded aggregates
        // don't cover the requested range.
        let should_include_running = aggregates.last().map_or(true, |a| end_block > a.to_block);

        let total_aggregate_filters = total_filters_stmt.query_row(
            named_params![
                ":end_block": &end_block,
                ":start_block": &start_block,
            ],
            |row| row.get::<_, u64>(0),
        )?;
        let load_limit_reached = total_aggregate_filters > max_bloom_filters_to_load.get() as u64;

        if should_include_running && !load_limit_reached {
            let running_aggregate = match self.running_aggregate.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("Poisoned lock in load_aggregate_bloom_range");
                    poisoned.into_inner()
                }
            };
            aggregates.push(running_aggregate.clone());
        }

        Ok((aggregates, load_limit_reached))
    }
}

/// Reconstruct the [aggregate](crate::bloom::AggregateBloom) for the range of
/// blocks between the last stored `to_block` in the aggregate Bloom filter
/// table and the last overall block in the database. This is needed because the
/// aggregate Bloom filter for each [block
/// range](crate::bloom::AggregateBloom::BLOCK_RANGE_LEN) is stored once the
/// range is complete, before that it is kept in memory and can be lost upon
/// shutdown.
#[cfg(feature = "aggregate_bloom")]
pub fn reconstruct_running_aggregate(
    tx: &rusqlite::Transaction<'_>,
) -> anyhow::Result<AggregateBloom> {
    use super::transaction;

    let mut last_to_block_stmt = tx.prepare(
        r"
        SELECT to_block
        FROM starknet_events_filters_aggregate
        ORDER BY from_block DESC LIMIT 1
        ",
    )?;
    let mut events_to_reconstruct_stmt = tx.prepare(
        r"
        SELECT events
        FROM transactions
        WHERE block_number >= :first_running_aggregate_block
        ",
    )?;

    let last_to_block = last_to_block_stmt
        .query_row([], |row| row.get::<_, u64>(0))
        .optional()
        .context("Querying last stored aggregate to_block")?;

    let first_running_aggregate_block = match last_to_block {
        Some(last_to_block) => BlockNumber::new_or_panic(last_to_block + 1),
        // Aggregate Bloom filter table is empty -> reconstruct running aggregate
        // from the genesis block.
        None => BlockNumber::GENESIS,
    };

    let events_to_reconstruct: Vec<Option<Vec<Vec<Event>>>> = events_to_reconstruct_stmt
        .query_and_then(
            named_params![":first_running_aggregate_block": &first_running_aggregate_block],
            |row| {
                let events: Option<transaction::dto::EventsForBlock> = row
                    .get_optional_blob(0)?
                    .map(|events_blob| -> anyhow::Result<_> {
                        let events = transaction::compression::decompress_events(events_blob)
                            .context("Decompressing events")?;
                        let events: transaction::dto::EventsForBlock =
                            bincode::serde::decode_from_slice(&events, bincode::config::standard())
                                .context("Deserializing events")?
                                .0;

                        Ok(events)
                    })
                    .transpose()?;

                Ok(events.map(|events| {
                    events
                        .events()
                        .into_iter()
                        .map(|e| e.into_iter().map(Into::into).collect())
                        .collect()
                }))
            },
        )
        .context("Querying events to reconstruct")?
        .collect::<anyhow::Result<_>>()?;

    let mut running_aggregate = AggregateBloom::new(first_running_aggregate_block);

    for (block, events_for_block) in events_to_reconstruct.iter().enumerate() {
        if let Some(events) = events_for_block {
            let block_number = first_running_aggregate_block + block as u64;

            let mut bloom = BloomFilter::new();
            for event in events.iter().flatten() {
                bloom.set_keys(&event.keys);
                bloom.set_address(&event.from_address);
            }

            running_aggregate.add_bloom(&bloom, block_number);
        }
    }

    Ok(running_aggregate)
}

fn continuation_token(
    events: &[EmittedEvent],
    previous_token: ContinuationToken,
) -> Option<ContinuationToken> {
    if events.is_empty() {
        return None;
    }

    let last_block_number = events.last().unwrap().block_number;
    let number_of_events_in_last_block = events
        .iter()
        .rev()
        .take_while(|event| event.block_number == last_block_number)
        .count();

    // Since we're taking the block number of the last block this is at least one.
    assert!(number_of_events_in_last_block >= 1);

    let token = if number_of_events_in_last_block < events.len() {
        // the page contains events from a new block
        ContinuationToken {
            block_number: last_block_number,
            offset: number_of_events_in_last_block,
        }
    } else {
        // the page contains events from the same block
        ContinuationToken {
            block_number: previous_token.block_number,
            offset: previous_token.offset + events.len(),
        }
    };

    Some(token)
}

enum BlockScanResult {
    NoSuchBlock,
    Done { new_offset: usize },
}

enum Filter {
    Missing,
    Cached(BloomFilter),
    Loaded(BloomFilter),
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::{transaction as common, BlockHeader, BlockTimestamp, EntryPoint, Fee};
    use pathfinder_crypto::Felt;
    use pretty_assertions_sorted::assert_eq;

    use super::*;
    use crate::test_utils;

    static MAX_BLOCKS_TO_SCAN: LazyLock<NonZeroUsize> =
        LazyLock::new(|| NonZeroUsize::new(100).unwrap());
    static MAX_BLOOM_FILTERS_TO_LOAD: LazyLock<NonZeroUsize> =
        LazyLock::new(|| NonZeroUsize::new(100).unwrap());
    #[cfg(feature = "aggregate_bloom")]
    static MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD: LazyLock<NonZeroUsize> =
        LazyLock::new(|| NonZeroUsize::new(3).unwrap());

    #[test_log::test(test)]
    fn get_events_with_fully_specified_filter() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[1];
        let filter = EventFilter {
            from_block: Some(expected_event.block_number),
            to_block: Some(expected_event.block_number),
            contract_address: Some(expected_event.from_address),
            // we're using a key which is present in _all_ events as the 2nd key
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn events_are_ordered() {
        // This is a regression test where events were incorrectly ordered by
        // transaction hash instead of transaction index.
        //
        // Events should be ordered by block number, transaction index, event index.

        // All events we are storing, arbitrarily use from_address to distinguish them.
        let expected_events = (0u8..5)
            .map(|idx| Event {
                data: Vec::new(),
                keys: Vec::new(),
                from_address: ContractAddress::new_or_panic(
                    Felt::from_be_slice(&idx.to_be_bytes()).unwrap(),
                ),
            })
            .collect::<Vec<_>>();

        let header = BlockHeader::builder()
            .sequencer_address(sequencer_address!("0x1234"))
            .timestamp(BlockTimestamp::new_or_panic(0))
            .state_commitment(state_commitment!("0x1234"))
            .finalize_with_hash(block_hash!("0x1234"));

        // Note: hashes are reverse ordered to trigger the sorting bug.
        let transactions = vec![
            common::Transaction {
                hash: transaction_hash!("0xF"),
                variant: common::TransactionVariant::InvokeV0(common::InvokeTransactionV0 {
                    calldata: vec![],
                    // Only required because event insert rejects if this is None
                    sender_address: ContractAddress::new_or_panic(Felt::ZERO),
                    entry_point_type: Some(common::EntryPointType::External),
                    entry_point_selector: EntryPoint(Felt::ZERO),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                }),
            },
            common::Transaction {
                hash: transaction_hash!("0x1"),
                variant: common::TransactionVariant::InvokeV0(common::InvokeTransactionV0 {
                    calldata: vec![],
                    // Only required because event insert rejects if this is None
                    sender_address: ContractAddress::new_or_panic(Felt::ZERO),
                    entry_point_type: Some(common::EntryPointType::External),
                    entry_point_selector: EntryPoint(Felt::ZERO),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                }),
            },
        ];

        let receipts = vec![
            Receipt {
                transaction_hash: transactions[0].hash,
                transaction_index: pathfinder_common::TransactionIndex::new_or_panic(0),
                ..Default::default()
            },
            Receipt {
                transaction_hash: transactions[1].hash,
                transaction_index: pathfinder_common::TransactionIndex::new_or_panic(1),
                ..Default::default()
            },
        ];

        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        tx.insert_block_header(&header).unwrap();
        tx.insert_transaction_data(
            header.number,
            &vec![
                (transactions[0].clone(), receipts[0].clone()),
                (transactions[1].clone(), receipts[1].clone()),
            ],
            Some(&[expected_events[..3].to_vec(), expected_events[3..].to_vec()]),
        )
        .unwrap();

        let addresses = tx
            .events(
                &EventFilter {
                    from_block: None,
                    to_block: None,
                    contract_address: None,
                    keys: vec![],
                    page_size: 1024,
                    offset: 0,
                },
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap()
            .events
            .iter()
            .map(|e| e.from_address)
            .collect::<Vec<_>>();

        let expected = expected_events
            .iter()
            .map(|e| e.from_address)
            .collect::<Vec<_>>();

        assert_eq!(addresses, expected);
    }

    #[test]
    fn get_events_by_block() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const BLOCK_NUMBER: usize = 2;
        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64)),
            to_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64)),
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let expected_events = &emitted_events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
            ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_up_to_block() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const UNTIL_BLOCK_NUMBER: usize = 2;
        let filter = EventFilter {
            from_block: None,
            to_block: Some(BlockNumber::new_or_panic(UNTIL_BLOCK_NUMBER as u64)),
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let expected_events =
            &emitted_events[..test_utils::EVENTS_PER_BLOCK * (UNTIL_BLOCK_NUMBER + 1)];
        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_up_to_block_with_paging() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: Some(BlockNumber::new_or_panic(1)),
            contract_address: None,
            keys: vec![],
            page_size: test_utils::EVENTS_PER_BLOCK + 1,
            offset: 0,
        };

        let expected_events = &emitted_events[..test_utils::EVENTS_PER_BLOCK + 1];
        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        pretty_assertions_sorted::assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(1),
                    offset: 1
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // test continuation token
        let filter = EventFilter {
            from_block: Some(events.continuation_token.unwrap().block_number),
            to_block: Some(BlockNumber::new_or_panic(1)),
            contract_address: None,
            keys: vec![],
            page_size: test_utils::EVENTS_PER_BLOCK + 1,
            offset: events.continuation_token.unwrap().offset,
        };

        let expected_events =
            &emitted_events[test_utils::EVENTS_PER_BLOCK + 1..test_utils::EVENTS_PER_BLOCK * 2];
        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        pretty_assertions_sorted::assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_from_block_onwards() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const FROM_BLOCK_NUMBER: usize = 2;
        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(FROM_BLOCK_NUMBER as u64)),
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let expected_events = &emitted_events[test_utils::EVENTS_PER_BLOCK * FROM_BLOCK_NUMBER..];
        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_from_contract() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[33];

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: Some(expected_event.from_address),
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_by_key() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[27];
        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![vec![expected_event.keys[0]], vec![expected_event.keys[1]]],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // try event keys in the wrong order, should not match
        let filter = EventFilter {
            keys: vec![vec![expected_event.keys[1]], vec![expected_event.keys[0]]],
            ..filter
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_with_no_filter() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events,
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_with_no_filter_and_paging() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[..10].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(1),
                    offset: 0
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 10,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[10..20].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(2),
                    offset: 0
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 30,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[30..40].to_vec(),
                continuation_token: None
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_with_no_filter_and_nonexistent_page() {
        let (storage, _) = test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const PAGE_SIZE: usize = 10;
        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: PAGE_SIZE,
            // _after_ the last one
            offset: test_utils::NUM_BLOCKS * test_utils::EVENTS_PER_BLOCK,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn get_events_by_key_with_paging() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_events = &emitted_events[27..32];
        let keys_for_expected_events = vec![
            expected_events.iter().map(|e| e.keys[0]).collect(),
            expected_events.iter().map(|e| e.keys[1]).collect(),
        ];

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[..2].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(0),
                    offset: 2
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // increase offset
        let filter: EventFilter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 2,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[2..4].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(3),
                    offset: 1
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // using the continuation token should be equivalent to the previous query
        let filter: EventFilter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(0)),
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 2,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[2..4].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(3),
                    offset: 1
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // increase offset by two
        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 4,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[4..].to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        // using the continuation token should be equivalent to the previous query
        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(3)),
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events,
            page_size: 2,
            offset: 1,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[4..].to_vec(),
                continuation_token: None,
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    *MAX_BLOCKS_TO_SCAN,
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    fn scan_limit() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 20,
            offset: 0,
        };

        let events = tx
            .events(&filter, 1.try_into().unwrap(), *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[..10].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(1),
                    offset: 0
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    1.try_into().unwrap(),
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }

        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(1)),
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 20,
            offset: 0,
        };

        let events = tx
            .events(&filter, 1.try_into().unwrap(), *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[10..20].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(2),
                    offset: 0
                }),
            }
        );

        #[cfg(feature = "aggregate_bloom")]
        {
            let events_from_aggregate = tx
                .events_from_aggregate(
                    &filter,
                    1.try_into().unwrap(),
                    *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
                )
                .unwrap();
            assert_eq!(events_from_aggregate, events);
        }
    }

    #[test]
    #[cfg(feature = "aggregate_bloom")]
    fn crossing_aggregate_filter_range_stores_and_updates_running() {
        let blocks: Vec<usize> = [
            // First aggregate filter start.
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + 1,
            BlockNumber::GENESIS + 2,
            BlockNumber::GENESIS + 3,
            // End.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Second aggregate filter start.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 1,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 2,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 3,
            // End.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Third aggregate filter start.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN + 1,
        ]
        .iter()
        .map(|&n| n.get() as usize)
        .collect();

        let (storage, _) = test_utils::setup_custom_test_storage(&blocks, 2);
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let inserted_aggregate_filter_count = tx
            .inner()
            .prepare("SELECT COUNT(*) FROM starknet_events_filters_aggregate")
            .unwrap()
            .query_row([], |row| row.get::<_, u64>(0))
            .unwrap();
        assert_eq!(inserted_aggregate_filter_count, 2);

        let running_aggregate = tx.running_aggregate.lock().unwrap();
        // Running aggregate starts from next block range.
        assert_eq!(
            running_aggregate.from_block,
            2 * AggregateBloom::BLOCK_RANGE_LEN
        );
    }

    #[test]
    #[cfg(feature = "aggregate_bloom")]
    fn aggregate_bloom_filter_load_limit() {
        let blocks: Vec<usize> = [
            // First aggregate filter start.
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + 1,
            BlockNumber::GENESIS + 2,
            BlockNumber::GENESIS + 3,
            // End.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Second aggregate filter start.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 1,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 2,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 3,
            // End.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Third aggregate filter start.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN + 1,
        ]
        .iter()
        .map(|&n| n.get() as usize)
        .collect();

        let (storage, test_data) = test_utils::setup_custom_test_storage(&blocks, 2);
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            // We're using a key which is present in _all_ events as the 2nd key...
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events_from_aggregate(&filter, *MAX_BLOCKS_TO_SCAN, 1.try_into().unwrap())
            .unwrap();

        let first_aggregate_filter_range =
            BlockNumber::GENESIS.get()..AggregateBloom::BLOCK_RANGE_LEN;
        for event in events.events {
            // ...but only events from the first bloom filter range are returned.
            assert!(
                first_aggregate_filter_range.contains(&event.block_number.get()),
                "Event block number: {} should have been in the range: {:?}",
                event.block_number.get(),
                first_aggregate_filter_range
            );
        }
        let continue_from_block = events.continuation_token.unwrap().block_number;
        assert_eq!(continue_from_block, first_aggregate_filter_range.end);

        let filter_with_offset = EventFilter {
            from_block: Some(events.continuation_token.unwrap().block_number),
            to_block: None,
            contract_address: None,
            // We're using a key which is present in _all_ events as the 2nd key...
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events_from_aggregate(
                &filter_with_offset,
                *MAX_BLOCKS_TO_SCAN,
                1.try_into().unwrap(),
            )
            .unwrap();
        assert!(events.continuation_token.is_none());

        let second_aggregate_filter_range =
            AggregateBloom::BLOCK_RANGE_LEN..(2 * AggregateBloom::BLOCK_RANGE_LEN);
        let third_aggregate_filter_range =
            2 * AggregateBloom::BLOCK_RANGE_LEN..(3 * AggregateBloom::BLOCK_RANGE_LEN);
        for event in events.events {
            // ...but only events from the second (loaded) and third (running) bloom filter
            // range are returned.
            assert!(
                (second_aggregate_filter_range.start..third_aggregate_filter_range.end)
                    .contains(&event.block_number.get())
            );
        }
    }

    #[test]
    fn bloom_filter_load_limit() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![vec![], vec![emitted_events[0].keys[1]]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, 1.try_into().unwrap())
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[..10].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(1),
                    offset: 0
                }),
            }
        );

        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(1)),
            to_block: None,
            contract_address: None,
            keys: vec![vec![], vec![emitted_events[0].keys[1]]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, 1.try_into().unwrap())
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[10..20].to_vec(),
                continuation_token: Some(ContinuationToken {
                    block_number: BlockNumber::new_or_panic(2),
                    offset: 0
                }),
            }
        );
    }
}
