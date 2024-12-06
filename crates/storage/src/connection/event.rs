use std::collections::BTreeSet;
use std::num::NonZeroUsize;

use anyhow::{Context, Result};
use pathfinder_common::event::Event;
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    ContractAddress,
    EventData,
    EventKey,
    TransactionHash,
};

use crate::bloom::{AggregateBloom, BloomFilter};
use crate::prelude::*;

// We're using the upper 4 bits of the 32 byte representation of a felt
// to store the index of the key in the values set in the Bloom filter.
// This allows for the maximum of 16 keys per event to be stored in the
// filter.
pub const EVENT_KEY_FILTER_LIMIT: usize = 16;
pub const PAGE_SIZE_LIMIT: usize = 1_024;

#[derive(Debug, Default)]
pub struct EventConstraints {
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
    pub fn reconstruct_running_event_filter(&self) -> anyhow::Result<()> {
        let event_filter = reconstruct_running_event_filter(self.inner())?;
        let mut running_event_filter = self.running_event_filter.lock().unwrap();
        *running_event_filter = event_filter;

        Ok(())
    }

    /// Upsert the [running event Bloom filter](RunningEventFilter) for the
    /// given block number. This function operates under the assumption that
    /// blocks are _never_ skipped so even if there are no events for a
    /// block, this function should still be called with an empty iterator.
    /// When testing it is fine to skip blocks, as long as the block at the end
    /// of the current range is not skipped.
    pub(super) fn upsert_block_event_filters<'a>(
        &self,
        block_number: BlockNumber,
        events: impl Iterator<Item = &'a Event>,
    ) -> anyhow::Result<()> {
        let mut stmt = self.inner().prepare_cached(
            r"
            INSERT INTO event_filters
            (from_block, to_block, bitmap)
            VALUES (?, ?, ?)
            ON CONFLICT DO UPDATE SET bitmap=excluded.bitmap
            ",
        )?;

        let mut running_event_filter = self.running_event_filter.lock().unwrap();

        let mut bloom = BloomFilter::new();
        for event in events {
            bloom.set_keys(&event.keys);
            bloom.set_address(&event.from_address);
        }

        running_event_filter.filter.add_bloom(&bloom, block_number);
        running_event_filter.next_block = block_number + 1;

        // This check is the reason that blocks cannot be skipped, if they were we would
        // risk missing the last block of the running event filter's range.
        if block_number == running_event_filter.filter.to_block {
            stmt.execute(params![
                &running_event_filter.filter.from_block,
                &running_event_filter.filter.to_block,
                &running_event_filter.filter.compress_bitmap()
            ])?;

            *running_event_filter = RunningEventFilter {
                filter: AggregateBloom::new(block_number + 1),
                next_block: block_number + 1,
            };
        }

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
        let Some(latest_block) = self.block_number(crate::BlockId::Latest)? else {
            // No blocks in the database
            return Ok((vec![], None));
        };
        if from_block > latest_block {
            return Ok((vec![], None));
        }

        let constraints = EventConstraints {
            contract_address,
            keys,
            page_size: usize::MAX - 1,
            ..Default::default()
        };

        let event_filters = self.load_event_filter_range(from_block, to_block)?;

        let blocks_to_scan = event_filters
            .iter()
            .flat_map(|filter| filter.check(&constraints))
            .filter(|&block| (from_block..=to_block).contains(&block));

        let key_filter_is_empty = constraints.keys.iter().flatten().count() == 0;
        let keys: Vec<std::collections::HashSet<_>> = constraints
            .keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let mut emitted_events = vec![];

        for block in blocks_to_scan {
            let Some(block_header) = self.block_header(crate::BlockId::Number(block))? else {
                break;
            };

            let events = match self.events_for_block(block.into())? {
                Some(events) => events,
                // Reached the end of P2P (checkpoint) synced events.
                None => break,
            };

            let events = events
                .into_iter()
                .flat_map(|(transaction_hash, events)| {
                    events.into_iter().zip(std::iter::repeat(transaction_hash))
                })
                .filter(|(event, _)| match constraints.contract_address {
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
                .map(|(event, tx_hash)| EmittedEvent {
                    data: event.data.clone(),
                    keys: event.keys.clone(),
                    from_address: event.from_address,
                    block_hash: block_header.hash,
                    block_number: block_header.number,
                    transaction_hash: tx_hash,
                });

            emitted_events.extend(events);
        }

        let last_scanned_block = if latest_block > to_block {
            to_block
        } else {
            latest_block
        };

        Ok((emitted_events, Some(last_scanned_block)))
    }

    #[tracing::instrument(skip(self))]
    pub fn events(
        &self,
        constraints: &EventConstraints,
        max_blocks_to_scan: NonZeroUsize,
        max_event_filters_to_load: NonZeroUsize,
    ) -> Result<PageOfEvents, EventFilterError> {
        if constraints.page_size < 1 {
            return Err(EventFilterError::PageSizeTooSmall);
        }

        let from_block = constraints.from_block.unwrap_or(BlockNumber::GENESIS);
        let to_block = constraints.to_block.unwrap_or(BlockNumber::MAX);

        let (event_filters, load_limit_reached) =
            self.load_limited_event_filter_range(from_block, to_block, max_event_filters_to_load)?;

        let blocks_to_scan = event_filters
            .iter()
            .flat_map(|filter| filter.check(constraints))
            .filter(|&block| (from_block..=to_block).contains(&block));

        let keys: Vec<std::collections::HashSet<_>> = constraints
            .keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let key_filter_is_empty = constraints.keys.iter().flatten().count() == 0;
        let mut offset = constraints.offset;

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

            let events_required = constraints.page_size + 1 - emitted_events.len();
            tracing::trace!(%block, %events_required, "Processing block");

            let Some(block_header) = self.block_header(crate::BlockId::Number(block))? else {
                break;
            };

            let events = match self.events_for_block(block.into())? {
                Some(events) => events,
                // Reached the end of P2P (checkpoint) synced events.
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
                .filter(|(event, _)| match constraints.contract_address {
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
            if emitted_events.len() > constraints.page_size {
                let continuation_token = continuation_token(
                    &emitted_events,
                    ContinuationToken {
                        block_number: from_block,
                        offset: constraints.offset,
                    },
                )
                .unwrap();

                emitted_events.truncate(constraints.page_size);

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
            let last_loaded_block = event_filters
                .last()
                .expect("At least one filter is present")
                .to_block;

            Ok(PageOfEvents {
                events: emitted_events,
                continuation_token: Some(ContinuationToken {
                    // Event filter block range is inclusive so + 1.
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
    fn load_event_filter_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> anyhow::Result<Vec<AggregateBloom>> {
        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT from_block, to_block, bitmap
            FROM event_filters
            WHERE from_block <= :end_block AND to_block >= :start_block
            ORDER BY from_block
            ",
        )?;

        let mut event_filters = stmt
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
            .context("Querying event filter range")?
            .collect::<Result<Vec<_>, _>>()?;

        // There are no event filters in the database yet or the loaded ones
        // don't cover the requested range.
        let should_include_running = event_filters
            .last()
            .map_or(true, |a| end_block > a.to_block);

        if should_include_running {
            let running_event_filter = self.running_event_filter.lock().unwrap();
            event_filters.push(running_event_filter.filter.clone());
        }

        Ok(event_filters)
    }

    fn load_limited_event_filter_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        max_event_filters_to_load: NonZeroUsize,
    ) -> anyhow::Result<(Vec<AggregateBloom>, bool)> {
        let mut event_filters_in_range_stmt = self.inner().prepare_cached(
            r"
            SELECT from_block, to_block, bitmap
            FROM event_filters
            WHERE from_block <= :end_block AND to_block >= :start_block
            ORDER BY from_block
            LIMIT :max_event_filters_to_load
            ",
        )?;
        let mut total_filters_stmt = self.inner().prepare_cached(
            r"
            SELECT COUNT(*)
            FROM event_filters
            WHERE from_block <= :end_block AND to_block >= :start_block
            ",
        )?;

        let mut event_filters = event_filters_in_range_stmt
            .query_map(
                named_params![
                    ":end_block": &end_block,
                    ":start_block": &start_block,
                    ":max_event_filters_to_load": &max_event_filters_to_load.get(),
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
            .context("Querying event filter range")?
            .collect::<Result<Vec<_>, _>>()?;

        // There are no event filters in the database yet or the loaded ones
        // don't cover the requested range.
        let should_include_running = event_filters
            .last()
            .map_or(true, |a| end_block > a.to_block);

        let total_event_filters = total_filters_stmt.query_row(
            named_params![
                ":end_block": &end_block,
                ":start_block": &start_block,
            ],
            |row| row.get::<_, u64>(0),
        )?;
        let load_limit_reached = total_event_filters > max_event_filters_to_load.get() as u64;

        if should_include_running && !load_limit_reached {
            let running_event_filter = self.running_event_filter.lock().unwrap();
            event_filters.push(running_event_filter.filter.clone());
        }

        Ok((event_filters, load_limit_reached))
    }

    pub fn next_block_without_events(&self) -> BlockNumber {
        self.running_event_filter.lock().unwrap().next_block
    }
}

impl AggregateBloom {
    /// Returns the block numbers that match the given constraints.
    pub fn check(&self, constraints: &EventConstraints) -> BTreeSet<BlockNumber> {
        let addr_blocks = self.check_address(constraints.contract_address);
        let keys_blocks = self.check_keys(&constraints.keys);

        addr_blocks.intersection(&keys_blocks).cloned().collect()
    }

    fn check_address(&self, address: Option<ContractAddress>) -> BTreeSet<BlockNumber> {
        match address {
            Some(addr) => self.blocks_for_keys(&[addr.0]),
            None => self.all_blocks(),
        }
    }

    fn check_keys(&self, keys: &[Vec<EventKey>]) -> BTreeSet<BlockNumber> {
        if keys.is_empty() {
            return self.all_blocks();
        }

        keys.iter()
            .enumerate()
            .map(|(idx, key_group)| {
                let indexed_keys: Vec<_> = key_group
                    .iter()
                    .map(|key| {
                        let mut key_with_idx = key.0;
                        key_with_idx.as_mut_be_bytes()[0] |= (idx as u8) << 4;
                        key_with_idx
                    })
                    .collect();

                self.blocks_for_keys(&indexed_keys)
            })
            .reduce(|blocks, blocks_for_key| {
                blocks.intersection(&blocks_for_key).cloned().collect()
            })
            .unwrap_or_default()
    }
}

impl BloomFilter {
    pub fn set_address(&mut self, address: &ContractAddress) {
        self.set(&address.0);
    }

    pub fn set_keys(&mut self, keys: &[EventKey]) {
        for (i, key) in keys.iter().take(EVENT_KEY_FILTER_LIMIT).enumerate() {
            let mut key = key.0;
            key.as_mut_be_bytes()[0] |= (i as u8) << 4;
            self.set(&key);
        }
    }
}

#[derive(Debug)]
pub(crate) struct RunningEventFilter {
    filter: AggregateBloom,
    next_block: BlockNumber,
}

/// Reconstruct the [event filter](RunningEventFilter) for the
/// range of blocks between the last stored `to_block` in the event
/// filter table and the last overall block in the database. This is needed
/// because the aggregate event filter for each [block
/// range](crate::bloom::AggregateBloom::BLOCK_RANGE_LEN) is stored once the
/// range is complete, before that it is kept in memory and can be lost upon
/// shutdown.
pub(crate) fn reconstruct_running_event_filter(
    tx: &rusqlite::Transaction<'_>,
) -> anyhow::Result<RunningEventFilter> {
    use super::transaction;

    let mut last_to_block_stmt = tx.prepare(
        r"
        SELECT to_block
        FROM event_filters
        ORDER BY from_block DESC LIMIT 1
        ",
    )?;
    let mut events_to_reconstruct_stmt = tx.prepare(
        r"
        SELECT events
        FROM transactions
        WHERE block_number >= :first_running_event_filter_block
        ",
    )?;

    let last_to_block = last_to_block_stmt
        .query_row([], |row| row.get::<_, u64>(0))
        .optional()
        .context("Querying last stored event filter to_block")?;

    let first_running_event_filter_block = match last_to_block {
        Some(last_to_block) => BlockNumber::new_or_panic(last_to_block + 1),
        // Event filter table is empty -> reconstruct running filter
        // from the genesis block.
        None => BlockNumber::GENESIS,
    };

    let events_to_reconstruct: Vec<Option<Vec<Vec<Event>>>> = events_to_reconstruct_stmt
        .query_and_then(
            named_params![":first_running_event_filter_block": &first_running_event_filter_block],
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

    let mut filter = AggregateBloom::new(first_running_event_filter_block);

    for (block, events_for_block) in events_to_reconstruct.iter().enumerate() {
        let Some(events) = events_for_block else {
            break;
        };

        let mut bloom = BloomFilter::new();
        for event in events.iter().flatten() {
            bloom.set_keys(&event.keys);
            bloom.set_address(&event.from_address);
        }

        let block_number = first_running_event_filter_block + block as u64;
        filter.add_bloom(&bloom, block_number);
    }

    Ok(RunningEventFilter {
        filter,
        next_block: first_running_event_filter_block + events_to_reconstruct.len() as u64,
    })
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
        LazyLock::new(|| NonZeroUsize::new(3).unwrap());

    mod event_bloom {
        use pretty_assertions_sorted::assert_eq;

        use super::*;

        #[test]
        fn matching_constraints() {
            let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);

            let mut filter = BloomFilter::new();
            filter.set_keys(&[event_key!("0xdeadbeef")]);
            filter.set_address(&contract_address!("0x1234"));

            aggregate.add_bloom(&filter, BlockNumber::GENESIS);
            aggregate.add_bloom(&filter, BlockNumber::GENESIS + 1);
            let constraints = EventConstraints {
                from_block: None,
                to_block: None,
                contract_address: Some(contract_address!("0x1234")),
                keys: vec![vec![event_key!("0xdeadbeef")]],
                page_size: 1024,
                offset: 0,
            };

            assert_eq!(
                aggregate.check(&constraints),
                BTreeSet::from_iter(vec![BlockNumber::GENESIS, BlockNumber::GENESIS + 1])
            );
        }

        #[test]
        fn correct_key_wrong_address() {
            let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);

            let mut filter = BloomFilter::new();
            filter.set_keys(&[event_key!("0xdeadbeef")]);
            filter.set_address(&contract_address!("0x1234"));

            aggregate.add_bloom(&filter, BlockNumber::GENESIS);
            aggregate.add_bloom(&filter, BlockNumber::GENESIS + 1);
            let constraints = EventConstraints {
                from_block: None,
                to_block: None,
                contract_address: Some(contract_address!("0x4321")),
                keys: vec![vec![event_key!("0xdeadbeef")]],
                page_size: 1024,
                offset: 0,
            };

            assert_eq!(aggregate.check(&constraints), BTreeSet::new());
        }

        #[test]
        fn correct_address_wrong_key() {
            let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);

            let mut filter = BloomFilter::new();
            filter.set_keys(&[event_key!("0xdeadbeef")]);
            filter.set_address(&contract_address!("0x1234"));

            aggregate.add_bloom(&filter, BlockNumber::GENESIS);
            aggregate.add_bloom(&filter, BlockNumber::GENESIS + 1);
            let constraints = EventConstraints {
                from_block: None,
                to_block: None,
                contract_address: Some(contract_address!("0x1234")),
                keys: vec![vec![event_key!("0xfeebdaed"), event_key!("0x4321")]],
                page_size: 1024,
                offset: 0,
            };

            assert_eq!(aggregate.check(&constraints), BTreeSet::new());
        }

        #[test]
        fn wrong_and_correct_key() {
            let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);

            let mut filter = BloomFilter::new();
            filter.set_address(&contract_address!("0x1234"));
            filter.set_keys(&[event_key!("0xdeadbeef")]);

            aggregate.add_bloom(&filter, BlockNumber::GENESIS);
            aggregate.add_bloom(&filter, BlockNumber::GENESIS + 1);
            let constraints = EventConstraints {
                from_block: None,
                to_block: None,
                contract_address: None,
                keys: vec![
                    // Key present in both blocks as the first key.
                    vec![event_key!("0xdeadbeef")],
                    // Key that does not exist in any block.
                    vec![event_key!("0xbeefdead")],
                ],
                page_size: 1024,
                offset: 0,
            };

            assert_eq!(aggregate.check(&constraints), BTreeSet::new());
        }

        #[test]
        fn no_constraints() {
            let mut aggregate = AggregateBloom::new(BlockNumber::GENESIS);

            let mut filter = BloomFilter::new();
            filter.set_keys(&[event_key!("0xdeadbeef")]);
            filter.set_address(&contract_address!("0x1234"));

            aggregate.add_bloom(&filter, BlockNumber::GENESIS);
            aggregate.add_bloom(&filter, BlockNumber::GENESIS + 1);
            let constraints = EventConstraints {
                from_block: None,
                to_block: None,
                contract_address: None,
                keys: vec![],
                page_size: 1024,
                offset: 0,
            };

            assert_eq!(aggregate.check(&constraints), aggregate.all_blocks());
        }
    }

    #[test_log::test(test)]
    fn get_events_with_fully_specified_filter() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[1];
        let constraints = EventConstraints {
            from_block: Some(expected_event.block_number),
            to_block: Some(expected_event.block_number),
            contract_address: Some(expected_event.from_address),
            // we're using a key which is present in _all_ events as the 2nd key
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );
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
                &EventConstraints {
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
        let constraints = EventConstraints {
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
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_up_to_block() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const UNTIL_BLOCK_NUMBER: usize = 2;
        let constraints = EventConstraints {
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
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_up_to_block_with_paging() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let constraints = EventConstraints {
            from_block: None,
            to_block: Some(BlockNumber::new_or_panic(1)),
            contract_address: None,
            keys: vec![],
            page_size: test_utils::EVENTS_PER_BLOCK + 1,
            offset: 0,
        };

        let expected_events = &emitted_events[..test_utils::EVENTS_PER_BLOCK + 1];
        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        // test continuation token
        let constraints = EventConstraints {
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
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        pretty_assertions_sorted::assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_from_block_onwards() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const FROM_BLOCK_NUMBER: usize = 2;
        let constraints = EventConstraints {
            from_block: Some(BlockNumber::new_or_panic(FROM_BLOCK_NUMBER as u64)),
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let expected_events = &emitted_events[test_utils::EVENTS_PER_BLOCK * FROM_BLOCK_NUMBER..];
        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_from_contract() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[33];

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: Some(expected_event.from_address),
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_by_key() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let expected_event = &emitted_events[27];
        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![vec![expected_event.keys[0]], vec![expected_event.keys[1]]],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                continuation_token: None,
            }
        );

        // try event keys in the wrong order, should not match
        let constraints = EventConstraints {
            keys: vec![vec![expected_event.keys[1]], vec![expected_event.keys[0]]],
            ..constraints
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_with_no_filter() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events,
                continuation_token: None,
            }
        );
    }

    #[test]
    fn get_events_with_no_filter_and_paging() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 10,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 30,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[30..40].to_vec(),
                continuation_token: None
            }
        );
    }

    #[test]
    fn get_events_with_no_filter_and_nonexistent_page() {
        let (storage, _) = test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        const PAGE_SIZE: usize = 10;
        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: PAGE_SIZE,
            // _after_ the last one
            offset: test_utils::NUM_BLOCKS * test_utils::EVENTS_PER_BLOCK,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                continuation_token: None,
            }
        );
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

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        // increase offset
        let constraints: EventConstraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 2,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        // using the continuation token should be equivalent to the previous query
        let constraints: EventConstraints = EventConstraints {
            from_block: Some(BlockNumber::new_or_panic(0)),
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 2,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        // increase offset by two
        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 4,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[4..].to_vec(),
                continuation_token: None,
            }
        );

        // using the continuation token should be equivalent to the previous query
        let constraints = EventConstraints {
            from_block: Some(BlockNumber::new_or_panic(3)),
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events,
            page_size: 2,
            offset: 1,
        };

        let events = tx
            .events(
                &constraints,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[4..].to_vec(),
                continuation_token: None,
            }
        );
    }

    #[test]
    fn scan_limit() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 20,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                1.try_into().unwrap(),
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

        let constraints = EventConstraints {
            from_block: Some(BlockNumber::new_or_panic(1)),
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 20,
            offset: 0,
        };

        let events = tx
            .events(
                &constraints,
                1.try_into().unwrap(),
                *MAX_BLOOM_FILTERS_TO_LOAD,
            )
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

    #[test]
    fn crossing_event_filter_range_stores_and_updates_running() {
        let blocks: Vec<usize> = [
            // First event filter start.
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + 1,
            BlockNumber::GENESIS + 2,
            BlockNumber::GENESIS + 3,
            // End.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Second event filter start.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 1,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 2,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 3,
            // End.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Third event filter start.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN + 1,
        ]
        .iter()
        .map(|&n| n.get() as usize)
        .collect();

        let (storage, _) = test_utils::setup_custom_test_storage(&blocks, 2);
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let inserted_event_filter_count = tx
            .inner()
            .prepare("SELECT COUNT(*) FROM event_filters")
            .unwrap()
            .query_row([], |row| row.get::<_, u64>(0))
            .unwrap();
        assert_eq!(inserted_event_filter_count, 2);

        let running_event_filter = tx.running_event_filter.lock().unwrap();
        // Running event filter starts from next block range.
        assert_eq!(
            running_event_filter.filter.from_block,
            2 * AggregateBloom::BLOCK_RANGE_LEN
        );
    }

    #[test]
    fn event_filter_filter_load_limit() {
        let blocks: Vec<usize> = [
            // First event filter start.
            BlockNumber::GENESIS,
            BlockNumber::GENESIS + 1,
            BlockNumber::GENESIS + 2,
            BlockNumber::GENESIS + 3,
            // End.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Second event filter start.
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 1,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 2,
            BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN + 3,
            // End.
            BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN - 1,
            // Third event filter start.
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

        let constraints = EventConstraints {
            from_block: None,
            to_block: None,
            contract_address: None,
            // We're using a key which is present in _all_ events as the 2nd key...
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events(&constraints, *MAX_BLOCKS_TO_SCAN, 1.try_into().unwrap())
            .unwrap();

        let first_event_filter_range = BlockNumber::GENESIS.get()..AggregateBloom::BLOCK_RANGE_LEN;
        for event in events.events {
            // ...but only events from the first bloom filter range are returned.
            assert!(
                first_event_filter_range.contains(&event.block_number.get()),
                "Event block number: {} should have been in the range: {:?}",
                event.block_number.get(),
                first_event_filter_range
            );
        }
        let continue_from_block = events.continuation_token.unwrap().block_number;
        assert_eq!(continue_from_block, first_event_filter_range.end);

        let constraints_with_offset = EventConstraints {
            from_block: Some(events.continuation_token.unwrap().block_number),
            to_block: None,
            contract_address: None,
            // We're using a key which is present in _all_ events as the 2nd key...
            keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
            page_size: emitted_events.len(),
            offset: 0,
        };

        let events = tx
            .events(
                &constraints_with_offset,
                *MAX_BLOCKS_TO_SCAN,
                1.try_into().unwrap(),
            )
            .unwrap();
        assert!(events.continuation_token.is_none());

        let second_event_filter_range =
            AggregateBloom::BLOCK_RANGE_LEN..(2 * AggregateBloom::BLOCK_RANGE_LEN);
        let third_event_filter_range =
            2 * AggregateBloom::BLOCK_RANGE_LEN..(3 * AggregateBloom::BLOCK_RANGE_LEN);
        for event in events.events {
            // ...but only events from the second (loaded) and third (running) event filter
            // range are returned.
            assert!(
                (second_event_filter_range.start..third_event_filter_range.end)
                    .contains(&event.block_number.get())
            );
        }
    }
}
