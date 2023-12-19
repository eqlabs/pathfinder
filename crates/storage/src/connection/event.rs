use crate::bloom::BloomFilter;
use crate::prelude::*;

use pathfinder_common::event::Event;
use pathfinder_common::{
    BlockHash, BlockNumber, ContractAddress, EventData, EventKey, TransactionHash,
};

pub const PAGE_SIZE_LIMIT: usize = 1_024;
pub const KEY_FILTER_LIMIT: usize = 16;

#[derive(Debug)]
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
    #[error("requested page size is too big, supported maximum is {0}")]
    PageSizeTooBig(usize),
    #[error("requested page size is too small, supported minimum is 1")]
    PageSizeTooSmall,
    #[error("Event query too broad. Reduce the block range or add more keys.")]
    TooManyMatches,
}

impl From<rusqlite::Error> for EventFilterError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageOfEvents {
    pub events: Vec<EmittedEvent>,
    pub is_last_page: bool,
}

#[derive(Debug, PartialEq)]
pub struct KeyFilterResult<'a> {
    pub base_query: &'static str,
    pub where_statement: &'static str,
    pub param: (&'static str, rusqlite::types::ToSqlOutput<'a>),
}

pub(super) fn insert_block_events<'a>(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    events: impl Iterator<Item = &'a Event>,
) -> anyhow::Result<()> {
    let mut stmt = tx
        .inner()
        .prepare("INSERT INTO starknet_events_filters (block_number, bloom) VALUES (?, ?)")?;

    let mut bloom = BloomFilter::new();
    for event in events {
        for (i, key) in event.keys.iter().take(KEY_FILTER_LIMIT).enumerate() {
            let mut key = key.0;
            key.as_mut_be_bytes()[0] |= (i as u8) << 4;
            bloom.set(&key);
        }

        bloom.set(&event.from_address.0);
    }

    stmt.execute(params![&block_number, &bloom.as_compressed_bytes()])?;

    Ok(())
}

#[tracing::instrument(skip(tx))]
pub(super) fn get_events(
    tx: &Transaction<'_>,
    filter: &EventFilter,
) -> Result<PageOfEvents, EventFilterError> {
    if filter.page_size > PAGE_SIZE_LIMIT {
        return Err(EventFilterError::PageSizeTooBig(PAGE_SIZE_LIMIT));
    }

    if filter.page_size < 1 {
        return Err(EventFilterError::PageSizeTooSmall);
    }

    let from_block = filter.from_block.unwrap_or(BlockNumber::GENESIS).get();
    let to_block = filter.to_block.unwrap_or(BlockNumber::MAX).get();
    let mut offset = filter.offset;
    let key_filter_is_empty = filter.keys.iter().flatten().count() == 0;

    let mut bloom_stmt = tx
        .inner()
        .prepare_cached("SELECT bloom FROM starknet_events_filters WHERE block_number = ?")?;

    let mut emitted_events = Vec::new();

    for block_number in from_block..=to_block {
        if emitted_events.len() > filter.page_size {
            break;
        }
        let events_required = filter.page_size + 1 - emitted_events.len();

        tracing::trace!(%block_number, %events_required, "Processing block");

        if !key_filter_is_empty || filter.contract_address.is_some() {
            let bloom = bloom_stmt
                .query_row(params![&block_number], |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    Ok(BloomFilter::from_compressed_bytes(&bytes))
                })
                .optional()?;
            let Some(bloom) = bloom else {
                break;
            };

            if !keys_in_bloom(&bloom, &filter.keys) {
                continue;
            }
            if let Some(contract_address) = filter.contract_address {
                if !bloom.check(&contract_address.0) {
                    continue;
                }
            }

            tracing::trace!("Bloom filter matched");
        }

        let block_header = tx.block_header(crate::BlockId::Number(BlockNumber::new_or_panic(
            block_number,
        )))?;
        let Some(block_header) = block_header else {
            break;
        };

        let transaction_data = tx.transaction_data_for_block(crate::BlockId::Number(
            BlockNumber::new_or_panic(block_number),
        ))?;
        let Some(transaction_data) = transaction_data else {
            break;
        };

        let keys: Vec<std::collections::HashSet<_>> = filter
            .keys
            .iter()
            .map(|keys| keys.iter().collect())
            .collect();

        let events = transaction_data
            .into_iter()
            .flat_map(|(_, receipt)| {
                receipt
                    .events
                    .into_iter()
                    .zip(std::iter::repeat(receipt.transaction_hash))
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
    }

    let is_last_page = emitted_events.len() <= filter.page_size;
    emitted_events.truncate(filter.page_size);

    Ok(PageOfEvents {
        events: emitted_events,
        is_last_page,
    })
}

fn keys_in_bloom(bloom: &BloomFilter, keys: &[Vec<EventKey>]) -> bool {
    keys.iter().enumerate().all(|(idx, keys)| {
        if keys.is_empty() {
            return true;
        };

        keys.iter().any(|key| {
            let mut key = key.0;
            key.as_mut_be_bytes()[0] |= (idx as u8) << 4;
            tracing::trace!(%idx, %key, "Checking key in filter");
            bloom.check(&key)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils;
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHeader, BlockTimestamp, EntryPoint, Fee};

    use pathfinder_crypto::Felt;
    use starknet_gateway_types::reply::transaction as gateway_tx;

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

        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                is_last_page: true,
            }
        );
    }

    #[test]
    fn events_are_ordered() {
        // This is a regression test where events were incorrectly ordered by transaction hash
        // instead of transaction index.
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
            .with_sequencer_address(sequencer_address!("0x1234"))
            .with_timestamp(BlockTimestamp::new_or_panic(0))
            .with_state_commitment(state_commitment!("0x1234"))
            .finalize_with_hash(block_hash!("0x1234"));

        // Note: hashes are reverse ordered to trigger the sorting bug.
        let transactions = vec![
            gateway_tx::Transaction::Invoke(gateway_tx::InvokeTransaction::V0(
                gateway_tx::InvokeTransactionV0 {
                    calldata: vec![],
                    // Only required because event insert rejects if this is None
                    sender_address: ContractAddress::new_or_panic(Felt::ZERO),
                    entry_point_type: Some(gateway_tx::EntryPointType::External),
                    entry_point_selector: EntryPoint(Felt::ZERO),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                    transaction_hash: transaction_hash!("0xF"),
                },
            )),
            gateway_tx::Transaction::Invoke(gateway_tx::InvokeTransaction::V0(
                gateway_tx::InvokeTransactionV0 {
                    calldata: vec![],
                    // Only required because event insert rejects if this is None
                    sender_address: ContractAddress::new_or_panic(Felt::ZERO),
                    entry_point_type: Some(gateway_tx::EntryPointType::External),
                    entry_point_selector: EntryPoint(Felt::ZERO),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                    transaction_hash: transaction_hash!("0x1"),
                },
            )),
        ];

        let receipts = vec![
            gateway_tx::Receipt {
                actual_fee: None,
                events: expected_events[..3].to_vec(),
                execution_resources: Some(gateway_tx::ExecutionResources {
                    builtin_instance_counter: Default::default(),
                    n_steps: 0,
                    n_memory_holes: 0,
                }),
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: Vec::new(),
                transaction_hash: transactions[0].hash(),
                transaction_index: pathfinder_common::TransactionIndex::new_or_panic(0),
                execution_status: Default::default(),
                revert_error: Default::default(),
            },
            gateway_tx::Receipt {
                actual_fee: None,
                events: expected_events[3..].to_vec(),
                execution_resources: Some(gateway_tx::ExecutionResources {
                    builtin_instance_counter: Default::default(),
                    n_steps: 0,
                    n_memory_holes: 0,
                }),
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: Vec::new(),
                transaction_hash: transactions[1].hash(),
                transaction_index: pathfinder_common::TransactionIndex::new_or_panic(1),
                execution_status: Default::default(),
                revert_error: Default::default(),
            },
        ];

        let mut connection = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = connection.transaction().unwrap();

        tx.insert_block_header(&header).unwrap();
        tx.insert_transaction_data(
            header.hash,
            header.number,
            &vec![
                (transactions[0].clone(), receipts[0].clone()),
                (transactions[1].clone(), receipts[1].clone()),
            ],
        )
        .unwrap();

        let addresses = get_events(
            &tx,
            &EventFilter {
                from_block: None,
                to_block: None,
                contract_address: None,
                keys: vec![],
                page_size: 1024,
                offset: 0,
            },
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
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                is_last_page: true,
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
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                is_last_page: true,
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
        let filter = EventFilter {
            from_block: Some(BlockNumber::new_or_panic(FROM_BLOCK_NUMBER as u64)),
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let expected_events = &emitted_events[test_utils::EVENTS_PER_BLOCK * FROM_BLOCK_NUMBER..];
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events.to_vec(),
                is_last_page: true,
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

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: Some(expected_event.from_address),
            keys: vec![],
            page_size: test_utils::NUM_EVENTS,
            offset: 0,
        };

        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                is_last_page: true,
            }
        );
    }

    #[test]
    fn get_events_by_key_v03() {
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

        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![expected_event.clone()],
                is_last_page: true,
            }
        );

        // try event keys in the wrong order, should not match
        let filter = EventFilter {
            keys: vec![vec![expected_event.keys[1]], vec![expected_event.keys[0]]],
            ..filter
        };
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                is_last_page: true,
            }
        );
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

        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events,
                is_last_page: true,
            }
        );
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
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[..10].to_vec(),
                is_last_page: false,
            }
        );

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 10,
        };
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[10..20].to_vec(),
                is_last_page: false,
            }
        );

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 10,
            offset: 30,
        };
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: emitted_events[30..40].to_vec(),
                is_last_page: true,
            }
        );
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
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: vec![],
                is_last_page: true,
            }
        );
    }

    #[test]
    fn get_events_with_invalid_page_size() {
        let (storage, _) = test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: 0,
            offset: 0,
        };
        let result = get_events(&tx, &filter);
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), EventFilterError::PageSizeTooSmall);

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: vec![],
            page_size: PAGE_SIZE_LIMIT + 1,
            offset: 0,
        };
        let result = get_events(&tx, &filter);
        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            EventFilterError::PageSizeTooBig(PAGE_SIZE_LIMIT)
        );
    }

    #[test]
    fn get_events_by_key_v03_with_paging() {
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
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[..2].to_vec(),
                is_last_page: false,
            }
        );

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events.clone(),
            page_size: 2,
            offset: 2,
        };
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[2..4].to_vec(),
                is_last_page: false,
            }
        );

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: keys_for_expected_events,
            page_size: 2,
            offset: 4,
        };
        let events = get_events(&tx, &filter).unwrap();
        assert_eq!(
            events,
            PageOfEvents {
                events: expected_events[4..].to_vec(),
                is_last_page: true,
            }
        );
    }
}
