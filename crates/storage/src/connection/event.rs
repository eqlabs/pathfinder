use crate::params::ToSql;
use crate::prelude::*;

use anyhow::Context;
use pathfinder_common::event::Event;
use pathfinder_common::{
    BlockHash, BlockNumber, ContractAddress, EventData, EventKey, TransactionHash,
};
use stark_hash::Felt;

pub const PAGE_SIZE_LIMIT: usize = 1_024;
pub const KEY_FILTER_LIMIT: usize = 256;

const KEY_FILTER_COST_LIMIT: usize = 1_000_000;

pub struct EventFilter<K: KeyFilter> {
    pub from_block: Option<BlockNumber>,
    pub to_block: Option<BlockNumber>,
    pub contract_address: Option<ContractAddress>,
    pub keys: K,
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

#[derive(Copy, Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventFilterError {
    #[error("requested page size is too big, supported maximum is {0}")]
    PageSizeTooBig(usize),
    #[error("Event query too broad. Reduce the block range or add more keys.")]
    TooManyMatches,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageOfEvents {
    pub events: Vec<EmittedEvent>,
    pub is_last_page: bool,
}

pub trait KeyFilter {
    fn count(&self, tx: &Transaction<'_>) -> anyhow::Result<Option<usize>>;
    fn apply(&self, strategy: QueryStrategy) -> Option<KeyFilterResult<'_>>;
}

#[derive(Debug, PartialEq)]
pub struct KeyFilterResult<'a> {
    pub base_query: &'static str,
    pub where_statement: &'static str,
    pub param: (&'static str, rusqlite::types::ToSqlOutput<'a>),
}

pub(super) fn insert_events(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    transaction_hash: TransactionHash,
    events: &[Event],
) -> anyhow::Result<()> {
    let mut stmt = tx.inner().prepare(
        r"INSERT INTO starknet_events ( block_number,  idx,  transaction_hash,  from_address,  keys,  data)
                               VALUES (:block_number, :idx, :transaction_hash, :from_address, :keys, :data)"
    )?;

    let mut keys = String::new();
    let mut buffer = Vec::new();

    for (idx, event) in events.iter().enumerate() {
        keys.clear();
        event_keys_to_base64_strings(&event.keys, &mut keys);

        buffer.clear();
        encode_event_data_to_bytes(&event.data, &mut buffer);

        stmt.execute(named_params![
            ":block_number": &block_number,
            ":idx": &idx,
            ":transaction_hash": &transaction_hash,
            ":from_address": &event.from_address,
            ":keys": &keys,
            ":data": &buffer,
        ])
        .context("Insert events into events table")?;
    }
    Ok(())
}

pub fn event_count(
    tx: &Transaction<'_>,
    from_block: Option<BlockNumber>,
    to_block: Option<BlockNumber>,
    contract_address: Option<ContractAddress>,
    keys: &dyn KeyFilter,
) -> anyhow::Result<usize> {
    let strategy = select_query_strategy(
        tx,
        from_block.as_ref(),
        to_block.as_ref(),
        contract_address.as_ref(),
        keys,
    )?;

    let (query, params) = event_query(
        "SELECT COUNT(1) FROM starknet_events",
        from_block.as_ref(),
        to_block.as_ref(),
        contract_address.as_ref(),
        keys,
        strategy,
    );

    let params = params
        .iter()
        .map(|(s, x)| (*s, x as &dyn rusqlite::ToSql))
        .collect::<Vec<_>>();

    let count: usize = tx
        .inner()
        .query_row(&query, params.as_slice(), |row| row.get(0))?;

    Ok(count)
}

pub(super) fn get_events<K: KeyFilter>(
    tx: &Transaction<'_>,
    filter: &EventFilter<K>,
) -> anyhow::Result<PageOfEvents> {
    if filter.page_size > PAGE_SIZE_LIMIT {
        return Err(EventFilterError::PageSizeTooBig(PAGE_SIZE_LIMIT).into());
    }

    if filter.page_size < 1 {
        anyhow::bail!("Invalid page size");
    }

    let strategy = select_query_strategy(
        tx,
        filter.from_block.as_ref(),
        filter.to_block.as_ref(),
        filter.contract_address.as_ref(),
        &filter.keys,
    )?;

    let base_query = r#"SELECT
              block_number,
              starknet_blocks.hash as block_hash,
              transaction_hash,
              starknet_transactions.idx as transaction_idx,
              from_address,
              data,
              starknet_events.keys as keys
           FROM starknet_events
           INNER JOIN starknet_transactions ON (starknet_transactions.hash = starknet_events.transaction_hash)
           INNER JOIN starknet_blocks ON (starknet_blocks.number = starknet_events.block_number)"#;

    let (mut base_query, mut params) = event_query(
        base_query,
        filter.from_block.as_ref(),
        filter.to_block.as_ref(),
        filter.contract_address.as_ref(),
        &filter.keys,
        strategy,
    );

    // We have to be able to decide if there are more events. We request one extra event
    // above the requested page size, so that we can decide.
    let limit = filter.page_size + 1;
    params.push((":limit", limit.to_sql()));
    params.push((":offset", filter.offset.to_sql()));

    base_query.to_mut().push_str(
        " ORDER BY block_number, transaction_idx, starknet_events.idx LIMIT :limit OFFSET :offset",
    );

    let mut statement = tx
        .inner()
        .prepare(&base_query)
        .context("Preparing SQL query")?;
    let params = params
        .iter()
        .map(|(s, x)| (*s, x as &dyn rusqlite::ToSql))
        .collect::<Vec<_>>();
    let mut rows = statement
        .query(params.as_slice())
        .context("Executing SQL query")?;

    let mut is_last_page = true;
    let mut emitted_events = Vec::new();
    while let Some(row) = rows.next().context("Fetching next event")? {
        if emitted_events.len() == filter.page_size {
            // We already have a full page, and are just fetching the extra event
            // This means that there are more pages.
            is_last_page = false;
        } else {
            let block_number = row.get_block_number("block_number")?;
            let block_hash = row.get_block_hash("block_hash")?;
            let transaction_hash = row.get_transaction_hash("transaction_hash")?;
            let from_address = row.get_contract_address("from_address")?;

            let data = row.get_ref_unwrap("data").as_blob().unwrap();
            let data: Vec<_> = data
                .chunks_exact(32)
                .map(|data| {
                    let data = Felt::from_be_slice(data).unwrap();
                    EventData(data)
                })
                .collect();

            let keys = row.get_ref_unwrap("keys").as_str().unwrap();

            // no need to allocate a vec for this in loop
            let mut temp = [0u8; 32];

            let keys: Vec<_> = keys
                .split(' ')
                .map(|key| {
                    let used =
                        base64::decode_config_slice(key, base64::STANDARD, &mut temp).unwrap();
                    let key = Felt::from_be_slice(&temp[..used]).unwrap();
                    EventKey(key)
                })
                .collect();

            let event = EmittedEvent {
                data,
                from_address,
                keys,
                block_hash,
                block_number,
                transaction_hash,
            };
            emitted_events.push(event);
        }
    }

    Ok(PageOfEvents {
        events: emitted_events,
        is_last_page,
    })
}

fn event_keys_to_base64_strings(keys: &[EventKey], out: &mut String) {
    // with padding it seems 44 bytes are needed for each
    let needed = (keys.len() * (" ".len() + 44)).saturating_sub(" ".len());

    if let Some(more) = needed.checked_sub(out.capacity() - out.len()) {
        // This is a wish which is not always fulfilled
        out.reserve(more);
    }

    keys.iter().enumerate().for_each(|(i, x)| {
        encode_event_key_to_base64(x, out);

        if i != keys.len() - 1 {
            out.push(' ');
        }
    });
}

fn encode_event_key_to_base64(key: &EventKey, buf: &mut String) {
    base64::encode_config_buf(key.0.as_be_bytes(), base64::STANDARD, buf);
}

fn encode_event_data_to_bytes(data: &[EventData], buffer: &mut Vec<u8>) {
    buffer.extend(data.iter().flat_map(|e| (*e.0.as_be_bytes()).into_iter()))
}

fn encode_event_key_and_index_to_base32(index: u8, key: &EventKey, output: &mut String) {
    let mut buf = [0u8; 33];
    buf[0] = index;
    buf[1..].copy_from_slice(key.0.as_be_bytes());
    data_encoding::BASE32_NOPAD.encode_append(&buf, output);
}

#[derive(Clone)]
/// Event key filter for v0.3 of the JSON-RPC API
///
/// Here the filter is an array of array of keys. Each position in the array contains
/// a list of matching values for that position of the key.
///
/// [["key1_value1", "key1_value2"], [], ["key3_value1"]] means:
/// ((key1 == "key1_value1" OR key1 == "key1_value2") AND (key3 == "key3_value1")).
pub struct V03KeyFilter {
    key_fts_expression: Option<String>,
}

impl V03KeyFilter {
    pub fn new(keys: Vec<Vec<EventKey>>) -> Self {
        let filter_count = keys.iter().flatten().count();

        let key_fts_expression = if filter_count == 0 {
            None
        } else {
            let mut key_fts_expression = String::with_capacity(100);
            keys.iter().enumerate().for_each(|(i, values)| {
                if !values.is_empty() {
                    if key_fts_expression.ends_with(')') {
                        key_fts_expression.push_str(" AND ");
                    }

                    key_fts_expression.push('(');
                    values.iter().enumerate().for_each(|(j, key)| {
                        key_fts_expression.push('"');
                        encode_event_key_and_index_to_base32(i as u8, key, &mut key_fts_expression);
                        key_fts_expression.push('"');

                        if j != values.len() - 1 {
                            key_fts_expression.push_str(" OR ")
                        }
                    });
                    key_fts_expression.push(')');
                }
            });

            Some(key_fts_expression)
        };

        Self { key_fts_expression }
    }
}

impl KeyFilter for V03KeyFilter {
    fn count(&self, tx: &Transaction<'_>) -> anyhow::Result<Option<usize>> {
        match &self.key_fts_expression {
            None => Ok(None),
            Some(key_fts_expression) => {
                let count: usize = tx.inner().query_row(
                    "SELECT COUNT(1) FROM starknet_events_keys_03 WHERE keys MATCH :events_match",
                    [&key_fts_expression],
                    |row| row.get(0),
                )?;
                Ok(Some(count))
            }
        }
    }

    fn apply(&self, strategy: QueryStrategy) -> Option<KeyFilterResult<'_>> {
        match self.key_fts_expression.as_ref() {
            None => None,
            Some(key_fts_expression) => {
                let base_query = match strategy {
                    QueryStrategy::BlockRangeFirst => " CROSS JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
                    QueryStrategy::KeysFirst => " INNER JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
                };

                Some(KeyFilterResult {
                    base_query,
                    where_statement: "starknet_events_keys_03.keys MATCH :events_match",
                    param: (":events_match", key_fts_expression.to_sql()),
                })
            }
        }
    }
}

fn event_query<'query, 'arg>(
    base: &'query str,
    from_block: Option<&'arg BlockNumber>,
    to_block: Option<&'arg BlockNumber>,
    contract_address: Option<&'arg ContractAddress>,
    keys: &'arg (dyn KeyFilter + 'arg),
    strategy: QueryStrategy,
) -> (
    std::borrow::Cow<'query, str>,
    Vec<(&'static str, rusqlite::types::ToSqlOutput<'arg>)>,
) {
    let mut base_query = std::borrow::Cow::Borrowed(base);

    let mut where_statement_parts: Vec<&'static str> = Vec::new();
    let mut params: Vec<(&str, rusqlite::types::ToSqlOutput<'arg>)> = Vec::new();

    // filter on block range
    match (from_block, to_block) {
        (Some(from_block), Some(to_block)) => {
            where_statement_parts.push("block_number BETWEEN :from_block AND :to_block");
            params.push((":from_block", from_block.to_sql()));
            params.push((":to_block", to_block.to_sql()));
        }
        (Some(from_block), None) => {
            where_statement_parts.push("block_number >= :from_block");
            params.push((":from_block", from_block.to_sql()));
        }
        (None, Some(to_block)) => {
            where_statement_parts.push("block_number <= :to_block");
            params.push((":to_block", to_block.to_sql()));
        }
        (None, None) => {}
    }

    // on contract address
    if let Some(contract_address) = contract_address {
        where_statement_parts.push("from_address = :contract_address");
        params.push((":contract_address", contract_address.to_sql()));
    }

    // Filter on keys: this is using an FTS5 full-text index (virtual table) on the keys.
    // The idea is that we convert keys to a space-separated list of Base64/Base32 encoded string
    // representation and then use the full-text index to find events matching the events.
    if let Some(result) = keys.apply(strategy) {
        base_query.to_mut().push_str(result.base_query);
        where_statement_parts.push(result.where_statement);
        params.push((result.param.0, result.param.1));
    }

    if !where_statement_parts.is_empty() {
        let needed = " WHERE ".len()
            + where_statement_parts.len() * " AND ".len()
            + where_statement_parts.iter().map(|x| x.len()).sum::<usize>();

        let q = base_query.to_mut();
        if let Some(more) = needed.checked_sub(q.capacity() - q.len()) {
            q.reserve(more);
        }

        let _capacity = q.capacity();

        q.push_str(" WHERE ");

        let total = where_statement_parts.len();
        where_statement_parts
            .into_iter()
            .enumerate()
            .for_each(|(i, part)| {
                q.push_str(part);

                if i != total - 1 {
                    q.push_str(" AND ");
                }
            });

        debug_assert_eq!(_capacity, q.capacity(), "pre-reservation was not enough");
    }

    (base_query, params)
}

pub enum QueryStrategy {
    BlockRangeFirst,
    KeysFirst,
}

fn select_query_strategy(
    tx: &Transaction<'_>,
    from_block: Option<&BlockNumber>,
    to_block: Option<&BlockNumber>,
    contract_address: Option<&ContractAddress>,
    keys: &dyn KeyFilter,
) -> anyhow::Result<QueryStrategy> {
    // evaluate key filter first as that is roughly constant time
    let events_by_key_filter = number_of_events_by_key_filter(tx, keys)?;
    if let Some(events_by_key_filter) = events_by_key_filter {
        // shortcut if the key filter is specific enough
        if events_by_key_filter < 100_000 {
            tracing::trace!(
                %events_by_key_filter,
                "Partial queries for number of events done"
            );
            return Ok(QueryStrategy::KeysFirst);
        }
    }

    let events_in_block_range =
        number_of_events_in_block_range(tx, from_block, to_block, contract_address)?;

    tracing::trace!(
        ?events_in_block_range,
        ?events_by_key_filter,
        "Partial queries for number of events done"
    );

    const KEY_FILTER_WEIGHT: usize = 50;
    let weighted_events_by_key_filter =
        events_by_key_filter.map(|n| n.saturating_mul(KEY_FILTER_WEIGHT));

    if events_in_block_range
        .or(weighted_events_by_key_filter)
        .is_some()
    {
        let cost = std::cmp::min(
            events_in_block_range.unwrap_or(usize::MAX),
            weighted_events_by_key_filter.unwrap_or(usize::MAX),
        );

        if cost > KEY_FILTER_COST_LIMIT {
            return Err(EventFilterError::TooManyMatches.into());
        }
    }

    let strategy = match (events_in_block_range, events_by_key_filter) {
        (None, None) => QueryStrategy::BlockRangeFirst,
        (None, Some(_)) => QueryStrategy::KeysFirst,
        (Some(_), None) => QueryStrategy::BlockRangeFirst,
        (Some(events_in_block_range), Some(_)) => {
            if events_in_block_range
                > weighted_events_by_key_filter
                    .expect("Unwrap is safe because events_by_key_filter is some")
            {
                QueryStrategy::KeysFirst
            } else {
                QueryStrategy::BlockRangeFirst
            }
        }
    };

    Ok(strategy)
}

fn number_of_events_in_block_range(
    tx: &Transaction<'_>,
    from_block: Option<&BlockNumber>,
    to_block: Option<&BlockNumber>,
    contract_address: Option<&ContractAddress>,
) -> anyhow::Result<Option<usize>> {
    let mut query = "SELECT COUNT(1) FROM starknet_events WHERE ".to_owned();
    let mut params: Vec<(&str, rusqlite::types::ToSqlOutput<'_>)> = Vec::new();

    match (from_block, to_block) {
        (Some(from_block), Some(to_block)) => {
            query.push_str("block_number BETWEEN :from_block AND :to_block ");
            params.push((":from_block", from_block.to_sql()));
            params.push((":to_block", to_block.to_sql()));
        }
        (Some(from_block), None) => {
            query.push_str("block_number >= :from_block ");
            params.push((":from_block", from_block.to_sql()));
        }
        (None, Some(to_block)) => {
            query.push_str("block_number <= :to_block ");
            params.push((":to_block", to_block.to_sql()));
        }
        (None, None) => {}
    };

    // on contract address
    if let Some(contract_address) = contract_address {
        if params.is_empty() {
            query.push_str("from_address = :contract_address");
        } else {
            query.push_str("AND from_address = :contract_address");
        }
        params.push((":contract_address", contract_address.to_sql()));
    }

    let params = params
        .iter()
        .map(|(s, x)| (*s, x as &dyn rusqlite::ToSql))
        .collect::<Vec<_>>();

    if params.is_empty() {
        return Ok(None);
    }

    let count: usize = tx
        .inner()
        .query_row(&query, params.as_slice(), |row| row.get(0))?;

    Ok(Some(count))
}

fn number_of_events_by_key_filter(
    tx: &Transaction<'_>,
    keys: &dyn KeyFilter,
) -> anyhow::Result<Option<usize>> {
    keys.count(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils;
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHeader, BlockTimestamp, EntryPoint, Fee};

    use starknet_gateway_types::reply::transaction as gateway_tx;

    #[test]
    fn event_data_serialization() {
        let data = [event_data!("0x1"), event_data!("0x2"), event_data!("0x3")];

        let mut buffer = Vec::new();
        encode_event_data_to_bytes(&data, &mut buffer);

        assert_eq!(
            &buffer,
            &[
                0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
            ]
        );
    }

    #[test]
    fn event_keys_to_base64_strings() {
        let event = Event {
            from_address: contract_address!(
                "06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
            ),
            data: vec![],
            keys: vec![
                event_key!("0x901823"),
                event_key!("0x901824"),
                event_key!("0x901825"),
            ],
        };

        let mut buf = String::new();
        super::event_keys_to_base64_strings(&event.keys, &mut buf);
        assert_eq!(buf.capacity(), buf.len());
        assert_eq!(
                    buf,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCM= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCQ= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCU="
                );
    }

    #[test]
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
            keys: V03KeyFilter::new(vec![vec![], vec![event_key!("0xdeadbeef")]]),
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
                keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![
                vec![expected_event.keys[0]],
                vec![expected_event.keys[1]],
            ]),
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
            keys: V03KeyFilter::new(vec![
                vec![expected_event.keys[1]],
                vec![expected_event.keys[0]],
            ]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
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
            keys: V03KeyFilter::new(vec![]),
            page_size: 0,
            offset: 0,
        };
        let result = get_events(&tx, &filter);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid page size");

        let filter = EventFilter {
            from_block: None,
            to_block: None,
            contract_address: None,
            keys: V03KeyFilter::new(vec![]),
            page_size: PAGE_SIZE_LIMIT + 1,
            offset: 0,
        };
        let result = get_events(&tx, &filter);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().downcast::<EventFilterError>().unwrap(),
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
        let keys_for_expected_events = V03KeyFilter::new(vec![
            expected_events.iter().map(|e| e.keys[0]).collect(),
            expected_events.iter().map(|e| e.keys[1]).collect(),
        ]);

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

    #[test]
    fn event_count_by_block() {
        let (storage, _) = test_utils::setup_test_storage();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let block = Some(BlockNumber::new_or_panic(2));

        let count = event_count(&tx, block, block, None, &V03KeyFilter::new(vec![])).unwrap();
        assert_eq!(count, test_utils::EVENTS_PER_BLOCK);
    }

    #[test]
    fn event_count_from_contract() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let addr = events[0].from_address;
        let expected = events
            .iter()
            .filter(|event| event.from_address == addr)
            .count();

        let count = event_count(
            &tx,
            Some(BlockNumber::GENESIS),
            Some(BlockNumber::MAX),
            Some(addr),
            &V03KeyFilter::new(vec![]),
        )
        .unwrap();
        assert_eq!(count, expected);
    }

    #[test]
    fn event_count_by_key() {
        let (storage, test_data) = test_utils::setup_test_storage();
        let emitted_events = test_data.events;
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let key = emitted_events[27].keys[0];
        let expected = emitted_events
            .iter()
            .filter(|event| event.keys.contains(&key))
            .count();

        let count = event_count(
            &tx,
            Some(BlockNumber::GENESIS),
            Some(BlockNumber::MAX),
            None,
            &V03KeyFilter::new(vec![vec![key]]),
        )
        .unwrap();
        assert_eq!(count, expected);
    }

    #[test]
    fn v03_key_filter() {
        check_v03_filter(vec![], None);
        check_v03_filter(vec![vec![], vec![]], None);
        check_v03_filter(
                    vec![
                        vec![],
                        vec![event_key!("01"), event_key!("02")],
                        vec![],
                        vec![event_key!("01"), event_key!("03")],
                        vec![],
                    ],
                    Some("(\"AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\" OR \"AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE\") AND (\"AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\" OR \"AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG\")"),
                );
    }

    fn check_v03_filter(filter: Vec<Vec<EventKey>>, expected_fts_expression: Option<&str>) {
        let filter = V03KeyFilter::new(filter);

        let result = filter.apply(QueryStrategy::KeysFirst);
        match expected_fts_expression {
            Some(expected_fts_expression) => assert_matches!(
                result,
                Some(result) => {assert_eq!(result, KeyFilterResult { base_query: " INNER JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
                 where_statement: "starknet_events_keys_03.keys MATCH :events_match", param: (":events_match", expected_fts_expression.to_sql()) })}
            ),
            None => assert_eq!(result, None),
        }

        let result = filter.apply(QueryStrategy::BlockRangeFirst);
        match expected_fts_expression {
            Some(expected_fts_expression) => assert_matches!(
                result,
                Some(result) => {assert_eq!(result, KeyFilterResult { base_query: " CROSS JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
                 where_statement: "starknet_events_keys_03.keys MATCH :events_match", param: (":events_match", expected_fts_expression.to_sql()) })}
            ),
            None => assert_eq!(result, None),
        }
    }
}
