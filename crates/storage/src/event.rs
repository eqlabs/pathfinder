use crate::prelude::*;

use anyhow::Context;
use pathfinder_common::event::Event;
use pathfinder_common::{
    BlockHash, BlockNumber, ContractAddress, EventData, EventKey, TransactionHash,
};
use stark_hash::Felt;

pub const PAGE_SIZE_LIMIT: usize = 1_024;
pub const KEY_FILTER_LIMIT: usize = 256;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageOfEvents {
    pub events: Vec<EmittedEvent>,
    pub is_last_page: bool,
}

pub trait KeyFilter {
    fn apply<'a>(&self, key_fts_expression: &'a mut String) -> Option<KeyFilterResult<'a>>;
}

#[derive(Debug, PartialEq)]
pub struct KeyFilterResult<'a> {
    pub base_query: &'static str,
    pub where_statement: &'static str,
    pub param: (&'static str, &'a str),
}

pub(crate) fn insert_events(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    transaction_hash: TransactionHash,
    events: &[Event],
) -> anyhow::Result<()> {
    let mut stmt = tx.prepare(
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

pub(crate) fn get_events<K: KeyFilter>(
    tx: &Transaction<'_>,
    filter: &EventFilter<K>,
) -> anyhow::Result<PageOfEvents> {
    if filter.page_size > PAGE_SIZE_LIMIT {
        return Err(EventFilterError::PageSizeTooBig(PAGE_SIZE_LIMIT).into());
    }

    if filter.page_size < 1 {
        anyhow::bail!("Invalid page size");
    }

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

    let mut key_fts_expression = String::new();

    let (mut base_query, mut params) = event_query(
        base_query,
        filter.from_block.as_ref(),
        filter.to_block.as_ref(),
        filter.contract_address.as_ref(),
        &filter.keys,
        &mut key_fts_expression,
    );

    // We have to be able to decide if there are more events. We request one extra event
    // above the requested page size, so that we can decide.
    let limit = filter.page_size + 1;
    params.push((":limit", &limit));
    params.push((":offset", &filter.offset));

    base_query.to_mut().push_str(
        " ORDER BY block_number, transaction_idx, starknet_events.idx LIMIT :limit OFFSET :offset",
    );

    let mut statement = tx.prepare(&base_query).context("Preparing SQL query")?;
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
            let block_number = row.get_unwrap("block_number");
            let block_hash = row.get_unwrap("block_hash");
            let transaction_hash = row.get_unwrap("transaction_hash");
            let from_address = row.get_unwrap("from_address");

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
        out.reserve(more);
    }

    let _capacity = out.capacity();

    keys.iter().enumerate().for_each(|(i, x)| {
        encode_event_key_to_base64(x, out);

        if i != keys.len() - 1 {
            out.push(' ');
        }
    });

    debug_assert_eq!(_capacity, out.capacity(), "pre-reservation was not enough");
}

fn encode_event_key_to_base64(key: &EventKey, buf: &mut String) {
    base64::encode_config_buf(key.0.as_be_bytes(), base64::STANDARD, buf);
}

fn encode_event_data_to_bytes(data: &[EventData], buffer: &mut Vec<u8>) {
    buffer.extend(data.iter().flat_map(|e| (*e.0.as_be_bytes()).into_iter()))
}

#[derive(Clone)]
/// Event key filter for the v0.1 and v0.2 JSON-RPC API
///
/// In these API versions events are matched against a list of keys. An event
/// matches the filter if _any_ key matches.
pub struct V02KeyFilter(pub Vec<EventKey>);

impl KeyFilter for V02KeyFilter {
    fn apply<'arg>(&self, key_fts_expression: &'arg mut String) -> Option<KeyFilterResult<'arg>> {
        let keys = &self.0;
        if !keys.is_empty() {
            let needed =
                (keys.len() * (" OR ".len() + "\"\"".len() + 44)).saturating_sub(" OR ".len());
            if let Some(more) = needed.checked_sub(key_fts_expression.capacity()) {
                key_fts_expression.reserve(more);
            }

            let _capacity = key_fts_expression.capacity();

            keys.iter().enumerate().for_each(|(i, key)| {
                key_fts_expression.push('"');
                encode_event_key_to_base64(key, key_fts_expression);
                key_fts_expression.push('"');

                if i != keys.len() - 1 {
                    key_fts_expression.push_str(" OR ");
                }
            });

            debug_assert_eq!(
                _capacity,
                key_fts_expression.capacity(),
                "pre-reservation was not enough"
            );

            Some(KeyFilterResult {
                base_query: " CROSS JOIN starknet_events_keys ON starknet_events.rowid = starknet_events_keys.rowid",
                where_statement: "starknet_events_keys.keys MATCH :events_match",
                param: (":events_match", key_fts_expression),
            })
        } else {
            None
        }
    }
}

pub fn event_count(
    tx: &Transaction<'_>,
    from_block: Option<BlockNumber>,
    to_block: Option<BlockNumber>,
    contract_address: Option<ContractAddress>,
    keys: &dyn KeyFilter,
) -> anyhow::Result<usize> {
    let mut key_fts_expression = String::new();
    let (query, params) = event_query(
        "SELECT COUNT(1) FROM starknet_events",
        from_block.as_ref(),
        to_block.as_ref(),
        contract_address.as_ref(),
        keys,
        &mut key_fts_expression,
    );

    let count: usize = tx.query_row(&query, params.as_slice(), |row| row.get(0))?;

    Ok(count)
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
pub struct V03KeyFilter(pub Vec<Vec<EventKey>>);

impl KeyFilter for V03KeyFilter {
    fn apply<'a>(&self, key_fts_expression: &'a mut String) -> Option<KeyFilterResult<'a>> {
        let filter_count = self.0.iter().flatten().count();

        if filter_count > 0 {
            self.0.iter().enumerate().for_each(|(i, values)| {
                if !values.is_empty() {
                    if key_fts_expression.ends_with(')') {
                        key_fts_expression.push_str(" AND ");
                    }

                    key_fts_expression.push('(');
                    values.iter().enumerate().for_each(|(j, key)| {
                        key_fts_expression.push('"');
                        encode_event_key_and_index_to_base32(i as u8, key, key_fts_expression);
                        key_fts_expression.push('"');

                        if j != values.len() - 1 {
                            key_fts_expression.push_str(" OR ")
                        }
                    });
                    key_fts_expression.push(')');
                }
            });
            Some(KeyFilterResult {
                base_query: " CROSS JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
                where_statement: "starknet_events_keys_03.keys MATCH :events_match",
                param: (":events_match", key_fts_expression),
            })
        } else {
            None
        }
    }
}

fn event_query<'query, 'arg>(
    base: &'query str,
    from_block: Option<&'arg BlockNumber>,
    to_block: Option<&'arg BlockNumber>,
    contract_address: Option<&'arg ContractAddress>,
    keys: &dyn KeyFilter,
    key_fts_expression: &'arg mut String,
) -> (
    std::borrow::Cow<'query, str>,
    Vec<(&'static str, &'arg dyn rusqlite::ToSql)>,
) {
    let mut base_query = std::borrow::Cow::Borrowed(base);

    let mut where_statement_parts: Vec<&'static str> = Vec::new();
    let mut params: Vec<(&str, &dyn rusqlite::ToSql)> = Vec::new();

    // filter on block range
    match (from_block, to_block) {
        (Some(from_block), Some(to_block)) => {
            where_statement_parts.push("block_number BETWEEN :from_block AND :to_block");
            params.push((":from_block", from_block));
            params.push((":to_block", to_block));
        }
        (Some(from_block), None) => {
            where_statement_parts.push("block_number >= :from_block");
            params.push((":from_block", from_block));
        }
        (None, Some(to_block)) => {
            where_statement_parts.push("block_number <= :to_block");
            params.push((":to_block", to_block));
        }
        (None, None) => {}
    }

    // on contract address
    if let Some(contract_address) = contract_address {
        where_statement_parts.push("from_address = :contract_address");
        params.push((":contract_address", contract_address))
    }

    // Filter on keys: this is using an FTS5 full-text index (virtual table) on the keys.
    // The idea is that we convert keys to a space-separated list of Bas64 encoded string
    // representation and then use the full-text index to find events matching the events.
    if let Some(result) = keys.apply(key_fts_expression) {
        base_query.to_mut().push_str(result.base_query);
        where_statement_parts.push(result.where_statement);
        params.push((result.param.0, key_fts_expression));
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
