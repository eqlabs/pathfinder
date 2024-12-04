use std::str::FromStr;

use anyhow::Context;
use pathfinder_common::{
    BlockHash,
    BlockId,
    BlockNumber,
    ContractAddress,
    EventData,
    EventKey,
    TransactionHash,
};
use pathfinder_storage::{EventFilterError, EVENT_KEY_FILTER_LIMIT};
use starknet_gateway_types::reply::PendingBlock;
use tokio::task::JoinHandle;

use crate::context::RpcContext;
use crate::dto::serialize::{self, SerializeForVersion, Serializer};
use crate::dto::{self};
use crate::pending::PendingData;

pub const EVENT_PAGE_SIZE_LIMIT: usize = 1024;

#[derive(Debug)]
pub enum GetEventsError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    PageSizeTooBig,
    InvalidContinuationToken,
    TooManyKeysInFilter { limit: usize, requested: usize },
}

impl From<anyhow::Error> for GetEventsError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<GetEventsError> for crate::error::ApplicationError {
    fn from(e: GetEventsError) -> Self {
        match e {
            GetEventsError::Internal(internal) => Self::Internal(internal),
            GetEventsError::Custom(internal) => Self::Custom(internal),
            GetEventsError::BlockNotFound => Self::BlockNotFound,
            GetEventsError::PageSizeTooBig => Self::PageSizeTooBig,
            GetEventsError::InvalidContinuationToken => Self::InvalidContinuationToken,
            GetEventsError::TooManyKeysInFilter { limit, requested } => {
                Self::TooManyKeysInFilter { limit, requested }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetEventsInput {
    filter: EventFilter,
}

impl crate::dto::DeserializeForVersion for GetEventsInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                filter: value.deserialize("filter")?,
            })
        })
    }
}

/// Contains event filter parameters passed to `starknet_getEvents`.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct EventFilter {
    pub from_block: Option<BlockId>,
    pub to_block: Option<BlockId>,
    pub address: Option<ContractAddress>,
    pub keys: Vec<Vec<EventKey>>,
    pub chunk_size: usize,
    /// Offset, measured in events, which points to the requested chunk
    pub continuation_token: Option<String>,
}

impl crate::dto::DeserializeForVersion for EventFilter {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                from_block: value.deserialize_optional("from_block")?,
                to_block: value.deserialize_optional("to_block")?,
                address: value.deserialize_optional("address")?.map(ContractAddress),
                keys: value
                    .deserialize_optional_array("keys", |value| {
                        value.deserialize_array(|value| value.deserialize().map(EventKey))
                    })?
                    .unwrap_or_default(),
                chunk_size: value.deserialize_serde("chunk_size")?,
                continuation_token: value.deserialize_optional_serde("continuation_token")?,
            })
        })
    }
}

/// Returns events matching the specified filter
pub async fn get_events(
    context: RpcContext,
    input: GetEventsInput,
) -> Result<GetEventsResult, GetEventsError> {
    // The [Block::Pending] in ranges makes things quite complicated. This
    // implementation splits the ranges into the following buckets:
    //
    // 1. pending     :     pending -> query pending only
    // 2. pending     : non-pending -> return empty result
    // 3. non-pending : non-pending -> query db only
    // 4. non-pending :     pending -> query db and potentially append pending
    //    events
    //
    // The database query for 3 and 4 is combined into one step.
    //
    // 4 requires some additional logic to handle some edge cases:
    //  a) if from_block_number > pending_block_number -> return empty result
    //  b) Query database
    //  c) if full page -> return page
    //      check if there are matching events in the pending block
    //      and return a continuation token for the pending block
    //  d) else if empty / partially full -> append events from start of pending
    //      if there are more pending events return a continuation token
    //      with the appropriate offset within the pending block

    use BlockId::*;

    let request = input.filter;

    let continuation_token = match &request.continuation_token {
        Some(s) => Some(
            s.parse::<ContinuationToken>()
                .map_err(|_| GetEventsError::InvalidContinuationToken)?,
        ),
        None => None,
    };

    if request.keys.len() > EVENT_KEY_FILTER_LIMIT {
        return Err(GetEventsError::TooManyKeysInFilter {
            limit: EVENT_KEY_FILTER_LIMIT,
            requested: request.keys.len(),
        });
    }
    if request.chunk_size > EVENT_PAGE_SIZE_LIMIT {
        return Err(GetEventsError::PageSizeTooBig);
    }

    let storage = context.storage.clone();

    // truncate empty key lists from the end of the key filter
    let mut keys = request.keys.clone();
    if let Some(last_non_empty) = keys.iter().rposition(|keys| !keys.is_empty()) {
        keys.truncate(last_non_empty + 1);
    }

    // blocking task to perform database event query
    let span = tracing::Span::current();
    let db_events: JoinHandle<Result<_, GetEventsError>> = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        // Handle the trivial (1), (2) and (4a) cases.
        match (&request.from_block, &request.to_block) {
            (Some(Pending), id) if !matches!(id, Some(Pending) | None) => {
                return Ok(GetEventsResult {
                    events: Vec::new(),
                    continuation_token: None,
                });
            }
            (Some(Pending), Some(Pending) | None) => {
                let pending = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?;
                return get_pending_events(&request, &pending, continuation_token);
            }
            (Some(BlockId::Number(from_block)), Some(BlockId::Pending)) => {
                let pending = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?;

                // `from_block` is larger than or equal to pending block's number
                if from_block >= &pending.number {
                    return Ok(GetEventsResult {
                        events: Vec::new(),
                        continuation_token: None,
                    });
                }
            }
            _ => {}
        }

        let from_block = map_from_block_to_number(&transaction, request.from_block)?;
        let to_block = map_to_block_to_number(&transaction, request.to_block)?;

        // Handle cases (3) and (4) where `from_block` is non-pending.

        let (from_block, requested_offset) = match continuation_token {
            Some(token) => token.start_block_and_offset(from_block)?,
            None => (from_block, 0),
        };

        let filter = pathfinder_storage::EventFilter {
            from_block,
            to_block,
            contract_address: request.address,
            keys: keys.clone(),
            page_size: request.chunk_size,
            offset: requested_offset,
        };

        // TODO:
        // Instrumentation and `AggregateBloom` version of fetching events
        // for the given `EventFilter` are under a feature flag for now and
        // we do not execute them during testing because they would only
        // slow the tests down and would not have any impact on their outcome.
        // Follow-up PR will use the `AggregateBloom` logic to create the output,
        // then the conditions will be removed.

        #[cfg(all(feature = "aggregate_bloom", not(test)))]
        let start = std::time::Instant::now();

        let page = transaction
            .events(
                &filter,
                context.config.get_events_max_blocks_to_scan,
                context.config.get_events_max_uncached_bloom_filters_to_load,
            )
            .map_err(|e| match e {
                EventFilterError::Internal(e) => GetEventsError::Internal(e),
                EventFilterError::PageSizeTooSmall => GetEventsError::Custom(e.into()),
            })?;

        #[cfg(all(feature = "aggregate_bloom", not(test)))]
        {
            let elapsed = start.elapsed();

            tracing::info!(
                "Getting events (individual Bloom filters) took {:?}",
                elapsed
            );

            let start = std::time::Instant::now();
            let page_from_aggregate = transaction
                .events_from_aggregate(
                    &filter,
                    context.config.get_events_max_blocks_to_scan,
                    context.config.get_events_max_bloom_filters_to_load,
                )
                .map_err(|e| match e {
                    EventFilterError::Internal(e) => GetEventsError::Internal(e),
                    EventFilterError::PageSizeTooSmall => GetEventsError::Custom(e.into()),
                })?;
            let elapsed = start.elapsed();

            tracing::info!(
                "Getting events (aggregate Bloom filters) took {:?}",
                elapsed
            );

            if page != page_from_aggregate {
                tracing::error!(
                    "Page of events from individual and aggregate bloom filters does not match!"
                );
                tracing::error!("Individual: {:?}", page);
                tracing::error!("Aggregate: {:?}", page_from_aggregate);
            } else {
                tracing::info!("Page of events from individual and aggregate bloom filters match!");
            }
        }

        let mut events = GetEventsResult {
            events: page.events.into_iter().map(|e| e.into()).collect(),
            continuation_token: page.continuation_token.map(|token| {
                ContinuationToken {
                    block_number: token.block_number,
                    offset: token.offset,
                }
                .to_string()
            }),
        };

        // Append pending data if required.
        if events.continuation_token.is_none() && matches!(request.to_block, Some(Pending)) {
            let pending = context
                .pending_data
                .get(&transaction)
                .context("Querying pending data")?;

            if events.events.len() < request.chunk_size {
                let amount = request.chunk_size - events.events.len();

                let current_offset = match continuation_token {
                    Some(continuation_token) => {
                        continuation_token.offset_in_block(pending.number)?
                    }
                    None => 0,
                };

                let keys: Vec<std::collections::HashSet<_>> = request
                    .keys
                    .into_iter()
                    .map(|keys| keys.into_iter().collect())
                    .collect();

                let is_last_page = append_pending_events(
                    &pending.block,
                    &mut events.events,
                    current_offset,
                    amount,
                    request.address,
                    keys,
                );

                events.continuation_token = if is_last_page {
                    None
                } else {
                    let continuation_token = ContinuationToken {
                        block_number: pending.number,
                        offset: current_offset + amount,
                    };
                    Some(continuation_token.to_string())
                };
            } else {
                // We have a full page from the database, but there might be more pending
                // events. Return a continuation token for the pending block.
                events.continuation_token = Some(
                    ContinuationToken {
                        block_number: pending.number,
                        offset: 0,
                    }
                    .to_string(),
                );
            }
        }

        Ok(events)
    });

    db_events
        .await
        .context("Database read panic or shutting down")?
}

// Handle the case when we're querying events exclusively from the pending
// block.
fn get_pending_events(
    request: &EventFilter,
    pending: &PendingData,
    continuation_token: Option<ContinuationToken>,
) -> Result<GetEventsResult, GetEventsError> {
    let current_offset = match continuation_token {
        Some(continuation_token) => continuation_token.offset_in_block(pending.number)?,
        None => 0,
    };

    let keys: Vec<std::collections::HashSet<_>> = request
        .keys
        .iter()
        .map(|keys| keys.iter().copied().collect())
        .collect();

    let mut events = Vec::new();

    let is_last_page = append_pending_events(
        &pending.block,
        &mut events,
        current_offset,
        request.chunk_size,
        request.address,
        keys,
    );

    let continuation_token = if is_last_page {
        None
    } else {
        Some(
            ContinuationToken {
                block_number: pending.number,
                offset: current_offset + request.chunk_size,
            }
            .to_string(),
        )
    };

    Ok(GetEventsResult {
        events,
        continuation_token,
    })
}

// Maps `to_block` BlockId to a block number which can be used by the events
// query.
//
// This block id specifies the upper end of the range, so pending/latest/None
// means there's no upper limit.
fn map_to_block_to_number(
    tx: &pathfinder_storage::Transaction<'_>,
    block: Option<BlockId>,
) -> Result<Option<BlockNumber>, GetEventsError> {
    use BlockId::*;

    match block {
        Some(Hash(hash)) => {
            let number = tx
                .block_id(hash.into())
                .context("Querying block number")?
                .ok_or(GetEventsError::BlockNotFound)?
                .0;

            Ok(Some(number))
        }
        Some(Number(number)) => Ok(Some(number)),
        Some(Pending) | Some(Latest) | None => Ok(None),
    }
}

// Maps `from_block` BlockId to a block number which can be used by the events
// query.
//
// This block id specifies the lower end of the range, so pending/latest means
// a lower limit here.
fn map_from_block_to_number(
    tx: &pathfinder_storage::Transaction<'_>,
    block: Option<BlockId>,
) -> Result<Option<BlockNumber>, GetEventsError> {
    use BlockId::*;

    match block {
        Some(Hash(hash)) => {
            let number = tx
                .block_id(hash.into())
                .context("Querying block number")?
                .ok_or(GetEventsError::BlockNotFound)?
                .0;

            Ok(Some(number))
        }
        Some(Number(number)) => Ok(Some(number)),
        Some(Pending) | Some(Latest) => {
            let number = tx
                .block_id(pathfinder_storage::BlockId::Latest)
                .context("Querying latest block number")?
                .ok_or(GetEventsError::BlockNotFound)?
                .0;
            Ok(Some(number))
        }
        None => Ok(None),
    }
}

/// Append's pending events to `dst` based on the filter requirements and
/// returns true if this was the last pending data i.e. `is_last_page`.
fn append_pending_events(
    pending_block: &PendingBlock,
    dst: &mut Vec<EmittedEvent>,
    skip: usize,
    amount: usize,
    address: Option<ContractAddress>,
    keys: Vec<std::collections::HashSet<EventKey>>,
) -> bool {
    let original_len = dst.len();

    let key_filter_is_empty = keys.iter().flatten().count() == 0;

    let pending_events = pending_block
        .transaction_receipts
        .iter()
        .flat_map(|(receipt, events)| {
            events
                .iter()
                .zip(std::iter::repeat(receipt.transaction_hash))
        })
        .filter(|(event, _)| match address {
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
        .skip(skip)
        // We need to take an extra event to determine is_last_page.
        .take(amount + 1)
        .map(|(event, tx_hash)| EmittedEvent {
            data: event.data.clone(),
            keys: event.keys.clone(),
            from_address: event.from_address,
            block_hash: None,
            block_number: None,
            transaction_hash: tx_hash,
        });

    dst.extend(pending_events);
    let is_last_page = dst.len() <= (original_len + amount);
    if !is_last_page {
        dst.pop();
    }

    is_last_page
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ContinuationToken {
    block_number: BlockNumber,
    offset: usize,
}

impl FromStr for ContinuationToken {
    type Err = ParseContinuationTokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((block_number, offset)) = s.split_once('-') {
            let block_number = block_number
                .parse::<u64>()
                .map_err(|_| ParseContinuationTokenError)?;
            let offset = offset.parse().map_err(|_| ParseContinuationTokenError)?;

            let block_number = BlockNumber::new(block_number).ok_or(ParseContinuationTokenError)?;

            Ok(ContinuationToken {
                block_number,
                offset,
            })
        } else {
            Err(ParseContinuationTokenError)
        }
    }
}

impl std::fmt::Display for ContinuationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.block_number.get(), self.offset)
    }
}

impl ContinuationToken {
    fn offset_in_block(&self, block_number: BlockNumber) -> Result<usize, GetEventsError> {
        use std::cmp::Ordering;
        match Ord::cmp(&self.block_number, &block_number) {
            Ordering::Equal => Ok(self.offset),
            Ordering::Less => Ok(0),
            Ordering::Greater => Err(GetEventsError::InvalidContinuationToken),
        }
    }

    fn start_block_and_offset(
        &self,
        from_block: Option<BlockNumber>,
    ) -> Result<(Option<BlockNumber>, usize), GetEventsError> {
        match from_block {
            Some(from_block) => {
                if from_block > self.block_number {
                    Err(GetEventsError::InvalidContinuationToken)
                } else {
                    Ok((Some(self.block_number), self.offset))
                }
            }
            None => {
                // from block was unspecified in filter, just use the value from the token
                Ok((Some(self.block_number), self.offset))
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ParseContinuationTokenError;

/// Describes an emitted event returned by starknet_getEvents
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmittedEvent {
    pub data: Vec<EventData>,
    pub keys: Vec<EventKey>,
    pub from_address: ContractAddress,
    /// [`None`] for pending events.
    pub block_hash: Option<BlockHash>,
    /// [`None`] for pending events.
    pub block_number: Option<BlockNumber>,
    pub transaction_hash: TransactionHash,
}

impl From<pathfinder_storage::EmittedEvent> for EmittedEvent {
    fn from(event: pathfinder_storage::EmittedEvent) -> Self {
        Self {
            data: event.data,
            keys: event.keys,
            from_address: event.from_address,
            block_hash: Some(event.block_hash),
            block_number: Some(event.block_number),
            transaction_hash: event.transaction_hash,
        }
    }
}

// Result type for starknet_getEvents
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetEventsResult {
    pub events: Vec<EmittedEvent>,
    /// Offset, measured in events, which points to the chunk that follows
    /// currently requested chunk (`events`)
    pub continuation_token: Option<String>,
}

impl SerializeForVersion for EmittedEvent {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter("data", self.data.len(), &mut self.data.iter().map(|d| d.0))?;
        serializer.serialize_iter("keys", self.keys.len(), &mut self.keys.iter().map(|d| d.0))?;
        serializer.serialize_field("from_address", &dto::Address(&self.from_address))?;
        serializer
            .serialize_optional("block_hash", self.block_hash.as_ref().map(dto::BlockHash))?;
        serializer.serialize_optional("block_number", self.block_number.map(dto::BlockNumber))?;
        serializer.serialize_field("transaction_hash", &dto::TxnHash(&self.transaction_hash))?;

        serializer.end()
    }
}

impl SerializeForVersion for &'_ EmittedEvent {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        (*self).serialize(serializer)
    }
}

impl SerializeForVersion for GetEventsResult {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter("events", self.events.len(), &mut self.events.iter())?;
        serializer.serialize_optional("continuation_token", self.continuation_token.as_ref())?;

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_storage::test_utils;
    use pretty_assertions_sorted::assert_eq;
    use serde_json::json;

    use super::{EmittedEvent, GetEventsResult, *};
    use crate::dto::DeserializeForVersion;
    use crate::RpcVersion;

    #[rstest::rstest]
    #[case::positional_with_optionals(json!([{
        "from_block":{"block_number":0},
        "to_block":"latest",
        "address":"0x1",
        "keys":[["0x2"],[]],
        "chunk_size":3,
        "continuation_token":"4"}]), true
    )]
    #[case::named_with_optionals(json!({"filter":{
        "from_block":{"block_number":0},
        "to_block":"latest",
        "address":"0x1","keys":[["0x2"],[]],
        "chunk_size":3,
        "continuation_token":"4"}}), true
    )]
    #[case::positional_without_optionals(json!([{"chunk_size":5}]), false)]
    #[case::named_without_optionals(json!({"filter":{"chunk_size":5}}), false)]
    fn parsing(#[case] input: serde_json::Value, #[case] with_optionals: bool) {
        let filter = if with_optionals {
            EventFilter {
                from_block: Some(BlockId::Number(BlockNumber::new_or_panic(0))),
                to_block: Some(BlockId::Latest),
                address: Some(contract_address!("0x1")),
                keys: vec![vec![event_key!("0x2")], vec![]],
                chunk_size: 3,
                continuation_token: Some("4".to_string()),
            }
        } else {
            EventFilter {
                chunk_size: 5,
                ..Default::default()
            }
        };
        let expected = GetEventsInput { filter };

        let input =
            GetEventsInput::deserialize(crate::dto::Value::new(input, RpcVersion::V07)).unwrap();
        assert_eq!(input, expected);
    }

    #[test]
    fn continuation_token() {
        use assert_matches::assert_matches;

        assert_matches!(
            "1234".parse::<ContinuationToken>(),
            Err(ParseContinuationTokenError)
        );
        assert_matches!(
            "invalid".parse::<ContinuationToken>(),
            Err(ParseContinuationTokenError)
        );
        assert_matches!(
            "1234-5678-9012".parse::<ContinuationToken>(),
            Err(ParseContinuationTokenError)
        );
        assert_matches!(
            "-1234-5678".parse::<ContinuationToken>(),
            Err(ParseContinuationTokenError)
        );

        assert_eq!(
            "1234-4567".parse::<ContinuationToken>().unwrap(),
            ContinuationToken {
                block_number: BlockNumber::new_or_panic(1234),
                offset: 4567
            }
        );
    }

    fn setup() -> (RpcContext, Vec<EmittedEvent>) {
        let (storage, test_data) = test_utils::setup_test_storage();
        let events = test_data
            .events
            .into_iter()
            .map(EmittedEvent::from)
            .collect();
        let context = RpcContext::for_tests().with_storage(storage);

        (context, events)
    }

    impl PartialEq for GetEventsError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    #[tokio::test]
    async fn get_events_with_empty_filter() {
        let (context, events) = setup();

        let input = GetEventsInput {
            filter: EventFilter {
                chunk_size: test_utils::NUM_EVENTS,
                ..Default::default()
            },
        };
        let result = get_events(context, input).await.unwrap();

        assert_eq!(
            result,
            GetEventsResult {
                events,
                continuation_token: None,
            }
        );
    }

    #[tokio::test]
    async fn get_events_with_fully_specified_filter() {
        let (context, events) = setup();

        let expected_event = &events[1];
        let expected_result = GetEventsResult {
            events: vec![expected_event.clone()],
            continuation_token: None,
        };
        let input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(expected_event.block_number.unwrap().into()),
                to_block: Some(expected_event.block_number.unwrap().into()),
                address: Some(expected_event.from_address),
                // we're using a key which is present in _all_ events
                keys: vec![vec![], vec![event_key!("0xdeadbeef")]],
                chunk_size: test_utils::NUM_EVENTS,
                continuation_token: None,
            },
        };
        let result = get_events(context.clone(), input.clone()).await.unwrap();
        assert_eq!(result, expected_result);
    }

    #[tokio::test]
    async fn get_events_by_block() {
        let (context, events) = setup();

        const BLOCK_NUMBER: usize = 2;
        let input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                to_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                chunk_size: test_utils::NUM_EVENTS,
                ..Default::default()
            },
        };

        let result = get_events(context, input).await.unwrap();

        let expected_events = &events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
            ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[tokio::test]
    async fn get_events_from_latest_block() {
        let (context, events) = setup();

        const LATEST_BLOCK_NUMBER: usize = 3;
        let input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(BlockId::Latest),
                to_block: Some(BlockId::Latest),
                chunk_size: test_utils::NUM_EVENTS,
                ..Default::default()
            },
        };

        let result = get_events(context, input).await.unwrap();

        let expected_events = &events[test_utils::EVENTS_PER_BLOCK * LATEST_BLOCK_NUMBER
            ..test_utils::EVENTS_PER_BLOCK * (LATEST_BLOCK_NUMBER + 1)];
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events.to_vec(),
                continuation_token: None,
            }
        );
    }

    #[tokio::test]
    async fn get_events_with_invalid_page_size() {
        let (context, _) = setup();

        let input = GetEventsInput {
            filter: EventFilter {
                chunk_size: pathfinder_storage::EVENT_PAGE_SIZE_LIMIT + 1,
                ..Default::default()
            },
        };
        let error = get_events(context, input).await.unwrap_err();

        assert_eq!(GetEventsError::PageSizeTooBig, error);
    }

    #[tokio::test]
    async fn get_events_with_too_many_keys_in_filter() {
        let (context, _) = setup();

        let limit = EVENT_KEY_FILTER_LIMIT;

        let keys = [vec![event_key!("01")]]
            .iter()
            .cloned()
            .cycle()
            .take(limit + 1)
            .collect::<Vec<_>>();

        let input = GetEventsInput {
            filter: EventFilter {
                keys,
                chunk_size: 10,
                ..Default::default()
            },
        };
        let error = get_events(context, input).await.unwrap_err();

        assert_eq!(
            GetEventsError::TooManyKeysInFilter {
                limit,
                requested: limit + 1
            },
            error
        );
    }

    #[tokio::test]
    async fn get_events_by_key_with_paging() {
        let (context, events) = setup();

        let expected_events = &events[27..33];
        let keys_for_expected_events: Vec<Vec<_>> =
            vec![expected_events.iter().map(|e| e.keys[0]).collect()];

        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 1,
                ..Default::default()
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[..1].to_vec(),
                continuation_token: Some("0-1".to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 2,
                continuation_token: Some("0-1".to_string()),
                ..Default::default()
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[1..3].to_vec(),
                continuation_token: Some("3-0".to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 3,
                continuation_token: Some("3-0".to_string()),
                ..Default::default()
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[3..].to_vec(),
                continuation_token: None,
            }
        );

        // nonexistent page
        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 1,
                // Offset pointing to after the last event
                continuation_token: Some("2-6".to_string()),
                ..Default::default()
            },
        };
        let result = get_events(context, input).await.unwrap();
        assert_eq!(result.events, &[]);
        assert_eq!(result.continuation_token, None);
    }

    mod pending {
        use pretty_assertions_sorted::assert_eq;

        use super::*;

        #[tokio::test]
        async fn backward_range() {
            let context = RpcContext::for_tests_with_pending().await;

            let input = GetEventsInput {
                filter: EventFilter {
                    from_block: Some(BlockId::Pending),
                    to_block: Some(BlockId::Latest),
                    chunk_size: 100,
                    ..Default::default()
                },
            };
            let result = get_events(context, input).await.unwrap();
            assert!(result.events.is_empty());
        }

        #[tokio::test]
        async fn all_events() {
            let context = RpcContext::for_tests_with_pending().await;

            let mut input = GetEventsInput {
                filter: EventFilter {
                    to_block: Some(BlockId::Latest),
                    chunk_size: 1024,
                    ..Default::default()
                },
            };

            let events = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(events.events.len(), 1);

            input.filter.from_block = Some(BlockId::Pending);
            input.filter.to_block = Some(BlockId::Pending);
            let pending_events = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(pending_events.events.len(), 3);

            input.filter.from_block = None;
            let all_events = get_events(context.clone(), input.clone()).await.unwrap();

            let expected = events
                .events
                .into_iter()
                .chain(pending_events.events.into_iter())
                .collect::<Vec<_>>();

            assert_eq!(all_events.events, expected);
            assert!(all_events.continuation_token.is_none());
        }

        #[tokio::test]
        async fn paging() {
            let context = RpcContext::for_tests_with_pending().await;

            let mut input = GetEventsInput {
                filter: EventFilter {
                    to_block: Some(BlockId::Pending),
                    chunk_size: 1024,
                    ..Default::default()
                },
            };

            let all = get_events(context.clone(), input.clone())
                .await
                .unwrap()
                .events;

            // Check edge case where the page is full with events from the DB but this was
            // the last page from the DB -- should continue from offset 0 of the
            // pending block next time
            input.filter.chunk_size = 1;
            input.filter.continuation_token = None;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..1]);
            assert_eq!(result.continuation_token, Some("3-0".to_string()));

            // Page includes a DB event and an event from the pending block, but there are
            // more pending events for the next page
            input.filter.chunk_size = 2;
            input.filter.continuation_token = None;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..2]);
            assert_eq!(result.continuation_token, Some("3-1".to_string()));

            input.filter.chunk_size = 1;
            input.filter.continuation_token = result.continuation_token;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[2..3]);
            assert_eq!(result.continuation_token, Some("3-2".to_string()));

            input.filter.chunk_size = 100; // Only a single event remains though
            input.filter.continuation_token = result.continuation_token;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[3..4]);
            assert_eq!(result.continuation_token, None);

            // continuing from a page that does exist, should return all events (even from
            // pending)
            input.filter.chunk_size = 123;
            input.filter.continuation_token = Some("0-0".to_string());
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, all);
            assert_eq!(result.continuation_token, None);

            // nonexistent page: offset too large
            input.filter.chunk_size = 123; // Does not matter
            input.filter.continuation_token = Some("3-3".to_string()); // Points to after the last event
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &[]);
            assert_eq!(result.continuation_token, None);

            // nonexistent page: block number
            input.filter.chunk_size = 123; // Does not matter
            input.filter.continuation_token = Some("4-1".to_string()); // Points to after the last event
            let error = get_events(context.clone(), input).await.unwrap_err();
            assert_eq!(error, GetEventsError::InvalidContinuationToken);
        }

        #[tokio::test]
        async fn paging_with_no_more_matching_events_in_pending() {
            let context = RpcContext::for_tests_with_pending().await;

            let mut input = GetEventsInput {
                filter: EventFilter {
                    from_block: None,
                    to_block: Some(BlockId::Pending),
                    address: None,
                    keys: vec![vec![
                        event_key_bytes!(b"event 0 key"),
                        event_key_bytes!(b"pending key 2"),
                    ]],
                    chunk_size: 1024,
                    continuation_token: None,
                },
            };

            let all = get_events(context.clone(), input.clone())
                .await
                .unwrap()
                .events;
            assert_eq!(all.len(), 2);

            // returns a continuation token if there are more matches in pending
            input.filter.chunk_size = 1;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..1]);
            assert_eq!(result.continuation_token, Some("3-0".to_string()));
        }

        #[tokio::test]
        async fn key_matching() {
            let context = RpcContext::for_tests_with_pending().await;

            let mut input = GetEventsInput {
                filter: EventFilter {
                    from_block: Some(BlockId::Pending),
                    to_block: Some(BlockId::Pending),
                    address: None,
                    keys: vec![],
                    chunk_size: 1024,
                    continuation_token: None,
                },
            };

            let all = get_events(context.clone(), input.clone())
                .await
                .unwrap()
                .events;
            assert_eq!(all.len(), 3);

            input.filter.keys = vec![vec![event_key_bytes!(b"pending key 2")]];
            let events = get_events(context.clone(), input.clone())
                .await
                .unwrap()
                .events;
            assert_eq!(events, &all[2..3]);

            input.filter.keys = vec![vec![], vec![event_key_bytes!(b"second pending key")]];
            let events = get_events(context.clone(), input.clone())
                .await
                .unwrap()
                .events;
            assert_eq!(events, &all[1..2]);
        }

        #[tokio::test]
        async fn from_block_past_pending() {
            let context = RpcContext::for_tests_with_pending().await;

            let input = GetEventsInput {
                filter: EventFilter {
                    from_block: Some(BlockId::Number(BlockNumber::new_or_panic(4))),
                    to_block: Some(BlockId::Pending),
                    chunk_size: 100,
                    ..Default::default()
                },
            };
            let result = get_events(context, input).await.unwrap();
            assert!(result.events.is_empty());
        }

        #[tokio::test]
        async fn from_block_pending_to_block_none() {
            let context = RpcContext::for_tests_with_pending().await;

            let input = GetEventsInput {
                filter: EventFilter {
                    from_block: Some(BlockId::Pending),
                    to_block: None,
                    chunk_size: 100,
                    ..Default::default()
                },
            };
            let result = get_events(context, input).await.unwrap();
            assert!(!result.events.is_empty());
        }
    }
}
