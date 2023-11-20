use std::str::FromStr;

use crate::context::RpcContext;
use crate::pending::PendingData;
use anyhow::Context;
use pathfinder_common::{BlockId, BlockNumber, ContractAddress, EventKey};
use pathfinder_storage::{EventFilterError, V03KeyFilter};
use serde::Deserialize;
use starknet_gateway_types::reply::PendingBlock;
use tokio::task::JoinHandle;

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

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
#[serde(deny_unknown_fields)]
pub struct GetEventsInput {
    filter: EventFilter,
}

/// Contains event filter parameters passed to `starknet_getEvents`.
#[serde_with::skip_serializing_none]
#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventFilter {
    #[serde(default)]
    pub from_block: Option<BlockId>,
    #[serde(default)]
    pub to_block: Option<BlockId>,
    #[serde(default)]
    pub address: Option<ContractAddress>,
    #[serde(default)]
    pub keys: Vec<Vec<EventKey>>,

    // These are inlined here because serde flatten and deny_unknown_fields
    // don't work together.
    pub chunk_size: usize,
    /// Offset, measured in events, which points to the requested chunk
    #[serde(default)]
    pub continuation_token: Option<String>,
}

/// Returns events matching the specified filter
pub async fn get_events(
    context: RpcContext,
    input: GetEventsInput,
) -> Result<types::GetEventsResult, GetEventsError> {
    // The [Block::Pending] in ranges makes things quite complicated. This implementation splits
    // the ranges into the following buckets:
    //
    // 1. pending     :     pending -> query pending only
    // 2. pending     : non-pending -> return empty result
    // 3. non-pending : non-pending -> query db only
    // 4. non-pending :     pending -> query db and potentially append pending events
    //
    // The database query for 3 and 4 is combined into one step.
    //
    // 4 requires some additional logic to handle some edge cases:
    //  a) Query database
    //  b) if full page -> return page
    //      check if there are matching events in the pending block
    //      and return a continuation token for the pending block
    //  c) else if empty / partially full -> append events from start of pending
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

    if request.keys.len() > pathfinder_storage::EVENT_KEY_FILTER_LIMIT {
        return Err(GetEventsError::TooManyKeysInFilter {
            limit: pathfinder_storage::EVENT_KEY_FILTER_LIMIT,
            requested: request.keys.len(),
        });
    }

    let storage = context.storage.clone();
    let keys = V03KeyFilter::new(request.keys.clone());

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

        // Handle the trivial (1) and (2) cases.
        match (&request.from_block, &request.to_block) {
            (Some(Pending), non_pending) if *non_pending != Some(Pending) => {
                return Ok(types::GetEventsResult {
                    events: Vec::new(),
                    continuation_token: None,
                });
            }
            (Some(Pending), Some(Pending)) => {
                let pending = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?;
                return get_pending_events(&request, &pending, continuation_token);
            }
            _ => {}
        }

        let from_block = map_from_block_to_number(&transaction, request.from_block)?;
        let to_block = map_to_block_to_number(&transaction, request.to_block)?;

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
        // We don't add context here, because [StarknetEventsTable::get_events] adds its
        // own context to the errors. This way we get meaningful error information
        // for errors related to query parameters.
        let page = transaction.events(&filter).map_err(|e| match e {
            EventFilterError::PageSizeTooBig(_) => GetEventsError::PageSizeTooBig,
            EventFilterError::TooManyMatches => GetEventsError::Custom(e.into()),
            EventFilterError::Internal(e) => GetEventsError::Internal(e),
            EventFilterError::PageSizeTooSmall => GetEventsError::Custom(e.into()),
        })?;

        let new_continuation_token = match page.is_last_page {
            true => None,
            false => {
                assert_eq!(page.events.len(), request.chunk_size);
                let last_block_number = page.events.last().unwrap().block_number;
                let number_of_events_in_last_block = page
                    .events
                    .iter()
                    .rev()
                    .take_while(|event| event.block_number == last_block_number)
                    .count();

                if number_of_events_in_last_block < request.chunk_size {
                    // the page contains events from a new block
                    Some(ContinuationToken {
                        block_number: last_block_number,
                        offset: number_of_events_in_last_block,
                    })
                } else {
                    match continuation_token {
                        Some(previous_continuation_token) => Some(ContinuationToken {
                            block_number: previous_continuation_token.block_number,
                            offset: previous_continuation_token.offset + request.chunk_size,
                        }),
                        None => Some(ContinuationToken {
                            block_number: page.events.first().unwrap().block_number,
                            offset: request.chunk_size,
                        }),
                    }
                }
            }
        };

        let mut events = types::GetEventsResult {
            events: page.events.into_iter().map(|e| e.into()).collect(),
            continuation_token: new_continuation_token.map(|token| token.to_string()),
        };

        // Append pending data if required.
        if matches!(request.to_block, Some(Pending)) {
            let pending = context
                .pending_data
                .get(&transaction)
                .context("Querying pending data")?;

            let keys: Vec<std::collections::HashSet<_>> = request
                .keys
                .into_iter()
                .map(|keys| keys.into_iter().collect())
                .collect();

            if events.events.len() < request.chunk_size {
                let amount = request.chunk_size - events.events.len();

                let current_offset = match continuation_token {
                    Some(continuation_token) => {
                        continuation_token.offset_in_block(pending.number)?
                    }
                    None => 0,
                };

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
            } else if page.is_last_page {
                // the page is full but this was the last page from the DB, so
                // we should continue with the first pending event in the next
                // page

                // check if there are matching pending events
                let mut buf: Vec<types::EmittedEvent> = Vec::new();
                let _ =
                    append_pending_events(&pending.block, &mut buf, 0, 1, request.address, keys);
                if buf.is_empty() {
                    // if there are no matching events in pending we should not return a token
                    events.continuation_token = None;
                } else {
                    let continuation_token = ContinuationToken {
                        block_number: pending.number,
                        offset: 0,
                    };
                    events.continuation_token = Some(continuation_token.to_string());
                }
            }
        }

        check_continuation_token_validity(continuation_token, &events.events)?;

        Ok(events)
    });

    db_events
        .await
        .context("Database read panic or shutting down")?
}

// Handle the case when we're querying events exclusively from the pending block.
fn get_pending_events(
    request: &EventFilter,
    pending: &PendingData,
    continuation_token: Option<ContinuationToken>,
) -> Result<types::GetEventsResult, GetEventsError> {
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

    check_continuation_token_validity(continuation_token, &events)?;

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

    Ok(types::GetEventsResult {
        events,
        continuation_token,
    })
}

// Maps `to_block` BlockId to a block number which can be used by the events query.
//
// This block id specifies the upper end of the range, so pending/latest/None means
// there's no upper limit.
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

// Maps `from_block` BlockId to a block number which can be used by the events query.
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

/// Append's pending events to `dst` based on the filter requirements and returns
/// true if this was the last pending data i.e. `is_last_page`.
fn append_pending_events(
    pending_block: &PendingBlock,
    dst: &mut Vec<types::EmittedEvent>,
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
        .flat_map(|receipt| {
            receipt
                .events
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

            let keys_to_check = std::cmp::min(keys.len(), event.keys.len());

            event
                .keys
                .iter()
                .zip(keys.iter())
                .take(keys_to_check)
                .all(|(key, filter)| filter.contains(key))
        })
        .skip(skip)
        // We need to take an extra event to determine is_last_page.
        .take(amount + 1)
        .map(|(event, tx_hash)| types::EmittedEvent {
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
        if self.block_number == block_number {
            Ok(self.offset)
        } else {
            Err(GetEventsError::InvalidContinuationToken)
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

/// Continuation token is invalid if it yields an empty page since we only ever
/// return a token if we know there are more events.
///
/// Unfortunately page retrieval has to be completed before the actual check can be done.
fn check_continuation_token_validity(
    continuation_token: Option<ContinuationToken>,
    events: &[types::EmittedEvent],
) -> Result<(), GetEventsError> {
    match continuation_token {
        Some(_) if events.is_empty() => Err(GetEventsError::InvalidContinuationToken),
        Some(_) | None => Ok(()),
    }
}

mod types {
    use pathfinder_common::{
        BlockHash, BlockNumber, ContractAddress, EventData, EventKey, TransactionHash,
    };
    use serde::Serialize;

    /// Describes an emitted event returned by starknet_getEvents
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct EmittedEvent {
        pub data: Vec<EventData>,
        pub keys: Vec<EventKey>,
        pub from_address: ContractAddress,
        /// [None] for pending events.
        pub block_hash: Option<BlockHash>,
        /// [None] for pending events.
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
    #[serde_with::skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct GetEventsResult {
        pub events: Vec<EmittedEvent>,
        /// Offset, measured in events, which points to the chunk that follows currently requested chunk (`events`)
        pub continuation_token: Option<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        types::{EmittedEvent, GetEventsResult},
        *,
    };
    use serde_json::json;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_storage::test_utils;
    use pretty_assertions::assert_eq;

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

        let input = serde_json::from_value::<GetEventsInput>(input).unwrap();
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
                chunk_size: pathfinder_storage::PAGE_SIZE_LIMIT + 1,
                ..Default::default()
            },
        };
        let error = get_events(context, input).await.unwrap_err();

        assert_eq!(GetEventsError::PageSizeTooBig, error);
    }

    #[tokio::test]
    async fn get_events_with_too_many_keys_in_filter() {
        let (context, _) = setup();

        let limit = pathfinder_storage::KEY_FILTER_LIMIT;

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
                continuation_token: Some("2-1".to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 2,
                continuation_token: Some("2-1".to_string()),
                ..Default::default()
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[1..3].to_vec(),
                continuation_token: Some("2-3".to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                keys: keys_for_expected_events.clone(),
                chunk_size: 3,
                continuation_token: Some("2-3".to_string()),
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
        let error = get_events(context, input).await.unwrap_err();
        assert_eq!(error, GetEventsError::InvalidContinuationToken);
    }

    mod pending {
        use super::*;
        use pretty_assertions::assert_eq;

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

            // Check edge case where the page is full with events from the DB but this was the
            // last page from the DB -- should continue from offset 0 of the pending block next time
            input.filter.chunk_size = 1;
            input.filter.continuation_token = None;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..1]);
            assert_eq!(result.continuation_token, Some("3-0".to_string()));

            // Page includes a DB event and an event from the pending block, but there are more pending
            // events for the next page
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

            // nonexistent page: offset too large
            input.filter.chunk_size = 123; // Does not matter
            input.filter.continuation_token = Some("3-3".to_string()); // Points to after the last event
            let error = get_events(context.clone(), input.clone())
                .await
                .unwrap_err();
            assert_eq!(error, GetEventsError::InvalidContinuationToken);

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

            // returns no continuation token if there are no matches in pending
            input.filter.keys = vec![vec![event_key_bytes!(b"event 0 key")]];
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..1]);
            assert_eq!(result.continuation_token, None);
        }
    }
}
