use crate::context::RpcContext;
use anyhow::Context;
use pathfinder_common::{BlockId, ContractAddress, EventKey, StarknetBlockNumber};
use pathfinder_storage::{
    EventFilterError, StarknetBlocksTable, StarknetEventFilter, StarknetEventsTable, V03KeyFilter,
};
use serde::Deserialize;
use starknet_gateway_types::pending::PendingData;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub enum GetEventsError {
    Internal(anyhow::Error),
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

impl From<GetEventsError> for crate::error::RpcError {
    fn from(e: GetEventsError) -> Self {
        match e {
            GetEventsError::Internal(internal) => Self::Internal(internal),
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
pub struct GetEventsInput {
    filter: EventFilter,
}

/// Contains event filter parameters passed to `starknet_getEvents`.
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
    //  b) if full page           -> return page
    //  c) else if partially full -> append events from start of pending
    //  d) else (page is empty):
    //      i) query database for event count
    //     ii) query pending data using count for paging into pending events

    use BlockId::*;

    let request = input.filter;
    let requested_offset = match request.continuation_token {
        Some(s) => Some(
            s.parse::<usize>()
                .map_err(|_| GetEventsError::InvalidContinuationToken)?,
        ),
        None => None,
    };

    if request.keys.len() > pathfinder_storage::StarknetEventsTable::KEY_FILTER_LIMIT {
        return Err(GetEventsError::TooManyKeysInFilter {
            limit: pathfinder_storage::StarknetEventsTable::KEY_FILTER_LIMIT,
            requested: request.keys.len(),
        });
    }

    // Handle the trivial (1) and (2) cases.
    match (request.from_block, request.to_block) {
        (Some(Pending), non_pending) if non_pending != Some(Pending) => {
            return Ok(types::GetEventsResult {
                events: Vec::new(),
                continuation_token: None,
            });
        }
        (Some(Pending), Some(Pending)) => {
            let skip = requested_offset.unwrap_or_default();

            let keys: Vec<std::collections::HashSet<_>> = request
                .keys
                .into_iter()
                .map(|keys| keys.into_iter().collect())
                .collect();

            let mut events = Vec::new();
            let is_last_page = append_pending_events(
                &context.pending_data,
                &mut events,
                skip,
                request.chunk_size,
                request.address,
                keys,
            )
            .await;

            check_continuation_token_validity(requested_offset, &events)?;

            let continuation_token =
                next_continuation_token(skip, request.chunk_size, is_last_page);

            return Ok(types::GetEventsResult {
                events,
                continuation_token,
            });
        }
        _ => {}
    }

    let storage = context.storage.clone();
    let keys = V03KeyFilter(request.keys.clone());

    // blocking task to perform database event query and optionally, the event count
    // required for (4d).
    let span = tracing::Span::current();
    let db_events: JoinHandle<Result<_, GetEventsError>> = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        let from_block = map_from_block_to_number(&transaction, request.from_block)?;
        let to_block = map_to_block_to_number(&transaction, request.to_block)?;

        let filter = StarknetEventFilter {
            from_block,
            to_block,
            contract_address: request.address,
            keys: keys.clone(),
            page_size: request.chunk_size,
            offset: requested_offset.unwrap_or_default(),
        };
        // We don't add context here, because [StarknetEventsTable::get_events] adds its
        // own context to the errors. This way we get meaningful error information
        // for errors related to query parameters.
        let page = StarknetEventsTable::get_events(&transaction, &filter).map_err(|e| {
            if e.downcast_ref::<EventFilterError>().is_some() {
                GetEventsError::PageSizeTooBig
            } else {
                GetEventsError::from(e)
            }
        })?;

        // Additional information is required if we need to append pending events.
        // More specifically, we need some database event count in order to page through
        // the pending events properly.
        let event_count = if request.to_block == Some(Pending) && page.events.is_empty() {
            let count = StarknetEventsTable::event_count(
                &transaction,
                from_block,
                to_block,
                request.address,
                &keys,
            )?;

            Some(count)
        } else {
            None
        };

        let continuation_token =
            next_continuation_token(filter.offset, filter.page_size, page.is_last_page);

        Ok((
            types::GetEventsResult {
                events: page.events.into_iter().map(|e| e.into()).collect(),
                continuation_token,
            },
            event_count,
        ))
    });

    let (mut events, count) = db_events
        .await
        .context("Database read panic or shutting down")??;

    // Append pending data if required.
    if matches!(request.to_block, Some(Pending)) && events.events.len() < request.chunk_size {
        let keys: Vec<std::collections::HashSet<_>> = request
            .keys
            .into_iter()
            .map(|keys| keys.into_iter().collect())
            .collect();

        let amount = request.chunk_size - events.events.len();

        let skip = match count {
            Some(count) => {
                // This will not yield an underflow error, as when continuation_token is None,
                // then the count is also always 0, since the last page can only be empty if there's
                // only a single empty page
                requested_offset.unwrap_or_default() - count
            }
            None => 0,
        };

        let is_last_page = append_pending_events(
            &context.pending_data,
            &mut events.events,
            skip,
            amount,
            request.address,
            keys,
        )
        .await;

        events.continuation_token = next_continuation_token(
            requested_offset.unwrap_or_default(),
            request.chunk_size,
            is_last_page,
        );
    }

    check_continuation_token_validity(requested_offset, &events.events)?;

    Ok(events)
}

// Maps `to_block` BlockId to a block number which can be used by the events query.
//
// This block id specifies the upper end of the range, so pending/latest/None means
// there's no upper limit.
fn map_to_block_to_number(
    tx: &rusqlite::Transaction<'_>,
    block: Option<BlockId>,
) -> Result<Option<StarknetBlockNumber>, GetEventsError> {
    use BlockId::*;

    match block {
        Some(Hash(hash)) => {
            let number =
                StarknetBlocksTable::get_number(tx, hash)?.ok_or(GetEventsError::BlockNotFound)?;

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
    tx: &rusqlite::Transaction<'_>,
    block: Option<BlockId>,
) -> Result<Option<StarknetBlockNumber>, GetEventsError> {
    use BlockId::*;

    match block {
        Some(Hash(hash)) => {
            let number =
                StarknetBlocksTable::get_number(tx, hash)?.ok_or(GetEventsError::BlockNotFound)?;

            Ok(Some(number))
        }
        Some(Number(number)) => Ok(Some(number)),
        Some(Pending) | Some(Latest) => {
            let number =
                StarknetBlocksTable::get_latest_number(tx)?.ok_or(GetEventsError::BlockNotFound)?;
            Ok(Some(number))
        }
        None => Ok(None),
    }
}

/// Append's pending events to `dst` based on the filter requirements and returns
/// true if this was the last pending data i.e. `is_last_page`.
async fn append_pending_events(
    pending_data: &Option<PendingData>,
    dst: &mut Vec<types::EmittedEvent>,
    skip: usize,
    amount: usize,
    address: Option<ContractAddress>,
    keys: Vec<std::collections::HashSet<EventKey>>,
) -> bool {
    let pending_block = match pending_data.as_ref() {
        Some(data) => match data.block().await {
            Some(block) => block,
            None => return true,
        },
        None => return true,
    };

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

/// Continuation token is invalid if:
/// 1. its value is nonzero (which means that it _actually_ points to some _next page_)
/// 2. it yields an empty page
///
/// Unfortunately page retrieval has to be completed before the actual check can be done.
fn check_continuation_token_validity(
    continuation_token: Option<usize>,
    events: &[types::EmittedEvent],
) -> Result<(), GetEventsError> {
    match continuation_token {
        Some(token) if token > 0 && events.is_empty() => {
            Err(GetEventsError::InvalidContinuationToken)
        }
        Some(_) | None => Ok(()),
    }
}

fn next_continuation_token(
    current_offset: usize,
    chunk_size: usize,
    is_last_page: bool,
) -> Option<String> {
    if is_last_page {
        None
    } else {
        // Point to the next page
        Some((current_offset + chunk_size).to_string())
    }
}

mod types {
    use pathfinder_common::{
        ContractAddress, EventData, EventKey, StarknetBlockHash, StarknetBlockNumber,
        StarknetTransactionHash,
    };
    use pathfinder_storage::StarknetEmittedEvent;
    use serde::Serialize;

    /// Describes an emitted event returned by starknet_getEvents
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct EmittedEvent {
        pub data: Vec<EventData>,
        pub keys: Vec<EventKey>,
        pub from_address: ContractAddress,
        /// [None] for pending events.
        pub block_hash: Option<StarknetBlockHash>,
        /// [None] for pending events.
        pub block_number: Option<StarknetBlockNumber>,
        pub transaction_hash: StarknetTransactionHash,
    }

    impl From<StarknetEmittedEvent> for EmittedEvent {
        fn from(event: StarknetEmittedEvent) -> Self {
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
        /// Offset, measured in events, which points to the chunk that follows currenty requested chunk (`events`)
        pub continuation_token: Option<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        types::{EmittedEvent, GetEventsResult},
        *,
    };
    use jsonrpsee::types::Params;
    use pathfinder_common::felt;
    use pathfinder_storage::test_utils;
    use pretty_assertions::assert_eq;

    #[test]
    fn parsing() {
        let optional_present = EventFilter {
            from_block: Some(BlockId::Number(StarknetBlockNumber::new_or_panic(0))),
            to_block: Some(BlockId::Latest),
            address: Some(ContractAddress::new_or_panic(felt!("0x1"))),
            keys: vec![vec![EventKey(felt!("0x2"))], vec![]],
            chunk_size: 3,
            continuation_token: Some("4".to_string()),
        };
        let optional_absent = EventFilter {
            from_block: None,
            to_block: None,
            address: None,
            keys: vec![],
            chunk_size: 5,
            continuation_token: None,
        };

        [
            (
                r#"[{"from_block":{"block_number":0},"to_block":"latest","address":"0x1","keys":[["0x2"],[]],"chunk_size":3,"continuation_token":"4"}]"#,
                optional_present.clone(),
            ),
            (
                r#"{"filter":{"from_block":{"block_number":0},"to_block":"latest","address":"0x1","keys":[["0x2"],[]],"chunk_size":3,"continuation_token":"4"}}"#,
                optional_present
            ),
            (r#"[{"chunk_size":5}]"#, optional_absent.clone()),
            (r#"{"filter":{"chunk_size":5}}"#, optional_absent),
        ]
        .into_iter()
        .enumerate()
        .for_each(|(i, (input, expected))| {
            let actual = Params::new(Some(input))
                .parse::<GetEventsInput>()
                .unwrap_or_else(|error| panic!("test case {i}: {input}, {error}"));
            assert_eq!(
                actual,
                GetEventsInput { filter: expected },
                "test case {i}: {input}"
            );
        });
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
                from_block: None,
                to_block: None,
                address: None,
                keys: vec![],
                chunk_size: test_utils::NUM_EVENTS,
                continuation_token: None,
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
        let mut input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(expected_event.block_number.unwrap().into()),
                to_block: Some(expected_event.block_number.unwrap().into()),
                address: Some(expected_event.from_address),
                // we're using a key which is present in _all_ events
                keys: vec![vec![], vec![EventKey(felt!("0xdeadbeef"))]],
                chunk_size: test_utils::NUM_EVENTS,
                continuation_token: None,
            },
        };
        let result = get_events(context.clone(), input.clone()).await.unwrap();
        assert_eq!(result, expected_result);

        // 0 continuation token should yield the same result as no token
        input.filter.continuation_token = Some(0.to_string());
        let result = get_events(context, input).await.unwrap();
        assert_eq!(result, expected_result);
    }

    #[tokio::test]
    async fn get_events_by_block() {
        let (context, events) = setup();

        const BLOCK_NUMBER: usize = 2;
        let input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                to_block: Some(StarknetBlockNumber::new_or_panic(BLOCK_NUMBER as u64).into()),
                address: None,
                keys: vec![],
                chunk_size: test_utils::NUM_EVENTS,
                continuation_token: None,
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
                address: None,
                keys: vec![],
                chunk_size: test_utils::NUM_EVENTS,
                continuation_token: None,
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
                from_block: None,
                to_block: None,
                address: None,
                keys: vec![],
                chunk_size: pathfinder_storage::StarknetEventsTable::PAGE_SIZE_LIMIT + 1,
                continuation_token: None,
            },
        };
        let error = get_events(context, input).await.unwrap_err();

        assert_eq!(GetEventsError::PageSizeTooBig, error);
    }

    #[tokio::test]
    async fn get_events_with_too_many_keys_in_filter() {
        let (context, _) = setup();

        let limit = pathfinder_storage::StarknetEventsTable::KEY_FILTER_LIMIT;

        let keys = [vec![EventKey(felt!("01"))]]
            .iter()
            .cloned()
            .cycle()
            .take(limit + 1)
            .collect::<Vec<_>>();

        let input = GetEventsInput {
            filter: EventFilter {
                from_block: None,
                to_block: None,
                address: None,
                keys,
                chunk_size: 10,
                continuation_token: None,
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
                from_block: None,
                to_block: None,
                address: None,
                keys: keys_for_expected_events.clone(),
                chunk_size: 1,
                continuation_token: None,
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[..1].to_vec(),
                continuation_token: Some(1.to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                from_block: None,
                to_block: None,
                address: None,
                keys: keys_for_expected_events.clone(),
                chunk_size: 2,
                continuation_token: Some(1.to_string()),
            },
        };
        let result = get_events(context.clone(), input).await.unwrap();
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events[1..3].to_vec(),
                continuation_token: Some(3.to_string()),
            }
        );

        let input = GetEventsInput {
            filter: EventFilter {
                from_block: None,
                to_block: None,
                address: None,
                keys: keys_for_expected_events.clone(),
                chunk_size: 3,
                continuation_token: Some(3.to_string()),
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
                from_block: None,
                to_block: None,
                address: None,
                keys: keys_for_expected_events.clone(),
                chunk_size: 1,
                // Offset pointing to after the last event
                continuation_token: Some(6.to_string()),
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
                    address: None,
                    keys: vec![],
                    chunk_size: 100,
                    continuation_token: None,
                },
            };
            let result = get_events(context, input).await.unwrap();
            assert!(result.events.is_empty());
        }

        #[tokio::test]
        async fn all_events() {
            let context = RpcContext::for_tests_with_pending().await;

            let input0 = GetEventsInput {
                filter: EventFilter {
                    from_block: None,
                    to_block: Some(BlockId::Latest),
                    address: None,
                    keys: vec![],
                    chunk_size: 1024,
                    continuation_token: None,
                },
            };
            let mut input1 = input0.clone();
            input1.filter.continuation_token = Some(0.to_string());

            for mut input in [input0, input1] {
                let events = get_events(context.clone(), input.clone()).await.unwrap();

                input.filter.from_block = Some(BlockId::Pending);
                input.filter.to_block = Some(BlockId::Pending);
                let pending_events = get_events(context.clone(), input.clone()).await.unwrap();

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
        }

        #[tokio::test]
        async fn paging() {
            let context = RpcContext::for_tests_with_pending().await;

            let mut input = GetEventsInput {
                filter: EventFilter {
                    from_block: None,
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

            input.filter.chunk_size = 2;
            input.filter.continuation_token = Some(0.to_string()); // Should yield the same result as None above
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[0..2]);
            assert_eq!(result.continuation_token, Some(2.to_string()));

            input.filter.chunk_size = 1;
            input.filter.continuation_token = result.continuation_token;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[2..3]);
            assert_eq!(result.continuation_token, Some(3.to_string()));

            input.filter.chunk_size = 100; // Only a single event remains though
            input.filter.continuation_token = result.continuation_token;
            let result = get_events(context.clone(), input.clone()).await.unwrap();
            assert_eq!(result.events, &all[3..4]);
            assert_eq!(result.continuation_token, None);

            // nonexistent page
            input.filter.chunk_size = 123; // Does not matter
            input.filter.continuation_token = Some(4.to_string()); // Points to after the last event
            let error = get_events(context.clone(), input).await.unwrap_err();
            assert_eq!(error, GetEventsError::InvalidContinuationToken);
        }
    }
}
