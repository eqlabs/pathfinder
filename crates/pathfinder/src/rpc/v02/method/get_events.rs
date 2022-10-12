use crate::core::{BlockId, ContractAddress, EventKey, StarknetBlockNumber};
use crate::rpc::v02::RpcContext;
use crate::state::PendingData;
use crate::storage::EventFilterError;
use crate::storage::{StarknetBlocksTable, StarknetEventsTable};
use anyhow::Context;
use serde::Deserialize;
use tokio::task::JoinHandle;

crate::rpc::error::generate_rpc_error_subset!(
    GetEventsError: BlockNotFound,
    PageSizeTooBig,
    InvalidContinuationToken
);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetEventsInput {
    filter: EventFilter,
}

/// Contains event filter parameters passed to `starknet_getEvents`.
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
// FIXME - needed?
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct EventFilter {
    #[serde(default, alias = "fromBlock")]
    pub from_block: Option<BlockId>,
    #[serde(default, alias = "toBlock")]
    pub to_block: Option<BlockId>,
    #[serde(default)]
    pub address: Option<ContractAddress>,
    #[serde(default)]
    pub keys: Vec<EventKey>,

    // These are inlined here because serde flatten and deny_unknown_fields
    // don't work together.
    pub page_size: usize,
    pub page_number: usize,
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

    // FIXME
    let request = input.filter;

    // Handle the trivial (1) and (2) cases.
    match (request.from_block, request.to_block) {
        (Some(Pending), non_pending) if non_pending != Some(Pending) => {
            return Ok(types::GetEventsResult {
                events: Vec::new(),
                // Or should this always be zero? Hard to say.. its a dumb request.
                page_number: request.page_number,
                is_last_page: true,
            });
        }
        (Some(Pending), Some(Pending)) => {
            let mut events = Vec::new();
            let is_last_page = append_pending_events(
                &context.pending_data,
                &mut events,
                request.page_number * request.page_size,
                request.page_size,
                request.address,
                request.keys.into_iter().collect(),
            )
            .await;
            return Ok(types::GetEventsResult {
                events,
                page_number: request.page_number,
                is_last_page,
            });
        }
        _ => {}
    }

    let storage = context.storage.clone();
    let keys = request.keys.clone();

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

        // Maps a BlockId to a block number which can be used by the events query.
        fn map_to_number(
            tx: &rusqlite::Transaction<'_>,
            block: Option<BlockId>,
        ) -> Result<Option<StarknetBlockNumber>, GetEventsError> {
            match block {
                Some(Hash(hash)) => {
                    let number = StarknetBlocksTable::get_number(tx, hash)?
                        .ok_or(GetEventsError::BlockNotFound)?;

                    Ok(Some(number))
                }
                Some(Number(number)) => Ok(Some(number)),
                Some(Pending) | Some(Latest) | None => Ok(None),
            }
        }

        let from_block = map_to_number(&transaction, request.from_block)?;
        let to_block = map_to_number(&transaction, request.to_block)?;

        let filter = crate::storage::StarknetEventFilter {
            from_block,
            to_block,
            contract_address: request.address,
            keys: keys.clone(),
            page_size: request.page_size,
            page_number: request.page_number,
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
                keys,
            )?;

            Some(count)
        } else {
            None
        };

        Ok((
            types::GetEventsResult {
                events: page.events.into_iter().map(|e| e.into()).collect(),
                page_number: filter.page_number,
                is_last_page: page.is_last_page,
            },
            event_count,
        ))
    });

    let (mut events, count) = db_events
        .await
        .context("Database read panic or shutting down")??;

    // Append pending data if required.
    if matches!(request.to_block, Some(Pending)) && events.events.len() < request.page_size {
        let keys = request
            .keys
            .into_iter()
            .collect::<std::collections::HashSet<_>>();

        let amount = request.page_size - events.events.len();
        let skip = match count {
            Some(count) => request.page_number * request.page_size - count,
            None => 0,
        };
        events.is_last_page = append_pending_events(
            &context.pending_data,
            &mut events.events,
            skip,
            amount,
            request.address,
            keys,
        )
        .await;
    }

    Ok(events)
}

/// Append's pending events to `dst` based on the filter requirements and returns
/// true if this was the last pending data i.e. `is_last_page`.
async fn append_pending_events(
    pending_data: &Option<PendingData>,
    dst: &mut Vec<types::EmittedEvent>,
    skip: usize,
    amount: usize,
    address: Option<ContractAddress>,
    keys: std::collections::HashSet<EventKey>,
) -> bool {
    let pending_block = match pending_data.as_ref() {
        Some(data) => match data.block().await {
            Some(block) => block,
            None => return true,
        },
        None => return true,
    };

    let original_len = dst.len();

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
            if keys.is_empty() {
                return true;
            }

            for ek in &event.keys {
                if keys.contains(ek) {
                    return true;
                }
            }
            false
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

mod types {
    use crate::core::{
        ContractAddress, EventData, EventKey, StarknetBlockHash, StarknetBlockNumber,
        StarknetTransactionHash,
    };
    use serde::Serialize;

    /// Describes an emitted event returned by starknet_getEvents
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    // FIXME - needed?
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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

    impl From<crate::storage::StarknetEmittedEvent> for EmittedEvent {
        fn from(event: crate::storage::StarknetEmittedEvent) -> Self {
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
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    // FIXME - needed?
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct GetEventsResult {
        pub events: Vec<EmittedEvent>,
        pub page_number: usize,
        pub is_last_page: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        types::{EmittedEvent, GetEventsResult},
        *,
    };
    use crate::starkhash;
    use crate::storage::test_utils;
    use jsonrpsee::types::Params;
    use pretty_assertions::assert_eq;

    #[test]
    fn parsing() {
        let optional_present = EventFilter {
            from_block: Some(BlockId::Number(StarknetBlockNumber::new_or_panic(0))),
            to_block: Some(BlockId::Latest),
            address: Some(ContractAddress::new_or_panic(starkhash!("01"))),
            keys: vec![EventKey(starkhash!("02"))],
            page_size: 3,
            page_number: 4,
        };
        let optional_absent = EventFilter {
            from_block: None,
            to_block: None,
            address: None,
            keys: vec![],
            page_size: 5,
            page_number: 6,
        };

        [
            (
                r#"[{"fromBlock":{"block_number":0},"toBlock":"latest","address":"0x1","keys":["0x2"],"page_size":3,"page_number":4}]"#,
                optional_present.clone(),
            ),
            (
                r#"{"filter":{"fromBlock":{"block_number":0},"toBlock":"latest","address":"0x1","keys":["0x2"],"page_size":3,"page_number":4}}"#,
                optional_present
            ),
            (r#"[{"page_size":5,"page_number":6}]"#, optional_absent.clone()),
            (r#"{"filter":{"page_size":5,"page_number":6}}"#, optional_absent),
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
        let (storage, events) = test_utils::setup_test_storage();
        let events = events.into_iter().map(EmittedEvent::from).collect();
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
                page_size: test_utils::NUM_EVENTS,
                page_number: 0,
            },
        };
        let result = get_events(context, input).await.unwrap();

        assert_eq!(
            result,
            GetEventsResult {
                events,
                page_number: 0,
                is_last_page: true,
            }
        );
    }

    #[tokio::test]
    async fn get_events_with_fully_specified_filter() {
        let (context, events) = setup();

        let expected_event = &events[1];
        let input = GetEventsInput {
            filter: EventFilter {
                from_block: Some(expected_event.block_number.unwrap().into()),
                to_block: Some(expected_event.block_number.unwrap().into()),
                address: Some(expected_event.from_address),
                // we're using a key which is present in _all_ events
                keys: vec![EventKey(starkhash!("deadbeef"))],
                page_size: test_utils::NUM_EVENTS,
                page_number: 0,
            },
        };
        let result = get_events(context, input).await.unwrap();

        assert_eq!(
            result,
            GetEventsResult {
                events: vec![expected_event.clone()],
                page_number: 0,
                is_last_page: true,
            }
        );
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
                page_size: test_utils::NUM_EVENTS,
                page_number: 0,
            },
        };
        let result = get_events(context, input).await.unwrap();

        let expected_events = &events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
            ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
        assert_eq!(
            result,
            GetEventsResult {
                events: expected_events.to_vec(),
                page_number: 0,
                is_last_page: true,
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
                page_size: crate::storage::StarknetEventsTable::PAGE_SIZE_LIMIT + 1,
                page_number: 0,
            },
        };
        let error = get_events(context, input).await.unwrap_err();

        assert_eq!(GetEventsError::PageSizeTooBig, error);
    }
}
