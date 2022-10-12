use crate::core::{BlockId, ContractAddress, StarknetBlockNumber};
use crate::rpc::v02::RpcContext;
use crate::state::PendingData;
use crate::storage::EventFilterError;
use crate::storage::{StarknetBlocksTable, StarknetEventsTable};
use anyhow::Context;
use tokio::task::JoinHandle;
// FIXME
use crate::rpc::v01::types::{
    reply::{EmittedEvent, GetEventsResult},
    request::EventFilter,
};

crate::rpc::error::generate_rpc_error_subset!(
    GetEventsError: BlockNotFound,
    PageSizeTooBig,
    InvalidContinuationToken
);

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetEventsInput {
    filter: EventFilter,
}

/// Returns events matching the specified filter
pub async fn get_events(
    context: RpcContext,
    input: GetEventsInput,
) -> Result<GetEventsResult, GetEventsError> {
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
            return Ok(GetEventsResult {
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
            return Ok(GetEventsResult {
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
            if let Some(_) = e.downcast_ref::<EventFilterError>() {
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
            GetEventsResult {
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
    dst: &mut Vec<EmittedEvent>,
    skip: usize,
    amount: usize,
    address: Option<ContractAddress>,
    keys: std::collections::HashSet<crate::core::EventKey>,
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
        .map(
            |(event, tx_hash)| crate::rpc::v01::types::reply::EmittedEvent {
                data: event.data.clone(),
                keys: event.keys.clone(),
                from_address: event.from_address,
                block_hash: None,
                block_number: None,
                transaction_hash: tx_hash,
            },
        );

    dst.extend(pending_events);
    let is_last_page = dst.len() <= (original_len + amount);
    if !is_last_page {
        dst.pop();
    }

    is_last_page
}
