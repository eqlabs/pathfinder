use anyhow::Context;
use futures::channel::mpsc;
use futures::SinkExt;
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockBodyMessage, BlockHeadersRequest,
    BlockHeadersResponse, BlockHeadersResponsePart,
};
use p2p_proto::common::{BlockId, BlockNumberOrHash, Direction, Fin, Hash, Iteration, Step};
use p2p_proto::consts::{
    CLASSES_MESSAGE_OVERHEAD, MAX_HEADERS_PER_MESSAGE, MAX_PARTS_PER_CLASS, MESSAGE_SIZE_LIMIT,
    PER_CLASS_OVERHEAD,
};
use p2p_proto::event::{Events, EventsRequest, EventsResponse, EventsResponseKind, TxnEvents};
use p2p_proto::receipt::{Receipts, ReceiptsRequest, ReceiptsResponse, ReceiptsResponseKind};
use p2p_proto::transaction::{
    Transactions, TransactionsRequest, TransactionsResponse, TransactionsResponseKind,
};
use pathfinder_common::{BlockHash, BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::Storage;
use pathfinder_storage::Transaction;
use tokio::sync::mpsc as tokio_mpsc;

pub mod conv;
#[cfg(test)]
mod tests;

use conv::ToProto;

#[cfg(not(test))]
const MAX_BLOCKS_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_BLOCKS_COUNT: u64 = MAX_COUNT_IN_TESTS;

const _: () = assert!(
    MAX_BLOCKS_COUNT <= MAX_HEADERS_PER_MESSAGE as u64,
    "All requested block headers, limited up to MAX_BLOCKS_COUNT should fit into one reply"
);

const _: () = assert!(
    MAX_PARTS_PER_CLASS as u64 <= MAX_BLOCKS_COUNT,
    "It does not make sense to accept classes that comprise more parts than the node can accept"
);

pub async fn get_headers(
    storage: Storage,
    request: BlockHeadersRequest,
    mut tx: mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<()> {
    let response = spawn_blocking_get(request, storage, blocking::get_headers).await?;
    tx.send(response).await.context("Sending response")
}

// TODO consider batching db ops instead doing all in bulk if it's more performant
pub async fn get_bodies(
    storage: Storage,
    request: BlockBodiesRequest,
    tx: tokio_mpsc::Sender<BlockBodiesResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_bodies).await?;
    send(tx, responses).await
}

pub async fn get_transactions(
    storage: Storage,
    request: TransactionsRequest,
    tx: tokio_mpsc::Sender<TransactionsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_transactions).await?;
    send(tx, responses).await
}

pub async fn get_receipts(
    storage: Storage,
    request: ReceiptsRequest,
    tx: tokio_mpsc::Sender<ReceiptsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_receipts).await?;
    send(tx, responses).await
}

pub async fn get_events(
    storage: Storage,
    request: EventsRequest,
    tx: tokio_mpsc::Sender<EventsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_events).await?;
    send(tx, responses).await
}

pub(crate) mod blocking {
    use super::*;

    pub(crate) fn get_headers(
        tx: Transaction<'_>,
        request: BlockHeadersRequest,
    ) -> anyhow::Result<BlockHeadersResponse> {
        let parts = iterate(tx, request.iteration, get_header)?;
        Ok(BlockHeadersResponse { parts })
    }

    pub(crate) fn get_bodies(
        tx: Transaction<'_>,
        request: BlockBodiesRequest,
    ) -> anyhow::Result<Vec<BlockBodiesResponse>> {
        iterate(tx, request.iteration, get_body)
    }

    pub(crate) fn get_transactions(
        tx: Transaction<'_>,
        request: TransactionsRequest,
    ) -> anyhow::Result<Vec<TransactionsResponse>> {
        iterate(tx, request.iteration, get_transactions_for_block)
    }

    pub(crate) fn get_receipts(
        tx: Transaction<'_>,
        request: ReceiptsRequest,
    ) -> anyhow::Result<Vec<ReceiptsResponse>> {
        iterate(tx, request.iteration, get_receipts_for_block)
    }

    pub(crate) fn get_events(
        tx: Transaction<'_>,
        request: EventsRequest,
    ) -> anyhow::Result<Vec<EventsResponse>> {
        iterate(tx, request.iteration, get_events_for_block)
    }
}

fn get_header(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    parts: &mut Vec<BlockHeadersResponsePart>,
) -> anyhow::Result<bool> {
    if let Some(header) = tx.block_header(block_number.into())? {
        parts.push(BlockHeadersResponsePart::Header(Box::new(
            header.to_proto(),
        )));
        parts.push(BlockHeadersResponsePart::Fin(Fin::ok()));

        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(fake::Dummy))]
enum ClassId {
    Cairo(ClassHash),
    Sierra(SierraHash, CasmHash),
}

impl ClassId {
    pub fn into_dto(self) -> (Hash, Option<Hash>) {
        match self {
            ClassId::Cairo(class_hash) => (Hash(class_hash.0), None),
            ClassId::Sierra(sierra_hash, casm_hash) => {
                (Hash(sierra_hash.0), Some(Hash(casm_hash.0)))
            }
        }
    }

    pub fn class_hash(&self) -> ClassHash {
        match self {
            ClassId::Cairo(class_hash) => *class_hash,
            ClassId::Sierra(sierra_hash, _) => ClassHash(sierra_hash.0),
        }
    }
}

fn get_body(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<BlockBodiesResponse>,
) -> anyhow::Result<bool> {
    let Some(state_diff) = tx.state_update(block_number.into())? else {
        return Ok(false);
    };

    let new_classes = state_diff
        .declared_cairo_classes
        .iter()
        .map(|&class_hash| ClassId::Cairo(class_hash))
        .chain(
            state_diff
                .declared_sierra_classes
                .iter()
                .map(|(&sierra_hash, &casm_hash)| ClassId::Sierra(sierra_hash, casm_hash)),
        )
        .collect::<Vec<_>>();
    let block_hash = state_diff.block_hash;
    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    responses.push(BlockBodiesResponse {
        id,
        body_message: BlockBodyMessage::Diff(state_diff.to_proto()),
    });

    let get_compressed_definition =
        |block_number: BlockNumber, class_hash| -> anyhow::Result<Vec<u8>> {
            let definition = tx
                .compressed_class_definition_at(block_number.into(), class_hash)?
                .ok_or_else(|| {
                    anyhow::anyhow!("Class {} not found at block {}", class_hash, block_number)
                })?;
            Ok(definition)
        };

    classes(
        block_number,
        block_hash,
        new_classes,
        responses,
        get_compressed_definition,
    )?;

    responses.push(BlockBodiesResponse {
        id,
        body_message: BlockBodyMessage::Fin(Fin::ok()),
    });
    Ok(true)
}

fn get_transactions_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<TransactionsResponse>,
) -> anyhow::Result<bool> {
    let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    responses.push(TransactionsResponse {
        id,
        kind: TransactionsResponseKind::Transactions(Transactions {
            items: txn_data
                .into_iter()
                .map(|(txn, _)| pathfinder_common::transaction::Transaction::from(txn).to_proto())
                .collect(),
        }),
    });
    responses.push(TransactionsResponse {
        id,
        kind: TransactionsResponseKind::Fin(Fin::ok()),
    });

    Ok(true)
}

fn get_receipts_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<ReceiptsResponse>,
) -> anyhow::Result<bool> {
    let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    responses.push(ReceiptsResponse {
        id,
        kind: ReceiptsResponseKind::Receipts(Receipts {
            items: txn_data.into_iter().map(ToProto::to_proto).collect(),
        }),
    });
    responses.push(ReceiptsResponse {
        id,
        kind: ReceiptsResponseKind::Fin(Fin::ok()),
    });

    Ok(true)
}

fn get_events_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<EventsResponse>,
) -> anyhow::Result<bool> {
    let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let items = txn_data
        .into_iter()
        .map(|(_, r)| TxnEvents {
            events: r.events.into_iter().map(ToProto::to_proto).collect(),
            transaction_hash: Hash(r.transaction_hash.0),
        })
        .collect::<Vec<_>>();

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    responses.push(EventsResponse {
        id,
        kind: EventsResponseKind::Events(Events { items }),
    });
    responses.push(EventsResponse {
        id,
        kind: EventsResponseKind::Fin(Fin::ok()),
    });

    Ok(true)
}

/// `block_handler` returns Ok(true) if the iteration should continue and is
/// responsible for delimiting block data with `Fin::ok()` marker.
fn iterate<T: From<Fin>>(
    tx: Transaction<'_>,
    iteration: Iteration,
    block_handler: impl Fn(&Transaction<'_>, BlockNumber, &mut Vec<T>) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<T>> {
    let Iteration {
        start,
        direction,
        limit,
        step,
    } = iteration;

    if limit == 0 {
        return Ok(vec![T::from(Fin::ok())]);
    }

    let mut block_number = match get_start_block_number(start, &tx)? {
        Some(x) => x,
        None => {
            return Ok(vec![T::from(Fin::unknown())]);
        }
    };

    let (limit, mut ending_marker) = if limit > MAX_BLOCKS_COUNT {
        (MAX_BLOCKS_COUNT, Some(Fin::too_much()))
    } else {
        (limit, None)
    };

    let mut responses = Vec::new();

    for i in 0..limit {
        if block_handler(&tx, block_number, &mut responses)? {
            // Block data retrieved successfully, `block_handler` should add `Fin::ok()` marker on its own
        } else {
            // No such block
            ending_marker = Some(Fin::unknown());
            break;
        }

        if i < limit - 1 {
            block_number = match get_next_block_number(block_number, step, direction) {
                Some(x) => x,
                None => {
                    // Out of range block number value
                    ending_marker = Some(Fin::unknown());
                    break;
                }
            };
        }
    }

    if let Some(end) = ending_marker {
        responses.push(T::from(end));
    }

    Ok(responses)
}

fn get_start_block_number(
    start: BlockNumberOrHash,
    tx: &Transaction<'_>,
) -> Result<Option<BlockNumber>, anyhow::Error> {
    Ok(match start {
        BlockNumberOrHash::Number(n) => BlockNumber::new(n),
        BlockNumberOrHash::Hash(h) => tx.block_id(BlockHash(h.0).into())?.map(|(n, _)| n),
    })
}

/// Helper function to get a range of classes from storage and put them into messages taking into account the 1MiB encoded message size limit.
///
/// - If N consecutive classes are small enough to fit into a single message, then they will be put in a single message.
/// - If a class is too big to fit into a single message, then it will be split into chunks and each chunk will be put into a separate message.
/// - The function is not greedy, which means that no artificial chunking will be done to fill in the message size limit.
/// - `class_definition_getter` assumes that the class definition should always be available in storage, otherwise there is a problem with
///   the database itself (e.g. it's inconsistent/corrupted, inaccessible, etc.) which is a fatal error
fn classes(
    block_number: BlockNumber,
    block_hash: BlockHash,
    new_classes: Vec<ClassId>,
    responses: &mut Vec<BlockBodiesResponse>,
    mut class_definition_getter: impl FnMut(BlockNumber, ClassHash) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut estimated_message_size = CLASSES_MESSAGE_OVERHEAD;
    let mut classes_for_this_msg: Vec<(ClassId, Vec<u8>)> = Vec::new();
    let new_classes = new_classes.into_iter();

    // 1. Let's take the next class definition from storage
    for class_id in new_classes {
        let compressed_definition = class_definition_getter(block_number, class_id.class_hash())?;

        // 2. Let's check if this definition needs to be chunked
        if (CLASSES_MESSAGE_OVERHEAD + PER_CLASS_OVERHEAD + compressed_definition.len())
            <= MESSAGE_SIZE_LIMIT
        {
            // 2.A Ok this definition is small enough but we can still exceed the limit for the entire
            // message if we have already accumulated some previous "small" class definitions
            estimated_message_size += PER_CLASS_OVERHEAD + compressed_definition.len();

            if estimated_message_size <= MESSAGE_SIZE_LIMIT {
                // 2.A.A Ok, it fits, let's add it to the message but don't send the message yet
                classes_for_this_msg.push((class_id, compressed_definition));
                // --> 1.
            } else {
                // 2.A.B Current definition would be too much for the current message, so send what we have accumulated so far
                debug_assert!(!classes_for_this_msg.is_empty());
                debug_assert_eq!(
                    estimated_message_size,
                    // What we have accumulated so far
                    classes_for_this_msg.iter().fold(
                                CLASSES_MESSAGE_OVERHEAD,
                                |acc, (_, x)| acc
                                    + PER_CLASS_OVERHEAD
                                    + x.len()
                            ) +
                            // Current definition that didn't fit
                            (PER_CLASS_OVERHEAD + compressed_definition.len()),
                );
                responses.push(block_bodies_response::take_from_class_definitions(
                    block_number,
                    block_hash,
                    &mut classes_for_this_msg,
                ));
                // Buffer for accumulating class definitions for a new message is guaranteed to be empty now
                debug_assert!(classes_for_this_msg.is_empty());

                // Now we reset the counter and start over with the current definition that didn't fit
                estimated_message_size =
                    CLASSES_MESSAGE_OVERHEAD + PER_CLASS_OVERHEAD + compressed_definition.len();
                classes_for_this_msg.push((class_id, compressed_definition));
                // --> 1.
            }
        } else {
            // 2.B Ok, so the current definition is too big to fit into a single message

            // But first we need to send what we've already accumulated so far
            if !classes_for_this_msg.is_empty() {
                responses.push(block_bodies_response::take_from_class_definitions(
                    block_number,
                    block_hash,
                    &mut classes_for_this_msg,
                ));
            }
            // Buffer for accumulating class definitions for a new message is guaranteed to be empty now
            debug_assert!(classes_for_this_msg.is_empty());

            // Now we can take care of the current class definition
            // This class definition is too big, we need to chunk it and send each chunk in a separate message
            const CHUNK_SIZE_LIMIT: usize =
                MESSAGE_SIZE_LIMIT - CLASSES_MESSAGE_OVERHEAD - PER_CLASS_OVERHEAD;

            let chunk_iter = compressed_definition.chunks(CHUNK_SIZE_LIMIT).enumerate();
            let chunk_count = chunk_iter.len().try_into()?;

            for (i, chunk) in chunk_iter {
                let chunk_idx = i
                    .try_into()
                    .expect("chunk_count conversion succeeded, so chunk_idx should too");
                // One chunk per message, we don't care if the last chunk is smaller
                // as we don't want to artificially break the next class definition into pieces
                responses.push(block_bodies_response::from_class_definition_part(
                    block_number,
                    block_hash,
                    class_id,
                    chunk,
                    chunk_count,
                    chunk_idx,
                ));
            }
            // Now we reset the counter and start over with a clean slate
            estimated_message_size = CLASSES_MESSAGE_OVERHEAD;
            // --> 1.
        }
    }

    // 3. Send the remaining accumulated classes if there are any
    if !classes_for_this_msg.is_empty() {
        responses.push(block_bodies_response::take_from_class_definitions(
            block_number,
            block_hash,
            &mut classes_for_this_msg,
        ));
    }
    debug_assert!(classes_for_this_msg.is_empty());

    Ok(())
}

mod block_bodies_response {
    use super::*;
    use p2p_proto::block::BlockBodyMessage;

    /// It is assumed that the chunk is not empty
    pub(super) fn from_class_definition_part(
        block_number: BlockNumber,
        block_hash: BlockHash,
        class_id: ClassId,
        part: &[u8],
        parts_count: u32,
        part_idx: u32,
    ) -> BlockBodiesResponse {
        use p2p_proto::state::{Class, Classes};
        let (compiled_hash, casm_hash) = class_id.into_dto();
        BlockBodiesResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            body_message: BlockBodyMessage::Classes(Classes {
                domain: 0, // FIXME
                classes: vec![Class {
                    compiled_hash,
                    definition: part.to_vec(),
                    casm_hash,
                    total_parts: Some(parts_count),
                    part_num: Some(part_idx),
                }],
            }),
        }
    }

    /// Pops all elements from `class_definitions` leaving the vector empty as if it was just `clear()`-ed,
    /// so that later on it can be reused.
    pub(super) fn take_from_class_definitions(
        block_number: BlockNumber,
        block_hash: BlockHash,
        class_definitions: &mut Vec<(ClassId, Vec<u8>)>,
    ) -> BlockBodiesResponse {
        use p2p_proto::state::{Class, Classes};
        let classes = class_definitions
            .drain(..)
            .map(|(class_id, definition)| {
                let (compiled_hash, casm_hash) = class_id.into_dto();

                Class {
                    compiled_hash,
                    definition,
                    casm_hash,
                    total_parts: None,
                    part_num: None,
                }
            })
            .collect();
        BlockBodiesResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            body_message: BlockBodyMessage::Classes(Classes {
                domain: 0, // FIXME
                classes,
            }),
        }
    }
}

async fn spawn_blocking_get<Request, Response, Getter>(
    request: Request,
    storage: Storage,
    getter: Getter,
) -> anyhow::Result<Response>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request) -> anyhow::Result<Response> + Send + 'static,
{
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;
        getter(tx, request)
    })
    .await
    .context("Database read panic or shutting down")?
}

async fn send<T>(tx: tokio_mpsc::Sender<T>, seq: Vec<T>) -> anyhow::Result<()>
where
    T: Send + 'static,
    tokio::sync::mpsc::error::SendError<T>: Sync,
{
    for elem in seq {
        tx.send(elem).await.context("Sending response")?;
    }

    Ok(())
}

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: BlockNumber,
    step: Step,
    direction: Direction,
) -> Option<BlockNumber> {
    match direction {
        Direction::Forward => current
            .get()
            .checked_add(step.into_inner())
            .and_then(BlockNumber::new),
        Direction::Backward => current
            .get()
            .checked_sub(step.into_inner())
            .and_then(BlockNumber::new),
    }
}
