use anyhow::Context;
use p2p_proto_v1::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockBodyMessage, BlockHeadersRequest,
    BlockHeadersResponse, BlockHeadersResponsePart,
};
use p2p_proto_v1::common::{BlockId, BlockNumberOrHash, Direction, Hash, Iteration, Step};
use p2p_proto_v1::consts::{
    CLASSES_MESSAGE_OVERHEAD, MAX_HEADERS_PER_MESSAGE, MESSAGE_SIZE_LIMIT, PER_CLASS_OVERHEAD,
};
use p2p_proto_v1::event::{Events, EventsRequest, EventsResponse, Responses, TxnEvents};
use p2p_proto_v1::receipt::{Receipts, ReceiptsRequest, ReceiptsResponse, ReceiptsResponseKind};
use p2p_proto_v1::transaction::{
    Transactions, TransactionsRequest, TransactionsResponse, TransactionsResponseKind,
};
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use pathfinder_storage::Storage;
use pathfinder_storage::Transaction;
use tokio::sync::mpsc;

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

// TODO consider batching db ops instead doing all in bulk if it's more performant
pub async fn get_headers(
    storage: &Storage,
    request: BlockHeadersRequest,
    tx: mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, headers).await?;
    send(tx, responses).await
}

pub async fn get_bodies(
    storage: &Storage,
    request: BlockBodiesRequest,
    tx: mpsc::Sender<BlockBodiesResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, bodies).await?;
    send(tx, responses).await
}

pub async fn get_transactions(
    storage: &Storage,
    request: TransactionsRequest,
    tx: mpsc::Sender<TransactionsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, transactions).await?;
    send(tx, responses).await
}

pub async fn get_receipts(
    storage: &Storage,
    request: ReceiptsRequest,
    tx: mpsc::Sender<ReceiptsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, receipts).await?;
    send(tx, responses).await
}

pub async fn get_events(
    storage: &Storage,
    request: EventsRequest,
    tx: mpsc::Sender<EventsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, events).await?;
    send(tx, responses).await
}

pub(crate) fn headers(
    tx: Transaction<'_>,
    request: BlockHeadersRequest,
) -> anyhow::Result<Vec<BlockHeadersResponse>> {
    let BlockHeadersRequest {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = get_start_block_number(start, &tx)?;
    let mut limit = limit.min(MAX_BLOCKS_COUNT);
    let mut parts = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        // 1. Get the block header
        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        parts.push(BlockHeadersResponsePart::Header(Box::new(
            header.to_proto(),
        )));

        // 2. Get the signatures for this block
        // TODO we don't have signatures yet

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    let responses = parts
        .chunks(MAX_HEADERS_PER_MESSAGE)
        .map(|parts| BlockHeadersResponse {
            parts: parts.to_vec(),
        })
        .collect();

    Ok(responses)
}

fn bodies(
    tx: Transaction<'_>,
    request: BlockBodiesRequest,
) -> anyhow::Result<Vec<BlockBodiesResponse>> {
    let BlockBodiesRequest {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = get_start_block_number(start, &tx)?;
    let mut limit = limit.min(MAX_BLOCKS_COUNT);
    let mut responses = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        // 1. Get the state diff for the block
        let Some(state_diff) = tx.state_update(block_number.into())? else {
            // No such block
            break;
        };

        let new_classes = state_diff
            .declared_cairo_classes
            .iter()
            .copied()
            .chain(
                state_diff
                    .declared_sierra_classes
                    .keys()
                    .map(|x| ClassHash(x.0)),
            )
            .collect::<Vec<_>>();

        let block_hash = state_diff.block_hash;
        responses.push(BlockBodiesResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            body_message: BlockBodyMessage::Diff(state_diff.to_proto()),
        });

        // 2. Get the newly declared classes in this block
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
            &mut responses,
            get_compressed_definition,
        )?;

        // 3. Get the proof for block
        // FIXME
        // We're not sending the proof for the block, as we're not storing it right now

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    Ok(responses)
}

pub(crate) fn transactions(
    tx: Transaction<'_>,
    request: TransactionsRequest,
) -> anyhow::Result<Vec<TransactionsResponse>> {
    let TransactionsRequest {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = get_start_block_number(start, &tx)?;
    let mut limit = limit.min(MAX_BLOCKS_COUNT);
    let mut responses = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
            break;
        };

        let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
            break;
        };

        responses.push(TransactionsResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            kind: TransactionsResponseKind::Transactions(Transactions {
                items: txn_data
                    .into_iter()
                    .map(|(txn, _)| {
                        pathfinder_common::transaction::Transaction::from(txn).to_proto()
                    })
                    .collect(),
            }),
        });

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    Ok(responses)
}

pub(crate) fn receipts(
    tx: Transaction<'_>,
    request: ReceiptsRequest,
) -> anyhow::Result<Vec<ReceiptsResponse>> {
    let ReceiptsRequest {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = get_start_block_number(start, &tx)?;
    let mut limit = limit.min(MAX_BLOCKS_COUNT);
    let mut responses = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
            break;
        };

        let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
            break;
        };

        responses.push(ReceiptsResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            kind: ReceiptsResponseKind::Receipts(Receipts {
                items: txn_data.into_iter().map(ToProto::to_proto).collect(),
            }),
        });

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    Ok(responses)
}

pub(crate) fn events(
    tx: Transaction<'_>,
    request: EventsRequest,
) -> anyhow::Result<Vec<EventsResponse>> {
    let EventsRequest {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = get_start_block_number(start, &tx)?;
    let mut limit = limit.min(MAX_BLOCKS_COUNT);
    let mut responses = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        let Some((_, block_hash)) = tx.block_id(block_number.into())? else {
            break;
        };

        let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
            break;
        };

        let items = txn_data
            .into_iter()
            .map(|(_, r)| TxnEvents {
                events: r.events.into_iter().map(ToProto::to_proto).collect(),
                transaction_hash: Hash(r.transaction_hash.0),
            })
            .collect::<Vec<_>>();

        responses.push(EventsResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            responses: Responses::Events(Events { items }),
        });

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
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
    new_classes: Vec<ClassHash>,
    responses: &mut Vec<BlockBodiesResponse>,
    mut class_definition_getter: impl FnMut(BlockNumber, ClassHash) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut estimated_message_size = CLASSES_MESSAGE_OVERHEAD;
    let mut classes_for_this_msg: Vec<(ClassHash, Vec<u8>)> = Vec::new();
    let new_classes = new_classes.into_iter();

    // 1. Let's take the next class definition from storage
    for class_hash in new_classes {
        let compressed_definition = class_definition_getter(block_number, class_hash)?;

        // 2. Let's check if this definition needs to be chunked
        if (CLASSES_MESSAGE_OVERHEAD + PER_CLASS_OVERHEAD + compressed_definition.len())
            <= MESSAGE_SIZE_LIMIT
        {
            // 2.A Ok this definition is small enough but we can still exceed the limit for the entire
            // message if we have already accumulated some previous "small" class definitions
            estimated_message_size += PER_CLASS_OVERHEAD + compressed_definition.len();

            if estimated_message_size <= MESSAGE_SIZE_LIMIT {
                // 2.A.A Ok, it fits, let's add it to the message but don't send the message yet
                classes_for_this_msg.push((class_hash, compressed_definition));
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
                classes_for_this_msg.push((class_hash, compressed_definition));
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
                    class_hash,
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
    use p2p_proto_v1::block::BlockBodyMessage;

    use super::*;

    /// It is assumed that the chunk is not empty
    pub fn from_class_definition_part(
        block_number: BlockNumber,
        block_hash: BlockHash,
        class_hash: ClassHash,
        part: &[u8],
        parts_count: u32,
        part_idx: u32,
    ) -> BlockBodiesResponse {
        use p2p_proto_v1::state::{Class, Classes};
        BlockBodiesResponse {
            id: Some(BlockId {
                number: block_number.get(),
                hash: Hash(block_hash.0),
            }),
            body_message: BlockBodyMessage::Classes(Classes {
                domain: 0, // FIXME
                classes: vec![Class {
                    compiled_hash: Hash(class_hash.0),
                    definition: part.to_vec(),
                    total_parts: Some(parts_count),
                    part_num: Some(part_idx),
                }],
            }),
        }
    }

    /// Pops all elements from `class_definitions` leaving the vector empty as if it was just `clear()`-ed,
    /// so that later on it can be reused.
    pub fn take_from_class_definitions(
        block_number: BlockNumber,
        block_hash: BlockHash,
        class_definitions: &mut Vec<(ClassHash, Vec<u8>)>,
    ) -> BlockBodiesResponse {
        use p2p_proto_v1::state::{Class, Classes};
        let classes = class_definitions
            .drain(..)
            .map(|(class_hash, definition)| Class {
                compiled_hash: Hash(class_hash.0),
                definition,
                total_parts: None,
                part_num: None,
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
    storage: &Storage,
    getter: Getter,
) -> anyhow::Result<Response>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request) -> anyhow::Result<Response> + Send + 'static,
{
    let storage = storage.clone();
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

async fn send<T>(tx: mpsc::Sender<T>, seq: Vec<T>) -> anyhow::Result<()>
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
            .checked_add(step.take_inner())
            .and_then(BlockNumber::new),
        Direction::Backward => current
            .get()
            .checked_sub(step.take_inner())
            .and_then(BlockNumber::new),
    }
}
