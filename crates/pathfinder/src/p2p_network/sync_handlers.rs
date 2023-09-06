//! Sync related data retrieval from storage as requested by other p2p clients

use anyhow::Context;
use p2p_proto::block::{
    BlockBodiesResponse, BlockBodiesResponsePart, BlockHeadersResponse, GetBlockBodies,
    GetBlockHeaders,
};
use p2p_proto::common::{BlockId, Hash};
use pathfinder_common::{BlockNumber, ClassHash};
use pathfinder_storage::{Storage, Transaction};

#[cfg(test)]
mod tests;
pub mod v0;

#[cfg(not(test))]
const MAX_BLOCKS_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_BLOCKS_COUNT: u64 = MAX_COUNT_IN_TESTS;

type BlockHeadersTx = tokio::sync::mpsc::Sender<BlockHeadersResponse>;
type BlockHeadersRx = tokio::sync::mpsc::Receiver<BlockHeadersResponse>;
type BlockBodiesTx = tokio::sync::mpsc::Sender<BlockBodiesResponse>;
type BlockBodiesRx = tokio::sync::mpsc::Receiver<BlockBodiesResponse>;

// TODO check which is more performant:
// 1. retrieve all data from storage, then send it to channel one by one
// 2. retrieve in batches,
// 3. retrieve in batches, don't wait for the previous batch to finish, send with index to rebuild the correct order in the receiver
pub async fn get_headers(
    storage: &Storage,
    request: GetBlockHeaders,
    reply_tx: BlockHeadersTx,
) -> anyhow::Result<()> {
    // TODO For really large requests we might want to use smaller batches
    let responses = spawn_blocking_get(request, storage, headers).await?;

    for response in responses {
        reply_tx
            .send(response)
            .await
            .context("Sending GetBlocks response")?;
    }

    Ok(())
}

pub async fn get_bodies(
    storage: &Storage,
    request: GetBlockBodies,
    reply_tx: BlockBodiesTx,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, bodies).await?;

    for response in responses {
        reply_tx
            .send(response)
            .await
            .context("Sending GetBlocks response")?;
    }

    Ok(())
}

fn headers(
    tx: Transaction<'_>,
    request: GetBlockHeaders,
) -> anyhow::Result<Vec<BlockHeadersResponse>> {
    use p2p_proto::block::Iteration;

    let GetBlockHeaders {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = BlockNumber::new(start.0);
    let mut limit = limit.min(MAX_BLOCKS_COUNT);

    let mut responses = Vec::new();

    while let Some(block_number) = next_block_number {
        if limit == 0 {
            break;
        }

        // 1. Get the block header
        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        responses.push(BlockHeadersResponse {
            id: BlockId(block_number.get()),
            block_part: todo!("header.to_proto()"),
        });

        // 2. Get the signatures for this block
        // TODO we don't have signatures yet

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    Ok(responses)
}

fn bodies(
    tx: Transaction<'_>,
    request: GetBlockBodies,
) -> anyhow::Result<Vec<BlockBodiesResponse>> {
    use p2p_proto::block::Iteration;

    let GetBlockBodies {
        iteration:
            Iteration {
                start,
                direction,
                limit,
                step,
            },
    } = request;

    let mut next_block_number = BlockNumber::new(start.0);
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
            .map(|x| *x)
            .chain(
                state_diff
                    .declared_sierra_classes
                    .keys()
                    .into_iter()
                    .map(|x| ClassHash(x.0)),
            )
            .collect::<Vec<_>>();

        responses.push(BlockBodiesResponse {
            id: BlockId(block_number.get()),
            block_part: todo!("state_diff.to_proto()"),
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

/// Helper function to get a range of classes from storage and put them into messages taking into account the 1MiB encoded message size limit.
///
/// - If N consecutive classes are small enough to fit into a single message, then they will be put in a single message.
/// - If a class is too big to fit into a single message, then it will be split into chunks and each chunk will be put into a separate message.
/// - The function is not greedy, which means that no artificial chunking will be done to fill in the message size limit.
fn classes(
    block_number: BlockNumber,
    mut new_classes: Vec<ClassHash>,
    responses: &mut Vec<BlockBodiesResponse>,
    class_definition_getter: impl Fn(BlockNumber, ClassHash) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<()> {
    /// It's generally safe to assume:
    /// N classes == 22 + 60 * N bytes
    ///
    /// Please see this test for more details:
    /// [`p2p_proto::check_classes_message_overhead`]
    const PER_MESSAGE_OVERHEAD: usize = 22;
    const PER_CLASS_OVERHEAD: usize = 60;
    const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024;
    let mut estimated_message_size = PER_MESSAGE_OVERHEAD;
    let mut classes_for_this_msg = Vec::new();

    while !new_classes.is_empty() {
        // 1. Let's take the next class definition from storage
        // We don't really care about the order as the source is a hash set/map so it's randomized anyway
        let class_hash = new_classes.pop().expect("vec is not empty");

        let compressed_definition = class_definition_getter(block_number, class_hash)?;

        // 2. Let's check if this definition needs to be chunked
        if (PER_MESSAGE_OVERHEAD + PER_CLASS_OVERHEAD + compressed_definition.len())
            < MESSAGE_SIZE_LIMIT
        {
            // 2.A Ok this definition is small enough but we can still exceed the limit for the entire
            // message if we have already accumulated some previous "small" class definitions
            estimated_message_size += PER_CLASS_OVERHEAD + compressed_definition.len();

            if estimated_message_size < MESSAGE_SIZE_LIMIT {
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
                                PER_MESSAGE_OVERHEAD,
                                |acc, (_, compressed_definition)| acc
                                    + PER_CLASS_OVERHEAD
                                    + compressed_definition.len()
                            ) +
                            // Current definition that didn't fit
                            (PER_MESSAGE_OVERHEAD + compressed_definition.len()),
                );
                responses.push(block_bodies_response::take_from_class_definitions(
                    block_number,
                    &mut classes_for_this_msg,
                ));
                // Buffer for accumulating class definitions for a new message is guaranteed to be empty now
                debug_assert!(classes_for_this_msg.is_empty());

                // Now we reset the counter and start over with the current definition that didn't fit
                estimated_message_size = PER_MESSAGE_OVERHEAD;
                classes_for_this_msg.push((class_hash, compressed_definition));
                // --> 1.
            }
        } else {
            // 2.B Ok, so the current definition is too big to fit into a single message

            // But first we need to send what we've already accumulated so far
            if !classes_for_this_msg.is_empty() {
                responses.push(block_bodies_response::take_from_class_definitions(
                    block_number,
                    &mut classes_for_this_msg,
                ));
            }
            // Buffer for accumulating class definitions for a new message is guaranteed to be empty now
            debug_assert!(classes_for_this_msg.is_empty());

            // Now we can take care of the current class definition
            // This class definition is too big, we need to chunk it and send each chunk in a separate message
            const CHUNK_SIZE_LIMIT: usize =
                MESSAGE_SIZE_LIMIT - PER_MESSAGE_OVERHEAD - PER_CLASS_OVERHEAD;

            let mut chunk_iter = compressed_definition.chunks(CHUNK_SIZE_LIMIT).enumerate();
            let chunk_count = chunk_iter.len().try_into()?;

            while let Some((i, chunk)) = chunk_iter.next() {
                let chunk_idx = i
                    .try_into()
                    .expect("chunk_count conversion succeeded, so chunk_count should too");
                // One chunk per message, we don't care if the last chunk is smaller
                // as we don't want to artificially break the next class definition into pieces
                responses.push(block_bodies_response::from_class_definition_chunk(
                    block_number,
                    class_hash,
                    chunk,
                    chunk_count,
                    chunk_idx,
                ));
            }
            // Now we reset the counter and start over with a clean slate
            estimated_message_size = PER_MESSAGE_OVERHEAD;
            // --> 1.
        }
    }

    Ok(())
}

mod block_bodies_response {
    use super::*;

    /// It is assumed that the chunk is not empty
    pub fn from_class_definition_chunk(
        block_number: BlockNumber,
        class_hash: ClassHash,
        chunk: &[u8],
        chunk_count: u32,
        chunk_idx: u32,
    ) -> BlockBodiesResponse {
        use p2p_proto::state::{Class, Classes};
        BlockBodiesResponse {
            id: BlockId(block_number.get()),
            block_part: BlockBodiesResponsePart::Classes(Classes {
                tree_id: 0, // FIXME
                classes: vec![Class {
                    compiled_hash: Hash(class_hash.0),
                    definition: chunk.to_vec(),
                    total_chunks: Some(chunk_count),
                    chunk_count: Some(chunk_idx),
                }],
            }),
        }
    }

    /// Pops all elements from `class_definitions` leaving the vector empty as if it was just `clear()`-ed,
    /// so that later on it can be reused.
    pub fn take_from_class_definitions(
        block_number: BlockNumber,
        class_definitions: &mut Vec<(ClassHash, Vec<u8>)>,
    ) -> BlockBodiesResponse {
        use p2p_proto::state::{Class, Classes};
        let classes = class_definitions
            .drain(..)
            .rev()
            .map(|(class_hash, definition)| Class {
                compiled_hash: Hash(class_hash.0),
                definition,
                total_chunks: None,
                chunk_count: None,
            })
            .collect();
        BlockBodiesResponse {
            id: BlockId(block_number.get()),
            block_part: BlockBodiesResponsePart::Classes(Classes {
                tree_id: 0, // FIXME
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

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: BlockNumber,
    step: p2p_proto::block::Step,
    direction: p2p_proto::block::Direction,
) -> Option<BlockNumber> {
    use p2p_proto::block::Direction::{Backward, Forward};
    match direction {
        Forward => current
            .get()
            .checked_add(step.take_inner())
            .and_then(BlockNumber::new),
        Backward => current
            .get()
            .checked_sub(step.take_inner())
            .and_then(BlockNumber::new),
    }
}
