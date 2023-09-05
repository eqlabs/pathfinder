//! Sync related data retrieval from storage as requested by other p2p clients

use super::conv::ToProto;
use anyhow::Context;
use p2p_proto::block::{
    BlockBodiesResponse, BlockBodiesResponsePart, BlockHeadersResponse, BlockHeadersResponsePart,
    GetBlockBodies, GetBlockHeaders,
};
use p2p_proto::common::BlockId;
use pathfinder_common::{BlockHash, BlockNumber};
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

        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        responses.push(BlockHeadersResponse {
            id: BlockId(block_number.get()),
            block_part: todo!("header.to_proto()"),
        });

        // TODO signatures

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

        let Some(state_diff) = tx.state_update(block_number.into())? else {
            // No such block
            break;
        };

        responses.push(BlockBodiesResponse {
            id: BlockId(block_number.get()),
            block_part: todo!("state_diff.to_proto()"),
        });

        // TODO get those classes

        // TODO
        // We're not sending the proof for the block, we're not storing it right now

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, direction);
    }

    Ok(responses)
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
