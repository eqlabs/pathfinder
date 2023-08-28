//! Sync related data retrieval from storage as requested by other p2p clients

use super::conv::ToProto;
use anyhow::Context;
use p2p_proto::block::GetBlocksResponse;
use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_storage::{Storage, Transaction};

pub mod v0;

const MAX_BLOCKS_COUNT: u64 = 100;

type GetBlocksResponseTx = tokio::sync::mpsc::Sender<GetBlocksResponse>;
type GetBlocksResponseRx = tokio::sync::mpsc::Receiver<GetBlocksResponse>;

// TODO check which is more performant:
// 1. retrieve all data from storage, then send it to channel one by one
// 2. retrieve in batches,
// 3. retrieve in batches, don't wait for the previous batch to finish, send with index to rebuild the correct order in the receiver
pub async fn get_blocks(
    request: p2p_proto::block::GetBlocks,
    storage: &Storage,
    reply_tx: GetBlocksResponseTx,
) -> anyhow::Result<()> {
    // TODO For really large requests we might want to use smaller batches
    let responses = spawn_blocking_get(request, storage, headers_and_diffs).await?;

    for response in responses {
        reply_tx
            .send(response)
            .await
            .context("Sending GetBlocks response")?;
    }

    Ok(())
}

fn headers_and_diffs(
    tx: Transaction<'_>,
    request: p2p_proto::block::GetBlocks,
) -> anyhow::Result<Vec<GetBlocksResponse>> {
    use p2p_proto::common::BlockId::{Hash, HashAndHeight, Height};
    use pathfinder_storage::BlockId;

    let p2p_proto::block::GetBlocks {
        start,
        direction,
        limit,
        skip,
        step,
    } = request;

    // step 0 means the step field was actually missing or
    // the client does not know what it's actually doing :P
    let step = if step == 0 { 1 } else { step };

    // Starting "by hash" with skip > 0 is inefficient as it will fail if the
    // start lookup fails even if the target block is available. ¯\_(ツ)_/¯
    let mut next_block_number = match start {
        Hash(hash) => tx
            .block_id(BlockId::Hash(BlockHash(hash.0)))
            .context("Retrieving start block id")?
            .and_then(|(number, _)| get_next_block_number(number, skip, direction)),
        Height(height) => BlockNumber::new(height)
            .and_then(|number| get_next_block_number(number, skip, direction)),
        HashAndHeight(hash, height) => match BlockNumber::new(height) {
            Some(number) => tx
                .block_id(number.into())
                .context("Retrieving start block id")?
                .and_then(|(number, expected_hash)| {
                    if expected_hash == BlockHash(hash.0) {
                        get_next_block_number(number, skip, direction)
                    } else {
                        None
                    }
                }),
            None => None,
        },
    };

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

        responses.push(GetBlocksResponse::BlockHeader(header.to_proto()));

        let Some(diff) = tx.state_update(block_number.into())? else {
            // No such block
            break;
        };

        responses.push(GetBlocksResponse::StateDiff(diff.to_proto()));

        limit -= 1;
        next_block_number = get_next_block_number(block_number, step, request.direction);
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
    step: u64,
    direction: p2p_proto::block::Direction,
) -> Option<BlockNumber> {
    use p2p_proto::block::Direction::{Backward, Forward};
    match direction {
        Forward => current.get().checked_add(step).and_then(BlockNumber::new),
        Backward => current.get().checked_sub(step).and_then(BlockNumber::new),
    }
}
