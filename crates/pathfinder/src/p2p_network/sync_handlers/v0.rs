use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use pathfinder_storage::{Storage, Transaction};

pub(crate) mod conv;
#[cfg(test)]
mod tests;

pub(crate) mod conv;
#[cfg(test)]
mod tests;

#[cfg(not(test))]
const MAX_HEADERS_COUNT: u64 = 1000;
#[cfg(not(test))]
const MAX_BODIES_COUNT: u64 = 100;
#[cfg(not(test))]
const MAX_STATE_UPDATES_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_HEADERS_COUNT: u64 = MAX_COUNT_IN_TESTS;
#[cfg(test)]
const MAX_BODIES_COUNT: u64 = MAX_COUNT_IN_TESTS;
#[cfg(test)]
const MAX_STATE_UPDATES_COUNT: u64 = MAX_COUNT_IN_TESTS;

pub async fn get_block_headers(
    request: p2p_proto_v0::sync::GetBlockHeaders,
    storage: &Storage,
) -> anyhow::Result<p2p_proto_v0::sync::BlockHeaders> {
    spawn_blocking_get(request, storage, block_headers).await
}

pub async fn get_block_bodies(
    request: p2p_proto_v0::sync::GetBlockBodies,
    storage: &Storage,
) -> anyhow::Result<p2p_proto_v0::sync::BlockBodies> {
    spawn_blocking_get(request, storage, block_bodies).await
}

pub async fn get_state_diffs(
    request: p2p_proto_v0::sync::GetStateDiffs,
    storage: &Storage,
) -> anyhow::Result<p2p_proto_v0::sync::StateDiffs> {
    spawn_blocking_get(request, storage, state_diffs).await
}

pub async fn get_classes(
    request: p2p_proto_v0::sync::GetClasses,
    storage: &Storage,
) -> anyhow::Result<p2p_proto_v0::sync::Classes> {
    spawn_blocking_get(request, storage, classes).await
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

fn block_headers(
    tx: Transaction<'_>,
    request: p2p_proto_v0::sync::GetBlockHeaders,
) -> anyhow::Result<p2p_proto_v0::sync::BlockHeaders> {
    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number = match BlockNumber::new(request.start_block) {
        Some(n) => Some(n),
        None => anyhow::bail!(
            "Unsupported block number value: {} > i64::MAX",
            request.start_block
        ),
    };

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        let transaction_count = tx
            .transaction_count(block_number.into())?
            .try_into()
            .context("Number of transactions exceeds 32 bits")?;

        let event_count = tx.event_count_for_block(block_number.into())?;

        headers.push(conv::header::from(
            header,
            transaction_count,
            event_count.try_into()?,
        ));

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto_v0::sync::BlockHeaders { headers })
}

fn block_bodies(
    tx: Transaction<'_>,
    request: p2p_proto_v0::sync::GetBlockBodies,
) -> anyhow::Result<p2p_proto_v0::sync::BlockBodies> {
    let mut count = std::cmp::min(request.count, MAX_BODIES_COUNT);
    let mut block_bodies = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let transactions_and_receipts = match tx.transaction_data_for_block(block_number.into())? {
            Some(x) if !x.is_empty() => x,
            // No such block
            Some(_) | None => break,
        };

        let (transactions, receipts) = transactions_and_receipts
            .into_iter()
            .map(conv::body::from)
            .unzip();

        block_bodies.push(p2p_proto_v0::common::BlockBody {
            transactions,
            receipts,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto_v0::sync::BlockBodies { block_bodies })
}

fn state_diffs(
    tx: Transaction<'_>,
    request: p2p_proto_v0::sync::GetStateDiffs,
) -> anyhow::Result<p2p_proto_v0::sync::StateDiffs> {
    let mut count = std::cmp::min(request.count, MAX_STATE_UPDATES_COUNT);
    let mut block_state_updates = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(state_update) = tx.state_update(block_number.into())? else {
            // No such state update, shouldn't happen with a single source of truth in L2...
            break;
        };

        block_state_updates.push(p2p_proto_v0::sync::BlockStateUpdateWithHash {
            block_hash: state_update.block_hash.0,
            state_commitment: state_update.state_commitment.0,
            parent_state_commitment: state_update.parent_state_commitment.0,
            state_update: conv::state_update::from(state_update),
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto_v0::sync::StateDiffs {
        block_state_updates,
    })
}

fn classes(
    tx: Transaction<'_>,
    request: p2p_proto_v0::sync::GetClasses,
) -> anyhow::Result<p2p_proto_v0::sync::Classes> {
    let mut classes = Vec::new();
    for hash in request.class_hashes {
        let Some(class) = tx.class_definition(ClassHash(hash))? else {
            break;
        };

        // This is a temporary measure to avoid exceeding the max size of a protobuf message.
        let class = zstd::bulk::compress(&class, 0)?;

        classes.push(p2p_proto_v0::common::RawClass { class });
    }

    Ok(p2p_proto_v0::sync::Classes { classes })
}

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: BlockNumber,
    direction: p2p_proto_v0::sync::Direction,
) -> Option<BlockNumber> {
    match direction {
        p2p_proto_v0::sync::Direction::Forward => {
            current.get().checked_add(1).and_then(BlockNumber::new)
        }
        p2p_proto_v0::sync::Direction::Backward => {
            current.get().checked_sub(1).and_then(BlockNumber::new)
        }
    }
}
