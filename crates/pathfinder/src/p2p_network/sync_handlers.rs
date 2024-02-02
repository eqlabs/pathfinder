use anyhow::Context;
use futures::channel::mpsc;
use futures::SinkExt;
use p2p_proto::common::{BlockId, BlockNumberOrHash, Direction, Hash, Iteration, Step};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::{BlockHash, BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::Storage;
use pathfinder_storage::Transaction;
use starknet_gateway_types::class_definition;

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

pub async fn get_headers(
    storage: Storage,
    request: BlockHeadersRequest,
    mut tx: mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<()> {
    let response = spawn_blocking_get(request, storage, blocking::get_headers).await?;
    tx.send(response).await.context("Sending response")
}

pub async fn get_transactions(
    storage: Storage,
    request: TransactionsRequest,
    tx: mpsc::Sender<TransactionsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_transactions).await?;
    send(tx, responses).await
}

pub async fn get_receipts(
    storage: Storage,
    request: ReceiptsRequest,
    tx: mpsc::Sender<ReceiptsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_receipts).await?;
    send(tx, responses).await
}

pub async fn get_events(
    storage: Storage,
    request: EventsRequest,
    tx: mpsc::Sender<EventsResponse>,
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
        todo!()
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
    parts: &mut Vec<BlockHeadersResponse>,
) -> anyhow::Result<bool> {
    if let Some(header) = tx.block_header(block_number.into())? {
        let hash = Hash(header.hash.0);
        todo!();

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
    pub fn class_hash(&self) -> ClassHash {
        match self {
            ClassId::Cairo(class_hash) => *class_hash,
            ClassId::Sierra(sierra_hash, _) => ClassHash(sierra_hash.0),
        }
    }
}

#[derive(Debug, Clone)]
enum ClassDefinition {
    Cairo(Vec<u8>),
    Sierra { sierra: Vec<u8>, casm: Vec<u8> },
}

fn get_transactions_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<TransactionsResponse>,
) -> anyhow::Result<bool> {
    let Some(block_hash) = tx.block_hash(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    todo!();

    Ok(true)
}

fn get_receipts_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<ReceiptsResponse>,
) -> anyhow::Result<bool> {
    let Some(block_hash) = tx.block_hash(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    todo!();

    Ok(true)
}

fn get_events_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<EventsResponse>,
) -> anyhow::Result<bool> {
    let Some(block_hash) = tx.block_hash(block_number.into())? else {
        return Ok(false);
    };

    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    let items = txn_data
        .into_iter()
        .flat_map(|(_, r)| {
            std::iter::repeat(r.transaction_hash)
                .zip(r.events)
                .map(ToProto::to_proto)
        })
        .collect::<Vec<_>>();

    let id = Some(BlockId {
        number: block_number.get(),
        hash: Hash(block_hash.0),
    });

    todo!();

    Ok(true)
}

/// `block_handler` returns Ok(true) if the iteration should continue and is
/// responsible for delimiting block data with `Fin::ok()` marker.
fn iterate<T>(
    tx: Transaction<'_>,
    iteration: Iteration,
    block_handler: impl Fn(&Transaction<'_>, BlockNumber, &mut Vec<T>) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<T>> {
    todo!()
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

async fn send<T>(mut tx: mpsc::Sender<T>, seq: Vec<T>) -> anyhow::Result<()>
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

mod def_into_dto {
    use p2p_proto::class::{
        Cairo0Class, Cairo1Class, Cairo1EntryPoints, EntryPoint, SierraEntryPoint,
    };
    use starknet_gateway_types::request::contract::{SelectorAndFunctionIndex, SelectorAndOffset};

    pub fn sierra(sierra: super::class_definition::Sierra<'_>, compiled: Vec<u8>) -> Cairo1Class {
        let into_dto = |x: SelectorAndFunctionIndex| SierraEntryPoint {
            selector: x.selector.0,
            index: x.function_idx,
        };

        let entry_points = Cairo1EntryPoints {
            externals: sierra
                .entry_points_by_type
                .external
                .into_iter()
                .map(into_dto)
                .collect(),
            l1_handlers: sierra
                .entry_points_by_type
                .l1_handler
                .into_iter()
                .map(into_dto)
                .collect(),
            constructors: sierra
                .entry_points_by_type
                .constructor
                .into_iter()
                .map(into_dto)
                .collect(),
        };

        Cairo1Class {
            abi: sierra.abi.as_bytes().to_owned(),
            program: sierra.sierra_program,
            entry_points,
            compiled, // TODO not sure if encoding in storage and dto is the same
            contract_class_version: sierra.contract_class_version.into(),
        }
    }

    pub fn cairo(cairo: super::class_definition::Cairo<'_>) -> Cairo0Class {
        let into_dto = |x: SelectorAndOffset| EntryPoint {
            selector: x.selector.0,
            offset: x.offset.0,
        };

        Cairo0Class {
            abi: cairo.abi.get().as_bytes().to_owned(),
            externals: cairo
                .entry_points_by_type
                .external
                .into_iter()
                .map(into_dto)
                .collect(),
            l1_handlers: cairo
                .entry_points_by_type
                .l1_handler
                .into_iter()
                .map(into_dto)
                .collect(),
            constructors: cairo
                .entry_points_by_type
                .constructor
                .into_iter()
                .map(into_dto)
                .collect(),
            program: cairo.program.get().as_bytes().to_owned(),
        }
    }
}
