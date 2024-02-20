use anyhow::Context;
use futures::channel::mpsc;
use futures::SinkExt;
use p2p_proto::class::{Class, ClassesRequest, ClassesResponse};
use p2p_proto::common::{
    Address, BlockNumberOrHash, ConsensusSignature, Direction, Hash, Iteration,
    L1DataAvailabilityMode, Merkle, Patricia, Step,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse, SignedBlockHeader};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::state::{ContractDiff, ContractStoredValue, StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_crypto::Felt;
use pathfinder_storage::Storage;
use pathfinder_storage::Transaction;
use starknet_gateway_types::class_definition;

pub mod conv;
#[cfg(test)]
mod tests;

use conv::ToDto;

#[cfg(not(test))]
const MAX_BLOCKS_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_BLOCKS_COUNT: u64 = MAX_COUNT_IN_TESTS;

pub async fn get_headers(
    storage: Storage,
    request: BlockHeadersRequest,
    tx: mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_headers).await?;
    send(tx, responses).await
}

pub async fn get_classes(
    storage: Storage,
    request: ClassesRequest,
    tx: mpsc::Sender<ClassesResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_classes).await?;
    send(tx, responses).await
}

pub async fn get_state_diffs(
    storage: Storage,
    request: StateDiffsRequest,
    tx: mpsc::Sender<StateDiffsResponse>,
) -> anyhow::Result<()> {
    let responses = spawn_blocking_get(request, storage, blocking::get_state_diffs).await?;
    send(tx, responses).await
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
    ) -> anyhow::Result<Vec<BlockHeadersResponse>> {
        iterate(tx, request.iteration, get_header)
    }

    pub(crate) fn get_classes(
        tx: Transaction<'_>,
        request: ClassesRequest,
    ) -> anyhow::Result<Vec<ClassesResponse>> {
        iterate(tx, request.iteration, get_classes_for_block)
    }

    pub(crate) fn get_state_diffs(
        tx: Transaction<'_>,
        request: StateDiffsRequest,
    ) -> anyhow::Result<Vec<StateDiffsResponse>> {
        iterate(tx, request.iteration, get_state_diff)
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
    responses: &mut Vec<BlockHeadersResponse>,
) -> anyhow::Result<bool> {
    if let Some(header) = tx.block_header(block_number.into())? {
        if let Some(signature) = tx.signature(block_number.into())? {
            let txn_count = header
                .transaction_count
                .try_into()
                .context("invalid transaction count")?;

            responses.push(BlockHeadersResponse::Header(Box::new(SignedBlockHeader {
                block_hash: Hash(header.hash.0),
                parent_hash: Hash(header.parent_hash.0),
                number: header.number.get(),
                time: header.timestamp.get(),
                sequencer_address: Address(header.sequencer_address.0),
                state_diff_commitment: Hash(Felt::ZERO), // TODO
                state: Patricia {
                    height: 251,
                    root: Hash(header.state_commitment.0),
                },
                transactions: Merkle {
                    n_leaves: txn_count,
                    root: Hash(header.transaction_commitment.0),
                },
                events: Merkle {
                    n_leaves: header
                        .event_count
                        .try_into()
                        .context("invalid event count")?,
                    root: Hash(header.event_commitment.0),
                },
                receipts: Merkle {
                    n_leaves: txn_count,
                    root: Hash(Felt::ZERO), // TODO
                },
                protocol_version: header.starknet_version.take_inner(),
                gas_price_wei: header.eth_l1_gas_price.0,
                gas_price_fri: header.strk_l1_gas_price.0,
                data_gas_price_wei: header.eth_l1_data_gas_price.0,
                data_gas_price_fri: header.strk_l1_data_gas_price.0,
                num_storage_diffs: 0,      // TODO
                num_nonce_updates: 0,      // TODO
                num_declared_classes: 0,   // TODO
                num_deployed_contracts: 0, // TODO
                l1_data_availability_mode: {
                    use pathfinder_common::L1DataAvailabilityMode::{Blob, Calldata};
                    match header.l1_da_mode {
                        Calldata => L1DataAvailabilityMode::Calldata,
                        Blob => L1DataAvailabilityMode::Blob,
                    }
                },
                signatures: vec![ConsensusSignature {
                    r: signature.r.0,
                    s: signature.s.0,
                }],
            })));
        }

        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Debug, Clone)]
enum ClassDefinition {
    Cairo(Vec<u8>),
    Sierra { sierra: Vec<u8>, casm: Vec<u8> },
}

fn get_classes_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<ClassesResponse>,
) -> anyhow::Result<bool> {
    let get_definition =
        |block_number: BlockNumber, class_hash| -> anyhow::Result<ClassDefinition> {
            let definition = tx
                .class_definition_at(block_number.into(), class_hash)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Class definition {} not found at block {}",
                        class_hash,
                        block_number
                    )
                })?;
            let casm_definition = tx.casm_definition(class_hash)?;
            Ok(match casm_definition {
                Some(casm) => ClassDefinition::Sierra {
                    sierra: definition,
                    casm,
                },
                None => ClassDefinition::Cairo(definition),
            })
        };

    let declared_classes = tx.declared_classes_at(block_number.into())?;
    let mut classes = Vec::new();

    for class_hash in declared_classes {
        let class_definition = get_definition(block_number, class_hash)?;

        let class: Class = match class_definition {
            ClassDefinition::Cairo(definition) => {
                let cairo_class =
                    serde_json::from_slice::<class_definition::Cairo<'_>>(&definition)?;
                Class::Cairo0 {
                    class: def_into_dto::cairo(cairo_class),
                    domain: 0, // TODO
                    class_hash: Hash(class_hash.0),
                }
            }
            ClassDefinition::Sierra { sierra, casm } => {
                let sierra_class = serde_json::from_slice::<class_definition::Sierra<'_>>(&sierra)?;

                Class::Cairo1 {
                    class: def_into_dto::sierra(sierra_class, casm),
                    domain: 0, // TODO
                    class_hash: Hash(class_hash.0),
                }
            }
        };
        classes.push(ClassesResponse::Class(class));
    }

    responses.extend(classes);

    Ok(true)
}

fn get_state_diff(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<StateDiffsResponse>,
) -> anyhow::Result<bool> {
    let Some(state_diff) = tx.state_update(block_number.into())? else {
        return Ok(false);
    };

    state_diff
        .contract_updates
        .into_iter()
        .for_each(|(address, update)| {
            responses.push(StateDiffsResponse::ContractDiff(ContractDiff {
                address: Address(address.0),
                nonce: update.nonce.map(|n| n.0),
                class_hash: update.class.as_ref().map(|c| c.class_hash().0),
                is_replaced: update.class.map(|c| c.is_replaced()),
                values: update
                    .storage
                    .into_iter()
                    .map(|(k, v)| ContractStoredValue {
                        key: k.0,
                        value: v.0,
                    })
                    .collect(),
                domain: 0, // TODO
            }))
        });

    state_diff
        .system_contract_updates
        .into_iter()
        .for_each(|(address, update)| {
            responses.push(StateDiffsResponse::ContractDiff(ContractDiff {
                address: Address(address.0),
                nonce: None,
                class_hash: None,
                is_replaced: None,
                values: update
                    .storage
                    .into_iter()
                    .map(|(k, v)| ContractStoredValue {
                        key: k.0,
                        value: v.0,
                    })
                    .collect(),
                domain: 0, // TODO
            }))
        });

    Ok(true)
}

fn get_transactions_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<TransactionsResponse>,
) -> anyhow::Result<bool> {
    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    responses.extend(
        txn_data
            .into_iter()
            .map(|(tnx, _)| TransactionsResponse::Transaction(tnx.to_dto())),
    );

    Ok(true)
}

fn get_receipts_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<ReceiptsResponse>,
) -> anyhow::Result<bool> {
    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    responses.extend(
        txn_data
            .into_iter()
            .map(ToDto::to_dto)
            .map(ReceiptsResponse::Receipt),
    );

    Ok(true)
}

fn get_events_for_block(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    responses: &mut Vec<EventsResponse>,
) -> anyhow::Result<bool> {
    let Some(txn_data) = tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    responses.extend(txn_data.into_iter().flat_map(|(_, r)| {
        std::iter::repeat(r.transaction_hash)
            .zip(r.events)
            .map(ToDto::to_dto)
            .map(EventsResponse::Event)
    }));

    Ok(true)
}

/// Assupmtions:
/// - `block_handler` returns `Ok(true)` if the iteration should continue.
/// - `T::default()` always returns the `Fin` variant of the implementing type.
fn iterate<T: Default + std::fmt::Debug>(
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
        return Ok(vec![T::default()]);
    }

    let mut block_number = match get_start_block_number(start, &tx)? {
        Some(x) => x,
        None => {
            return Ok(vec![T::default()]);
        }
    };

    let mut responses = Vec::new();
    let limit = limit.min(MAX_BLOCKS_COUNT);

    for i in 0..limit {
        if block_handler(&tx, block_number, &mut responses)? {
            // Block data retrieved successfully
        } else {
            // No such block
            break;
        }

        if i < limit - 1 {
            block_number = match get_next_block_number(block_number, step, direction) {
                Some(x) => x,
                None => {
                    // Out of range block number value
                    break;
                }
            };
        }
    }

    responses.push(T::default());

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
