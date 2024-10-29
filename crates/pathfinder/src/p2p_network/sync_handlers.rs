use anyhow::Context;
use futures::SinkExt;
use p2p::client::conv::ToDto;
use p2p_proto::class::{Class, ClassesRequest, ClassesResponse};
use p2p_proto::common::{
    Address,
    BlockNumberOrHash,
    Direction,
    Hash,
    Iteration,
    Step,
    VolitionDomain,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
use p2p_proto::state::{
    ContractDiff,
    ContractStoredValue,
    DeclaredClass,
    StateDiffsRequest,
    StateDiffsResponse,
};
use p2p_proto::transaction::{TransactionWithReceipt, TransactionsRequest, TransactionsResponse};
use pathfinder_common::{class_definition, BlockHash, BlockNumber, SignedBlockHeader};
use pathfinder_storage::{Storage, Transaction};
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

#[cfg(not(test))]
const MAX_BLOCKS_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_BLOCKS_COUNT: u64 = MAX_COUNT_IN_TESTS;

pub async fn get_headers(
    storage: Storage,
    request: BlockHeadersRequest,
    tx: futures::channel::mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<()> {
    spawn_blocking_get(request, storage, blocking::get_headers, tx).await
}

pub async fn get_classes(
    storage: Storage,
    request: ClassesRequest,
    tx: futures::channel::mpsc::Sender<ClassesResponse>,
) -> anyhow::Result<()> {
    spawn_blocking_get(request, storage, blocking::get_classes, tx).await
}

pub async fn get_state_diffs(
    storage: Storage,
    request: StateDiffsRequest,
    tx: futures::channel::mpsc::Sender<StateDiffsResponse>,
) -> anyhow::Result<()> {
    spawn_blocking_get(request, storage, blocking::get_state_diffs, tx).await
}

pub async fn get_transactions(
    storage: Storage,
    request: TransactionsRequest,
    tx: futures::channel::mpsc::Sender<TransactionsResponse>,
) -> anyhow::Result<()> {
    spawn_blocking_get(request, storage, blocking::get_transactions, tx).await
}

pub async fn get_events(
    storage: Storage,
    request: EventsRequest,
    tx: futures::channel::mpsc::Sender<EventsResponse>,
) -> anyhow::Result<()> {
    spawn_blocking_get(request, storage, blocking::get_events, tx).await
}

pub(crate) mod blocking {
    use super::*;

    #[tracing::instrument(skip(db_tx, tx))]
    pub(crate) fn get_headers(
        db_tx: Transaction<'_>,
        request: BlockHeadersRequest,
        tx: mpsc::Sender<BlockHeadersResponse>,
    ) -> anyhow::Result<()> {
        iterate(db_tx, request.iteration, get_header, tx)
    }

    #[tracing::instrument(skip(db_tx, tx))]
    pub(crate) fn get_classes(
        db_tx: Transaction<'_>,
        request: ClassesRequest,
        tx: mpsc::Sender<ClassesResponse>,
    ) -> anyhow::Result<()> {
        iterate(db_tx, request.iteration, get_classes_for_block, tx)
    }

    #[tracing::instrument(skip(db_tx, tx))]
    pub(crate) fn get_state_diffs(
        db_tx: Transaction<'_>,
        request: StateDiffsRequest,
        tx: mpsc::Sender<StateDiffsResponse>,
    ) -> anyhow::Result<()> {
        iterate(db_tx, request.iteration, get_state_diff, tx)
    }

    #[tracing::instrument(skip(db_tx, tx))]
    pub(crate) fn get_transactions(
        db_tx: Transaction<'_>,
        request: TransactionsRequest,
        tx: mpsc::Sender<TransactionsResponse>,
    ) -> anyhow::Result<()> {
        iterate(db_tx, request.iteration, get_transactions_for_block, tx)
    }

    #[tracing::instrument(skip(db_tx, tx))]
    pub(crate) fn get_events(
        db_tx: Transaction<'_>,
        request: EventsRequest,
        tx: mpsc::Sender<EventsResponse>,
    ) -> anyhow::Result<()> {
        iterate(db_tx, request.iteration, get_events_for_block, tx)
    }
}

fn get_header(
    db_tx: &Transaction<'_>,
    block_number: BlockNumber,
    tx: &mpsc::Sender<BlockHeadersResponse>,
) -> anyhow::Result<bool> {
    if let Some(header) = db_tx.block_header(block_number.into())? {
        if let Some(signature) = db_tx.signature(block_number.into())? {
            tracing::trace!(?header, "Sending block header");

            let sbh = SignedBlockHeader { header, signature };

            tx.blocking_send(BlockHeadersResponse::Header(Box::new(sbh.to_dto())))
                .map_err(|_| anyhow::anyhow!("Sending header"))?;

            return Ok(true);
        }
    }

    Ok(false)
}

#[derive(Debug, Clone)]
enum ClassDefinition {
    Cairo(Vec<u8>),
    Sierra { sierra: Vec<u8>, _casm: Vec<u8> },
}

fn get_classes_for_block(
    db_tx: &Transaction<'_>,
    block_number: BlockNumber,
    tx: &mpsc::Sender<ClassesResponse>,
) -> anyhow::Result<bool> {
    let get_definition =
        |block_number: BlockNumber, class_hash| -> anyhow::Result<ClassDefinition> {
            let definition = db_tx
                .class_definition_at(block_number.into(), class_hash)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Class definition {} not found at block {}",
                        class_hash,
                        block_number
                    )
                })?;
            let casm_definition = db_tx.casm_definition(class_hash)?;
            Ok(match casm_definition {
                Some(_casm) => ClassDefinition::Sierra {
                    sierra: definition,
                    _casm: Vec::new(), // TODO casm
                },
                None => ClassDefinition::Cairo(definition),
            })
        };

    let Some(declared_classes) = db_tx.declared_classes_at(block_number.into())? else {
        return Ok(false);
    };

    for class_hash in declared_classes {
        let class_definition = get_definition(block_number, class_hash)?;

        tracing::trace!(?class_hash, "Sending class definition");

        let class: Class = match class_definition {
            ClassDefinition::Cairo(definition) => {
                let cairo_class =
                    serde_json::from_slice::<class_definition::Cairo<'_>>(&definition)?;
                Class::Cairo0 {
                    class: cairo_class.to_dto(),
                    domain: 0, // TODO
                    class_hash: Hash(class_hash.0),
                }
            }
            ClassDefinition::Sierra {
                sierra,
                _casm: _, /* TODO */
            } => {
                let sierra_class = serde_json::from_slice::<class_definition::Sierra<'_>>(&sierra)?;

                Class::Cairo1 {
                    class: sierra_class.to_dto(),
                    domain: 0, // TODO
                    class_hash: Hash(class_hash.0),
                }
            }
        };

        tx.blocking_send(ClassesResponse::Class(class))
            .map_err(|_| anyhow::anyhow!("Sending class"))?;
    }

    Ok(true)
}

fn get_state_diff(
    db_tx: &Transaction<'_>,
    block_number: BlockNumber,
    tx: &mpsc::Sender<StateDiffsResponse>,
) -> anyhow::Result<bool> {
    let Some(state_diff) = db_tx.state_update(block_number.into())? else {
        return Ok(false);
    };

    for (address, update) in state_diff.contract_updates {
        tx.blocking_send(StateDiffsResponse::ContractDiff(ContractDiff {
            address: Address(address.0),
            nonce: update.nonce.map(|n| n.0),
            class_hash: update.class.as_ref().map(|c| Hash(c.class_hash().0)),
            values: update
                .storage
                .into_iter()
                .map(|(k, v)| ContractStoredValue {
                    key: k.0,
                    value: v.0,
                })
                .collect(),
            domain: VolitionDomain::L1, // TODO
        }))
        .map_err(|_| anyhow::anyhow!("Sending contract diff"))?;
    }

    for (address, update) in state_diff.system_contract_updates {
        tx.blocking_send(StateDiffsResponse::ContractDiff(ContractDiff {
            address: Address(address.0),
            nonce: None,
            class_hash: None,
            values: update
                .storage
                .into_iter()
                .map(|(k, v)| ContractStoredValue {
                    key: k.0,
                    value: v.0,
                })
                .collect(),
            domain: VolitionDomain::L1, // TODO
        }))
        .map_err(|_| anyhow::anyhow!("Sending system contract diff"))?;
    }

    for class_hash in state_diff.declared_cairo_classes {
        tx.blocking_send(StateDiffsResponse::DeclaredClass(DeclaredClass {
            class_hash: Hash(class_hash.0),
            compiled_class_hash: None,
        }))
        .map_err(|_| anyhow::anyhow!("Sending declared cairo class"))?;
    }

    for (sierra_hash, casm_hash) in state_diff.declared_sierra_classes {
        tx.blocking_send(StateDiffsResponse::DeclaredClass(DeclaredClass {
            class_hash: Hash(sierra_hash.0),
            compiled_class_hash: Some(Hash(casm_hash.0)),
        }))
        .map_err(|_| anyhow::anyhow!("Sending declared sierra class"))?;
    }

    Ok(true)
}

fn get_transactions_for_block(
    db_tx: &Transaction<'_>,
    block_number: BlockNumber,
    tx: &mpsc::Sender<TransactionsResponse>,
) -> anyhow::Result<bool> {
    let Some(txn_data) = db_tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    for (txn, receipt, _) in txn_data {
        tracing::trace!(transaction_hash=%txn.hash, "Sending transaction");

        let receipt = (&txn.variant, receipt).to_dto();
        let transaction = p2p_proto::transaction::Transaction {
            txn: txn.variant.to_dto(),
            transaction_hash: Hash(txn.hash.0),
        };
        tx.blocking_send(TransactionsResponse::TransactionWithReceipt(
            TransactionWithReceipt {
                transaction,
                receipt,
            },
        ))
        .map_err(|_| anyhow::anyhow!("Sending transaction"))?;
    }

    Ok(true)
}

fn get_events_for_block(
    db_tx: &Transaction<'_>,
    block_number: BlockNumber,
    tx: &mpsc::Sender<EventsResponse>,
) -> anyhow::Result<bool> {
    let Some(txn_data) = db_tx.transaction_data_for_block(block_number.into())? else {
        return Ok(false);
    };

    for (_, r, events) in txn_data {
        for event in events {
            tx.blocking_send(EventsResponse::Event((r.transaction_hash, event).to_dto()))
                .map_err(|_| anyhow::anyhow!("Sending event"))?;
        }
    }

    Ok(true)
}

/// Assupmtions:
/// - `block_handler` returns `Ok(true)` if the iteration should continue,
/// - `T::default()` always returns the `Fin` variant of the implementing type.
fn iterate<T: Default + std::fmt::Debug>(
    db_tx: Transaction<'_>,
    iteration: Iteration,
    block_handler: impl Fn(&Transaction<'_>, BlockNumber, &mpsc::Sender<T>) -> anyhow::Result<bool>,
    tx: mpsc::Sender<T>,
) -> anyhow::Result<()> {
    let Iteration {
        start,
        direction,
        limit,
        step,
    } = iteration;

    if limit == 0 {
        tx.blocking_send(T::default())
            .map_err(|_| anyhow::anyhow!("Sending Fin"))?;
        return Ok(());
    }

    let mut block_number = match get_start_block_number(start, &db_tx)? {
        Some(x) => x,
        None => {
            tx.blocking_send(T::default())
                .map_err(|_| anyhow::anyhow!("Sending Fin"))?;
            return Ok(());
        }
    };

    let limit = limit.min(MAX_BLOCKS_COUNT);

    for i in 0..limit {
        if !block_handler(&db_tx, block_number, &tx)? {
            // No such block
            break;
        };

        if i < limit - 1 {
            block_number = match get_next_block_number(block_number, step, direction) {
                Some(x) => x,
                None => {
                    // Out of range block number value
                    break;
                }
            }
        }
    }

    tracing::trace!("Sending FIN");

    tx.blocking_send(T::default())
        .map_err(|_| anyhow::anyhow!("Sending Fin"))?;

    Ok(())
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

/// Spawns a blocking task and forwards the result to the given channel.
/// Bails out early if the database operation fails or sending fails.
/// The `getter` function is expected to send partial results through the tokio
/// channel as soon as possible, ideally after each database read operation.
async fn spawn_blocking_get<Request, Response, Getter>(
    request: Request,
    storage: Storage,
    getter: Getter,
    mut tx: futures::channel::mpsc::Sender<Response>,
) -> anyhow::Result<()>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request, mpsc::Sender<Response>) -> anyhow::Result<()>
        + Send
        + 'static,
{
    let span = tracing::Span::current();

    let (sync_tx, mut rx) = mpsc::channel(1); // For backpressure

    let db_fut = async {
        tokio::task::spawn_blocking(move || {
            let _g = span.enter();
            let mut connection = storage
                .connection()
                .context("Opening database connection")?;
            let db_tx = connection
                .transaction()
                .context("Creating database transaction")?;
            getter(db_tx, request, sync_tx)
        })
        .await
        .context("Database read panic or shutting down")?
        .context("Database read")
    };

    let fwd_fut = async move {
        while let Some(x) = rx.recv().await {
            tx.send(x).await.context("Sending item")?;
        }
        Ok::<_, anyhow::Error>(())
    };
    // Bail out early, either when db fails or sending fails
    tokio::try_join!(db_fut, fwd_fut)?;
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
