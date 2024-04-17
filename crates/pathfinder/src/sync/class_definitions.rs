use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use p2p::client::peer_agnostic::Class;
use p2p::PeerData;
use p2p_proto::transaction;
use pathfinder_common::{BlockNumber, ClassHash};
use pathfinder_storage::Storage;
use starknet_gateway_types::class_definition::{Cairo, ClassDefinition, Sierra};
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash, compute_sierra_class_hash,
};
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use crate::sync::error::SyncError;

#[derive(Debug)]
pub struct ClassWithLayout {
    pub class: Class,
    pub layout: ClassDefinition<'static>,
}

/// Returns the first block number which is missing at least one class definition, counting from genesis
/// or `None` if all class definitions up to `head` are present.
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let highest = db
            .highest_block_with_all_class_definitions_downloaded()
            .context("Querying highest block with any class definitions")?
            .unwrap_or_default();

        Ok((highest < head).then_some(highest + 1))
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn declared_class_counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop_inclusive: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    const BATCH_SIZE: usize = 1000;

    async_stream::try_stream! {
        let mut batch = Vec::<usize>::new();

        while start <= stop_inclusive {
            if let Some(counts) = batch.pop() {
                yield counts;
                continue;
            }

            let batch_size = NonZeroUsize::new(
                BATCH_SIZE.min(
                    (stop_inclusive.get() - start.get() + 1)
                        .try_into()
                        .expect("ptr size is 64bits"),
                ),
            )
            .expect(">0");
            let storage = storage.clone();

            batch = tokio::task::spawn_blocking(move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;
                db.declared_classes_counts(start.into(), batch_size)
                    .context("Querying declared classes counts")
            })
            .await
            .context("Joining blocking task")??;

            if batch.is_empty() {
                Err(anyhow::anyhow!(
                    "No declared classes counts found for range: start {start}, batch_size (batch_size)"
                ))?;
                break;
            }

            start += batch.len().try_into().expect("ptr size is 64bits");
        }
    }
}

pub(super) async fn verify_layout(
    peer_data: PeerData<Class>,
) -> Result<PeerData<ClassWithLayout>, SyncError> {
    let PeerData { peer, data } = peer_data;
    match data {
        Class::Cairo {
            block_number,
            hash,
            definition,
        } => {
            let layout = ClassDefinition::Cairo(
                serde_json::from_slice::<Cairo<'_>>(&definition).map_err(|e| {
                    eprintln!("cairo: {e}");
                    SyncError::BadClassLayout(peer)
                })?,
            );
            Ok(PeerData::new(
                peer,
                ClassWithLayout {
                    class: Class::Cairo {
                        block_number,
                        hash,
                        definition,
                    },
                    layout,
                },
            ))
        }
        Class::Sierra {
            block_number,
            sierra_hash,
            sierra_definition,
            casm_definition,
        } => {
            let layout = ClassDefinition::Sierra(
                serde_json::from_slice::<Sierra<'_>>(&sierra_definition).map_err(|e| {
                    eprintln!("sierra: {e}");
                    SyncError::BadClassLayout(peer)
                })?,
            );
            Ok(PeerData::new(
                peer,
                ClassWithLayout {
                    class: Class::Sierra {
                        block_number,
                        sierra_hash,
                        sierra_definition,
                        casm_definition,
                    },
                    layout,
                },
            ))
        }
    }
}

/// Checks if the streamed class is expected to be declared at the given block.
/// If yes, it removes its hash from the "expected" set and returns the class, otherwise it returns an error.
/// When the set of expected classes for the block is exhausted it fetches the set for the next block.
///
/// This function relies on the guarantee that the block numbers in the stream are correct.
pub(super) async fn verify_declared_at(
    storage: Storage,
    expected_classes_for_block: Arc<Mutex<HashSet<ClassHash>>>,
    current_class: PeerData<ClassWithLayout>,
) -> Result<PeerData<ClassWithLayout>, SyncError> {
    let mut locked_expected_classes_for_block = expected_classes_for_block.lock().await;
    let block_number = current_class.data.class.block_number();
    let peer_id = current_class.peer;

    if locked_expected_classes_for_block.is_empty() {
        let declared = tokio::task::spawn_blocking(move || {
            let mut db = storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().expect("todo");
            let declared: Vec<ClassHash> = db
                .declared_classes_at(block_number.into())
                .context("Querying declared classes at block")?
                .ok_or(anyhow::anyhow!("Block header not found"))?;
            Result::<_, SyncError>::Ok(declared)
        })
        .await
        .context("Joining blocking task")??;

        locked_expected_classes_for_block.extend(declared.into_iter());
    }

    let class_hash = current_class.data.class.hash();

    if locked_expected_classes_for_block.remove(&class_hash) {
        Ok(current_class)
    } else {
        Err(SyncError::UnexpectedClass(peer_id))
    }
}

pub(super) async fn verify_hash(
    peer_data: PeerData<ClassWithLayout>,
) -> Result<PeerData<Class>, SyncError> {
    let PeerData { peer, data } = peer_data;
    let ClassWithLayout { class, layout } = data;

    let computed = tokio::task::spawn_blocking(move || match layout {
        ClassDefinition::Cairo(c) => compute_cairo_class_hash(
            c.abi.as_ref().get().as_bytes(),
            c.program.as_ref().get().as_bytes(),
            c.entry_points_by_type.external,
            c.entry_points_by_type.l1_handler,
            c.entry_points_by_type.constructor,
        ),
        ClassDefinition::Sierra(c) => compute_sierra_class_hash(
            c.abi.as_ref(),
            c.sierra_program,
            c.contract_class_version.as_ref(),
            c.entry_points_by_type,
        ),
    })
    .await
    .context("Joining blocking task")?
    .context("Computing class hash")?;

    (computed == class.hash())
        .then_some(PeerData::new(peer, class))
        .ok_or(SyncError::BadClassHash(peer))
}

pub(super) async fn persist(
    storage: Storage,
    classes: Vec<PeerData<Class>>,
) -> Result<BlockNumber, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;
        let tail = classes
            .last()
            .map(|x| x.data.block_number())
            .ok_or(anyhow::anyhow!("No class definitions to persist"))?;

        for class in classes.into_iter().map(|x| x.data) {
            match class {
                Class::Cairo {
                    hash, definition, ..
                } => {
                    transaction
                        .update_cairo_class(hash, &definition)
                        .context("Updating cairo class definition")?;
                }
                Class::Sierra {
                    sierra_hash,
                    sierra_definition,
                    casm_definition,
                    ..
                } => {
                    let casm_hash = transaction
                        .casm_hash(ClassHash(sierra_hash.0))
                        .context("Getting casm hash for sierra class")?
                        .ok_or(anyhow::anyhow!("Casm hash not found"))?;

                    transaction
                        .update_sierra_class(
                            &sierra_hash,
                            &sierra_definition,
                            &casm_hash,
                            &casm_definition,
                        )
                        .context("Updating sierra class definition")?;
                }
            }
        }

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
