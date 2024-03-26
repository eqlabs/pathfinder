use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::peer_agnostic::Class;
use p2p::PeerData;
use pathfinder_common::{BlockNumber, ClassHash};
use pathfinder_storage::Storage;
use starknet_gateway_types::class_definition::ClassDefinition;
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash, compute_sierra_class_hash,
};
use tokio::task::spawn_blocking;

#[derive(Debug, thiserror::Error)]
pub(super) enum ClassDefinitionSyncError {
    #[error(transparent)]
    ClassDefinitionStreamError(#[from] anyhow::Error),
    #[error("Invalid class definition layout")]
    BadLayout(Box<PeerData<(BlockNumber, ClassHash, serde_json::Error)>>),
    #[error("Class hash verification failed")]
    BadClassHash(PeerData<(BlockNumber, ClassHash)>),
}

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

pub(super) fn verify_layout(
    peer_data: PeerData<Class>,
) -> Result<PeerData<ClassWithLayout>, ClassDefinitionSyncError> {
    let PeerData { peer, data } = peer_data;
    match data {
        Class::Cairo {
            block_number,
            hash,
            definition,
        } => {
            let layout = serde_json::from_slice(&definition).map_err(|e| {
                ClassDefinitionSyncError::BadLayout(Box::new(PeerData::new(
                    peer,
                    (block_number, hash, e),
                )))
            })?;
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
            let layout = serde_json::from_slice(&sierra_definition).map_err(|e| {
                ClassDefinitionSyncError::BadLayout(Box::new(PeerData::new(
                    peer,
                    (block_number, ClassHash(sierra_hash.0), e),
                )))
            })?;
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

pub(super) async fn verify_hash(
    peer_data: PeerData<ClassWithLayout>,
) -> Result<PeerData<Class>, ClassDefinitionSyncError> {
    let PeerData { peer, data } = peer_data;
    let ClassWithLayout { class, layout } = data;

    let err = || {
        ClassDefinitionSyncError::BadClassHash(PeerData::new(
            peer,
            (class.block_number(), class.hash()),
        ))
    };

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
    .map_err(|_| err())?
    .map_err(|_| err())?;

    if computed == class.hash() {
        Ok(PeerData::new(peer, class))
    } else {
        Err(ClassDefinitionSyncError::BadClassHash(PeerData::new(
            peer,
            (class.block_number(), class.hash()),
        )))
    }
}

pub(super) async fn persist(
    storage: Storage,
    classes: Vec<PeerData<Class>>,
) -> Result<BlockNumber, ClassDefinitionSyncError> {
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
            let block_hash = transaction
                .block_hash(class.block_number().into())
                .context("Getting block hash")?
                .ok_or(anyhow::anyhow!("Block hash not found"))?;

            match class {
                Class::Cairo {
                    hash, definition, ..
                } => {
                    transaction
                        .insert_cairo_class(hash, &definition)
                        .context("Inserting cairo class definition")?;
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
                        .insert_sierra_class(
                            &sierra_hash,
                            &sierra_definition,
                            &casm_hash,
                            &casm_definition,
                        )
                        .context("Inserting sierra class definition")?;
                }
            }
        }

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
