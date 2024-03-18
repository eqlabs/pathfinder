use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::peer_agnostic::RawClass;
use p2p::PeerData;
use pathfinder_common::{BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

#[derive(Clone, Debug)]
pub enum Class {
    Cairo {
        block_number: BlockNumber,
        hash: ClassHash,
        definition: Vec<u8>,
    },
    Sierra {
        block_number: BlockNumber,
        sierra_hash: SierraHash,
        sierra_definition: Vec<u8>,
        casm_hash: CasmHash,
        casm_definition: Vec<u8>,
    },
}

impl Class {
    pub fn block_number(&self) -> BlockNumber {
        match self {
            Self::Cairo { block_number, .. } => *block_number,
            Self::Sierra { block_number, .. } => *block_number,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ClassDefinitionSyncError {
    #[error(transparent)]
    ClassDefinitionStreamError(#[from] anyhow::Error),
    #[error("Class hash verification failed")]
    BadClassHash(PeerData<(BlockNumber, ClassHash)>),
    #[error("Compiling sierra into casm failed")]
    SierraCompilationError(PeerData<(BlockNumber, SierraHash)>),
}

/// Returns the first block number which is missing at least one class definition, counting from genesis
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        if let Some(highest) = db
            .highest_block_with_all_class_definitions_downloaded()
            .context("Querying highest block with all class definitions")?
        {
            Ok((highest < head).then_some(highest + 1))
        } else {
            Ok(Some(BlockNumber::GENESIS))
        }
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

pub(super) async fn verify_hash(
    class: PeerData<RawClass>,
) -> Result<PeerData<RawClass>, ClassDefinitionSyncError> {
    todo!()
}

pub(super) async fn compile_sierra(
    class: PeerData<RawClass>,
) -> Result<PeerData<Class>, ClassDefinitionSyncError> {
    todo!()
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
                    casm_hash,
                    casm_definition,
                    ..
                } => {
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
