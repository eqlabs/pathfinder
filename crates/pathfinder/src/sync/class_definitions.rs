use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use futures::pin_mut;
use futures::stream::StreamExt;
use p2p::client::peer_agnostic::ClassDefinition as P2PClassDefinition;
use p2p::PeerData;
use p2p_proto::transaction;
use pathfinder_common::state_update::DeclaredClasses;
use pathfinder_common::{BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::Storage;
use serde_json::de;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::class_definition::{
    Cairo,
    ClassDefinition as GwClassDefinition,
    Sierra,
};
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash,
    compute_sierra_class_hash,
};
use starknet_gateway_types::reply::call;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use crate::sync::error::{SyncError, SyncError2};
use crate::sync::stream::ProcessStage;

#[derive(Debug)]
pub struct ClassWithLayout {
    pub block_number: BlockNumber,
    pub definition: ClassDefinition,
    pub layout: GwClassDefinition<'static>,
}

#[derive(Debug)]
pub(super) enum ClassDefinition {
    Cairo(Vec<u8>),
    Sierra(Vec<u8>),
}

#[derive(Debug)]
pub struct Class {
    pub block_number: BlockNumber,
    pub hash: ClassHash,
    pub definition: ClassDefinition,
}

#[derive(Debug)]
pub(super) struct CompiledClass {
    pub block_number: BlockNumber,
    pub hash: ClassHash,
    pub definition: CompiledClassDefinition,
}

#[derive(Debug)]
pub(super) enum CompiledClassDefinition {
    Cairo(Vec<u8>),
    Sierra {
        sierra_definition: Vec<u8>,
        casm_definition: Vec<u8>,
    },
}

/// Returns the first block number which is missing at least one class
/// definition, counting from genesis or `None` if all class definitions up to
/// `head` are present.
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let next_missing = db
            .first_block_with_missing_class_definitions()
            .context("Querying first block number with missing class definitions")?;

        match next_missing {
            Some(next_missing) if next_missing <= head => Ok(Some(next_missing)),
            Some(_) | None => Ok(None),
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
                db.declared_classes_counts(start, batch_size)
                    .context("Querying declared classes counts")
            })
            .await
            .context("Joining blocking task")??;

            if batch.is_empty() {
                Err(anyhow::anyhow!(
                    "No declared classes counts found for range: start {start}, batch_size {batch_size}"
                ))?;
                break;
            }

            start += batch.len().try_into().expect("ptr size is 64bits");
        }

        while let Some(counts) = batch.pop() {
            yield counts;
        }
    }
}

pub struct VerifyLayout;

impl ProcessStage for VerifyLayout {
    const NAME: &'static str = "Class::VerifyLayout";

    type Input = P2PClassDefinition;
    type Output = ClassWithLayout;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        match input {
            P2PClassDefinition::Cairo {
                block_number,
                definition,
            } => {
                let layout = GwClassDefinition::Cairo(
                    serde_json::from_slice::<Cairo<'_>>(&definition)
                        .map_err(|_| SyncError2::BadClassLayout)?,
                );
                Ok(ClassWithLayout {
                    block_number,
                    definition: ClassDefinition::Cairo(definition),
                    layout,
                })
            }
            P2PClassDefinition::Sierra {
                block_number,
                sierra_definition,
            } => {
                let layout = GwClassDefinition::Sierra(
                    serde_json::from_slice::<Sierra<'_>>(&sierra_definition)
                        .map_err(|_| SyncError2::BadClassLayout)?,
                );
                Ok(ClassWithLayout {
                    block_number,
                    definition: ClassDefinition::Sierra(sierra_definition),
                    layout,
                })
            }
        }
    }
}

pub struct ComputeHash;

impl ProcessStage for ComputeHash {
    const NAME: &'static str = "Class::ComputeHash";

    type Input = ClassWithLayout;
    type Output = Class;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let ClassWithLayout {
            block_number,
            definition,
            layout,
        } = input;

        let hash = match layout {
            GwClassDefinition::Cairo(c) => compute_cairo_class_hash(
                c.abi.as_ref().get().as_bytes(),
                c.program.as_ref().get().as_bytes(),
                c.entry_points_by_type.external,
                c.entry_points_by_type.l1_handler,
                c.entry_points_by_type.constructor,
            ),
            GwClassDefinition::Sierra(c) => compute_sierra_class_hash(
                c.abi.as_ref(),
                c.sierra_program,
                c.contract_class_version.as_ref(),
                c.entry_points_by_type,
            ),
        }?;

        Ok(Class {
            block_number,
            definition,
            hash,
        })
    }
}

pub struct VerifyDeclaredAt {
    expectation_source: Receiver<ExpectedDeclarations>,
    current: ExpectedDeclarations,
}

impl VerifyDeclaredAt {
    pub fn new(expectation_source: Receiver<ExpectedDeclarations>) -> Self {
        Self {
            expectation_source,
            current: Default::default(),
        }
    }
}

impl ProcessStage for VerifyDeclaredAt {
    const NAME: &'static str = "Class::VerifyDeclarationBlock";

    type Input = Class;
    type Output = Class;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        if self.current.classes.is_empty() {
            self.current = loop {
                let expected = self
                    .expectation_source
                    .blocking_recv()
                    .context("Receiving expected declarations")?;
                // Some blocks may have no declared classes.
                // Try the next one
                if expected.classes.is_empty() {
                    continue;
                }

                break expected;
            };
        }

        if self.current.block_number != input.block_number {
            return Err(SyncError2::UnexpectedClass);
        }

        if self.current.classes.remove(&input.hash) {
            Ok(input)
        } else {
            Err(SyncError2::UnexpectedClass)
        }
    }
}

#[derive(Debug, Default)]
pub struct ExpectedDeclarations {
    pub block_number: BlockNumber,
    pub classes: HashSet<ClassHash>,
}

pub struct ExpectedDeclarationsSource {
    db_connection: pathfinder_storage::Connection,
    start: BlockNumber,
    stop: BlockNumber,
}

impl ExpectedDeclarationsSource {
    pub fn new(
        db_connection: pathfinder_storage::Connection,
        start: BlockNumber,
        stop: BlockNumber,
    ) -> Self {
        Self {
            db_connection,
            start,
            stop,
        }
    }

    pub fn spawn(self) -> anyhow::Result<Receiver<ExpectedDeclarations>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let Self {
            mut db_connection,
            mut start,
            stop,
        } = self;
        tokio::task::spawn_blocking(move || {
            let db = db_connection
                .transaction()
                .context("Creating database transaction")?;

            while start <= stop {
                let declared = db
                    .declared_classes_at(start.into())
                    .context("Querying declared classes at block")?
                    .context("Block header not found")?
                    .into_iter()
                    .collect();
                tx.blocking_send(ExpectedDeclarations {
                    block_number: start,
                    classes: declared,
                })
                .context("Sending expected declarations")?;
            }

            start += 1;

            anyhow::Ok(())
        });

        Ok(rx)
    }
}

pub struct CompileSierraToCasm<T: GatewayApi + Clone + Send>(T);
pub struct Store {
    db: pathfinder_storage::Connection,
    current_block: BlockNumber,
}

impl Store {
    pub fn new(db: pathfinder_storage::Connection, start: BlockNumber) -> Self {
        Self {
            db,
            current_block: start,
        }
    }
}

pub(super) async fn verify_layout(
    peer_data: PeerData<P2PClassDefinition>,
) -> Result<PeerData<ClassWithLayout>, SyncError> {
    let PeerData { peer, data } = peer_data;
    match data {
        P2PClassDefinition::Cairo {
            block_number,
            definition,
        } => {
            let layout = GwClassDefinition::Cairo(
                serde_json::from_slice::<Cairo<'_>>(&definition).map_err(|e| {
                    tracing::debug!(error=%e, "Bad Cairo class layout");
                    SyncError::BadClassLayout(peer)
                })?,
            );
            Ok(PeerData::new(
                peer,
                ClassWithLayout {
                    block_number,
                    definition: ClassDefinition::Cairo(definition),
                    layout,
                },
            ))
        }
        P2PClassDefinition::Sierra {
            block_number,
            sierra_definition,
        } => {
            let layout = GwClassDefinition::Sierra(
                serde_json::from_slice::<Sierra<'_>>(&sierra_definition).map_err(|e| {
                    tracing::debug!(error=%e, "Bad Sierra class layout");
                    SyncError::BadClassLayout(peer)
                })?,
            );
            Ok(PeerData::new(
                peer,
                ClassWithLayout {
                    block_number,
                    definition: ClassDefinition::Sierra(sierra_definition),
                    layout,
                },
            ))
        }
    }
}

pub(super) async fn compute_hash(
    peer_data: PeerData<ClassWithLayout>,
) -> Result<PeerData<Class>, SyncError> {
    let PeerData { peer, data } = peer_data;
    let ClassWithLayout {
        block_number,
        definition,
        layout,
    } = data;

    let hash = tokio::task::spawn_blocking(move || match layout {
        GwClassDefinition::Cairo(c) => compute_cairo_class_hash(
            c.abi.as_ref().get().as_bytes(),
            c.program.as_ref().get().as_bytes(),
            c.entry_points_by_type.external,
            c.entry_points_by_type.l1_handler,
            c.entry_points_by_type.constructor,
        ),
        GwClassDefinition::Sierra(c) => compute_sierra_class_hash(
            c.abi.as_ref(),
            c.sierra_program,
            c.contract_class_version.as_ref(),
            c.entry_points_by_type,
        ),
    })
    .await
    .context("Joining blocking task")?
    .context("Computing class hash")?;

    Ok(PeerData::new(
        peer,
        Class {
            block_number,
            definition,
            hash,
        },
    ))
}

/// Returns a stream of sets of class hashes declared at each block in the range
/// [start, stop_inclusive].
pub(super) fn declared_classes_at_block_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop_inclusive: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<ExpectedDeclarations>> {
    async_stream::try_stream! {
        while start <= stop_inclusive {
            let storage = storage.clone();

            let declared_at_this_block = tokio::task::spawn_blocking(move || -> anyhow::Result<ExpectedDeclarations> {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().expect("todo");
                let declared = db
                    .declared_classes_at(start.into())
                    .context("Querying declared classes at block")?
                    .context("Block header not found")?
                    .into_iter()
                    .collect();
                Ok(ExpectedDeclarations {
                    block_number: start,
                    classes: declared,
                })
            })
            .await
            .context("Joining blocking task")??;

            yield declared_at_this_block;

            start += 1;
        }
    }
}

/// This function relies on the guarantee that the block numbers in the stream
/// are correct.
pub(super) fn verify_declared_at(
    mut declared_classes_at_block: impl futures::Stream<Item = Result<ExpectedDeclarations, SyncError>>
        + Unpin,
    mut classes: impl futures::Stream<Item = Result<PeerData<Class>, SyncError>> + Unpin,
) -> impl futures::Stream<Item = Result<PeerData<Class>, SyncError>> {
    async_stream::try_stream! {
        while let Some(declared) = declared_classes_at_block.next().await {
            let ExpectedDeclarations {
                block_number: declared_at,
                classes: mut declared,
            } = declared?;

            // Some blocks may have no declared classes.
            if declared.is_empty() {
                continue;
            }

            while let Some(class) = classes.next().await {
                let class = class?;

                if declared_at != class.data.block_number {
                    tracing::info!(hash=%class.data.hash, %declared_at, block_number=%class.data.block_number, "Unexpected class");
                    Err(SyncError::UnexpectedClass(class.peer))?;
                }

                if declared.remove(&class.data.hash) {
                    yield class;
                } else {
                    tracing::info!(hash=%class.data.hash, block_number=%class.data.block_number, "Class was not expected in this block");
                    Err(SyncError::UnexpectedClass(class.peer))?;
                }

                if declared.is_empty() {
                    break;
                }
            }

        }
    }
}

pub(super) async fn compile_sierra_to_casm_or_fetch<SequencerClient: GatewayApi + Clone + Send>(
    peer_data: PeerData<Class>,
    fgw: SequencerClient,
) -> Result<PeerData<CompiledClass>, SyncError> {
    let PeerData {
        peer,
        data: Class {
            block_number,
            hash,
            definition,
        },
    } = peer_data;

    let definition = match definition {
        ClassDefinition::Cairo(c) => CompiledClassDefinition::Cairo(c),
        ClassDefinition::Sierra(sierra_definition) => {
            let (casm_definition, sierra_definition) =
                tokio::task::spawn_blocking(move || -> (anyhow::Result<_>, _) {
                    let _span =
                        tracing::trace_span!("compile_sierra_to_casm_or_fetch", class_hash=%hash)
                            .entered();
                    (
                        pathfinder_compiler::compile_to_casm(&sierra_definition)
                            .context("Compiling Sierra class"),
                        sierra_definition,
                    )
                })
                .await
                .context("Joining blocking task")?;

            let casm_definition = match casm_definition {
                Ok(x) => x,
                Err(_) => fgw
                    .pending_casm_by_hash(hash)
                    .await
                    .context("Fetching casm definition from gateway")?
                    .to_vec(),
            };

            CompiledClassDefinition::Sierra {
                sierra_definition,
                casm_definition,
            }
        }
    };

    Ok(PeerData::new(
        peer,
        CompiledClass {
            block_number,
            hash,
            definition,
        },
    ))
}

pub(super) async fn persist(
    storage: Storage,
    classes: Vec<PeerData<CompiledClass>>,
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
            .map(|x| x.data.block_number)
            .context("No class definitions to persist")?;

        for CompiledClass {
            block_number: _,
            definition,
            hash,
        } in classes.into_iter().map(|x| x.data)
        {
            match definition {
                CompiledClassDefinition::Cairo(definition) => {
                    transaction
                        .update_cairo_class(hash, &definition)
                        .context("Updating cairo class definition")?;
                }
                CompiledClassDefinition::Sierra {
                    sierra_definition,
                    casm_definition,
                } => {
                    let casm_hash = transaction
                        .casm_hash(hash)
                        .context("Getting casm hash for sierra class")?
                        .context("Casm hash not found")?;

                    transaction
                        .update_sierra_class(
                            &SierraHash(hash.0),
                            &sierra_definition,
                            &casm_hash,
                            &casm_definition,
                        )
                        .context("Updating sierra class definition")?;
                }
            }
        }
        transaction.commit().context("Committing db transaction")?;

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}

pub struct VerifyClassHashes;

impl ProcessStage for VerifyClassHashes {
    const NAME: &'static str = "Classes::Verify";

    type Input = (DeclaredClasses, Vec<ClassWithLayout>);
    type Output = Vec<GwClassDefinition<'static>>;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, super::error::SyncError2> {
        todo!()
    }
}
