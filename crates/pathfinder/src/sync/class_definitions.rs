use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::thread;

use anyhow::Context;
use futures::pin_mut;
use futures::stream::{BoxStream, StreamExt};
use p2p::client::types::ClassDefinition as P2PClassDefinition;
use p2p::libp2p::PeerId;
use p2p::PeerData;
use p2p_proto::transaction;
use pathfinder_common::class_definition::{Cairo, ClassDefinition as GwClassDefinition, Sierra};
use pathfinder_common::state_update::DeclaredClasses;
use pathfinder_common::{BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::{Storage, Transaction};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde_json::de;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash,
    compute_sierra_class_hash,
};
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::call;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::{oneshot, Mutex};
use tokio::task::spawn_blocking;
use tokio_stream::wrappers::ReceiverStream;

use super::storage_adapters;
use crate::sync::error::{SyncError, SyncError2};
use crate::sync::stream::ProcessStage;

#[derive(Debug)]
pub struct ClassWithLayout {
    pub block_number: BlockNumber,
    pub definition: ClassDefinition,
    pub layout: GwClassDefinition<'static>,
    pub hash: ClassHash,
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
pub struct CompiledClass {
    pub block_number: BlockNumber,
    pub hash: ClassHash,
    pub definition: CompiledClassDefinition,
}

#[derive(Debug)]
pub enum CompiledClassDefinition {
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

pub(super) fn get_counts(
    db: pathfinder_storage::Transaction<'_>,
    start: BlockNumber,
    batch_size: NonZeroUsize,
) -> anyhow::Result<VecDeque<usize>> {
    db.declared_classes_counts(start, batch_size)
        .context("Querying declared classes counts")
}

pub(super) fn declared_class_counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
    batch_size: NonZeroUsize,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    storage_adapters::counts_stream(storage, start, stop, batch_size, get_counts)
}

pub(super) async fn verify_layout(
    peer_data: PeerData<P2PClassDefinition>,
) -> Result<PeerData<ClassWithLayout>, SyncError> {
    let PeerData { peer, data } = peer_data;
    verify_layout_impl(data)
        .map(|x| PeerData::new(peer, x))
        .map_err(|_| SyncError::BadClassLayout(peer))
}

pub struct VerifyLayout;

impl ProcessStage for VerifyLayout {
    const NAME: &'static str = "Class::VerifyLayout";

    type Input = P2PClassDefinition;
    type Output = ClassWithLayout;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        verify_layout_impl(input).map_err(|_| SyncError2::BadClassLayout)
    }
}

fn verify_layout_impl(def: P2PClassDefinition) -> anyhow::Result<ClassWithLayout> {
    match def {
        P2PClassDefinition::Cairo {
            block_number,
            definition,
            hash,
        } => {
            let layout = GwClassDefinition::Cairo(
                serde_json::from_slice::<Cairo<'_>>(&definition).inspect_err(
                    |e| tracing::debug!(%block_number, error=%e, "Bad class layout"),
                )?,
            );
            Ok(ClassWithLayout {
                block_number,
                definition: ClassDefinition::Cairo(definition),
                layout,
                hash,
            })
        }
        P2PClassDefinition::Sierra {
            block_number,
            sierra_definition,
            hash,
        } => {
            let layout = GwClassDefinition::Sierra(
                serde_json::from_slice::<Sierra<'_>>(&sierra_definition).inspect_err(
                    |e| tracing::debug!(%block_number, error=%e, "Bad class layout"),
                )?,
            );
            Ok(ClassWithLayout {
                block_number,
                definition: ClassDefinition::Sierra(sierra_definition),
                layout,
                hash: ClassHash(hash.0),
            })
        }
    }
}

pub struct ComputeHash;

impl ProcessStage for ComputeHash {
    const NAME: &'static str = "Class::ComputeHash";

    type Input = ClassWithLayout;
    type Output = Class;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        compute_hash_impl(input).map_err(|_| SyncError2::ClassHashComputationError)
    }
}

pub(super) async fn compute_hash(
    peer_data: Vec<PeerData<ClassWithLayout>>,
) -> Result<Vec<PeerData<Class>>, SyncError> {
    use rayon::prelude::*;
    let (tx, rx) = oneshot::channel();
    rayon::spawn(move || {
        let res = peer_data
            .into_par_iter()
            .map(|PeerData { peer, data }| {
                let compiled = compute_hash_impl(data)
                    .map_err(|_| SyncError::ClassHashComputationError(peer))?;
                Ok(PeerData::new(peer, compiled))
            })
            .collect::<Result<Vec<PeerData<Class>>, SyncError>>();
        tx.send(res);
    });
    rx.await.expect("Sender not to be dropped")
}

fn compute_hash_impl(input: ClassWithLayout) -> anyhow::Result<Class> {
    let ClassWithLayout {
        block_number,
        definition,
        layout,
        hash,
    } = input;

    let computed_hash = match layout {
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

    if computed_hash != hash {
        tracing::debug!(input_hash=%hash, actual_hash=%computed_hash, "Class hash mismatch");
        Err(SyncError2::BadClassHash.into())
    } else {
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

                // Some blocks may have no declared classes. Try the next one.
                if expected.classes.is_empty() {
                    continue;
                }

                break expected;
            };
        }

        if self.current.block_number != input.block_number {
            tracing::debug!(expected_block_number=%self.current.block_number, block_number=%input.block_number, class_hash=%input.hash, "Unexpected class definition");
            return Err(SyncError2::UnexpectedClass);
        }

        if self.current.classes.remove(&input.hash) {
            Ok(input)
        } else {
            tracing::debug!(block_number=%input.block_number, class_hash=%input.hash, "Unexpected class definition");
            Err(SyncError2::UnexpectedClass)
        }
    }
}

/// This function makes sure that the classes we receive from other peers are
/// really declared at the expected blocks.
///
/// ### Details
///
/// This function ingests two streams:
/// - `expected_declarations` which is a stream of expected class declarations
///   at each block,
/// - `classes` which is a stream of chunked class definitions as received from
///   other peers,
///
/// producing a stream of class definitions that we are sure are declared at the
/// expected blocks.
///
/// Any mismatch between the expected and received class definitions will result
/// in an error and termination of the resulting stream.
///
/// ### Important
///
/// - The caller guarantees that the block numbers in both input streams are
///   correct.
/// - This function does not care if `expected_declarations` skips empty blocks
///   or not.
pub(super) fn verify_declared_at(
    mut expected_declarations: BoxStream<
        'static,
        anyhow::Result<(BlockNumber, HashSet<ClassHash>)>,
    >,
    mut classes: BoxStream<'static, Result<Vec<PeerData<Class>>, SyncError>>,
) -> impl futures::Stream<Item = Result<PeerData<Class>, SyncError>> {
    make_stream::from_future(move |tx| async move {
        let mut dechunker = ClassDechunker::new();

        while let Some(expected) = expected_declarations.next().await {
            let (declared_at, mut declared) = match expected {
                Ok(x) => x,
                Err(e) => {
                    _ = tx.send(Err(e.into()));
                    return;
                }
            };

            loop {
                // even if `expected_declarations` skips empty blocks the current set can still
                // be empty because it has just been exhausted and we need to fetch the
                // expectations for the next block.
                if declared.is_empty() {
                    break;
                }

                let Some(maybe_class) = dechunker.next(&mut classes).await else {
                    // `classes` stream has terminated
                    return;
                };

                let res = maybe_class.and_then(|class| {
                    // Check if the class is declared at the expected block
                    if declared_at != class.data.block_number {
                        tracing::error!(%declared_at, %class.data.block_number, %class.data.hash, ?declared, "Unexpected class 1");
                        return Err(SyncError::UnexpectedClass(class.peer));
                    }

                    if declared.remove(&class.data.hash) {
                        Ok(class)
                    } else {
                        tracing::error!(%declared_at, %class.data.block_number, %class.data.hash, ?declared, "Unexpected class 2");
                        Err(SyncError::UnexpectedClass(class.peer))
                    }
                });
                let bail = res.is_err();
                // Send the result to the next stage
                tx.send(res).await.expect("Receiver not to be dropped");
                // Short-circuit on error
                if bail {
                    return;
                }
            }
        }
    })
}

struct ClassDechunker(VecDeque<PeerData<Class>>);

impl ClassDechunker {
    fn new() -> Self {
        Self(Default::default())
    }

    /// Caller must guarantee: chunks in `classes` are never empty.
    async fn next(
        &mut self,
        classes: &mut BoxStream<'static, Result<Vec<PeerData<Class>>, SyncError>>,
    ) -> Option<Result<PeerData<Class>, SyncError>> {
        if self.0.is_empty() {
            classes.next().await.map(|x| {
                x.map(|chunk| {
                    self.0.extend(chunk);
                    self.0.pop_front().expect("Chunk not to be empty")
                })
            })
        } else {
            self.0.pop_front().map(Ok)
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
        let (tx, rx) = mpsc::channel(1);
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
                    .collect::<HashSet<_>>();

                if !declared.is_empty() {
                    tx.blocking_send(ExpectedDeclarations {
                        block_number: start,
                        classes: declared,
                    })
                    .context("Sending expected declarations")?;
                }

                start += 1;
            }

            anyhow::Ok(())
        });

        Ok(rx)
    }
}

/// Returns a stream of sets of class hashes declared at each block in the range
/// `start..=stop`.
pub(super) fn expected_declarations_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<(BlockNumber, HashSet<ClassHash>)>> {
    make_stream::from_blocking(move |tx| {
        let mut db = match storage.connection().context("Creating database connection") {
            Ok(x) => x,
            Err(e) => {
                tx.blocking_send(Err(e));
                return;
            }
        };
        let db = match db.transaction().context("Creating database transaction") {
            Ok(x) => x,
            Err(e) => {
                tx.blocking_send(Err(e));
                return;
            }
        };

        while start <= stop {
            let res = db
                .declared_classes_at(start.into())
                .context("Querying declared classes at block")
                .and_then(|x| x.context("Block header not found"))
                .map_err(Into::into)
                .map(|x| (start, x.into_iter().collect::<HashSet<_>>()));
            let is_err = res.is_err();
            let is_empty = res.as_ref().map(|(_, x)| x.is_empty()).unwrap_or(false);
            if !is_empty {
                tx.blocking_send(res);
            }
            if is_err {
                return;
            }

            start += 1;
        }
    })
}

pub struct CompileSierraToCasm<T> {
    fgw: T,
    tokio_handle: tokio::runtime::Handle,
}

impl<T> CompileSierraToCasm<T> {
    pub fn new(fgw: T, tokio_handle: tokio::runtime::Handle) -> Self {
        Self { fgw, tokio_handle }
    }
}

impl<T: GatewayApi + Clone + Send + 'static> ProcessStage for CompileSierraToCasm<T> {
    const NAME: &'static str = "Class::CompileSierraToCasm";

    type Input = Class;
    type Output = CompiledClass;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let compiled = compile_or_fetch_impl(input, &self.fgw, &self.tokio_handle)
            .map_err(|_| SyncError2::FetchingCasmFailed)?;
        Ok(compiled)
    }
}

pub(super) async fn compile_sierra_to_casm_or_fetch<
    SequencerClient: GatewayApi + Clone + Send + 'static,
>(
    peer_data: Vec<PeerData<Class>>,
    fgw: SequencerClient,
    tokio_handle: tokio::runtime::Handle,
) -> Result<Vec<PeerData<CompiledClass>>, SyncError> {
    use rayon::prelude::*;
    let (tx, rx) = oneshot::channel();
    rayon::spawn(move || {
        let res = peer_data
            .into_par_iter()
            .map(|x| {
                let PeerData { peer, data } = x;
                let compiled = compile_or_fetch_impl(data, &fgw, &tokio_handle)
                    .map_err(|_| SyncError::FetchingCasmFailed)?;
                Ok(PeerData::new(peer, compiled))
            })
            .collect::<Result<Vec<PeerData<CompiledClass>>, SyncError>>();
        tx.send(res);
    });
    rx.await.expect("Sender not to be dropped")
}

fn compile_or_fetch_impl<SequencerClient: GatewayApi + Clone + Send + 'static>(
    class: Class,
    fgw: &SequencerClient,
    tokio_handle: &tokio::runtime::Handle,
) -> Result<CompiledClass, SequencerError> {
    let Class {
        block_number,
        hash,
        definition,
    } = class;

    let definition = match definition {
        ClassDefinition::Cairo(c) => CompiledClassDefinition::Cairo(c),
        ClassDefinition::Sierra(sierra_definition) => {
            let casm_definition = pathfinder_compiler::compile_to_casm(&sierra_definition)
                .context("Compiling Sierra class");

            let casm_definition = match casm_definition {
                Ok(x) => x,
                // Feeder gateway request errors are recoverable at this point because we know
                // that the class is declared and exists so if the gateway responds with an
                // error we should restart the sync and retry later.
                Err(_) => tokio_handle
                    .block_on(fgw.pending_casm_by_hash(hash))?
                    .to_vec(),
            };

            CompiledClassDefinition::Sierra {
                sierra_definition,
                casm_definition,
            }
        }
    };

    Ok(CompiledClass {
        block_number,
        hash,
        definition,
    })
}

pub struct Store(pub pathfinder_storage::Connection);

impl ProcessStage for Store {
    const NAME: &'static str = "Class::Persist";

    type Input = CompiledClass;
    type Output = BlockNumber;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let CompiledClass {
            block_number,
            hash,
            definition,
        } = input;

        let db = self
            .0
            .transaction()
            .context("Creating database transaction")?;

        persist_impl(&db, hash, definition)?;

        db.commit().context("Committing db transaction")?;

        Ok(block_number)
    }
}

pub(super) async fn persist(
    storage: Storage,
    classes: Vec<PeerData<CompiledClass>>,
) -> Result<BlockNumber, SyncError> {
    tokio::task::spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
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
            persist_impl(&db, hash, definition)?;
        }
        db.commit().context("Committing db transaction")?;

        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}

fn persist_impl(
    db: &Transaction<'_>,
    hash: ClassHash,
    definition: CompiledClassDefinition,
) -> anyhow::Result<()> {
    match definition {
        CompiledClassDefinition::Cairo(definition) => {
            db.update_cairo_class(hash, &definition)
                .context("Updating cairo class definition")?;
        }
        CompiledClassDefinition::Sierra {
            sierra_definition,
            casm_definition,
        } => {
            let casm_hash = db
                .casm_hash(hash)
                .context("Getting casm hash for sierra class")?
                .context("Casm hash not found")?;

            db.update_sierra_class(
                &SierraHash(hash.0),
                &sierra_definition,
                &casm_hash,
                &casm_definition,
            )
            .context("Updating sierra class definition")?;
        }
    }

    Ok(())
}

pub struct VerifyClassHashes {
    pub declarations: BoxStream<'static, DeclaredClasses>,
    pub tokio_handle: tokio::runtime::Handle,
}

impl ProcessStage for VerifyClassHashes {
    const NAME: &'static str = "Classes::VerifyHashes";

    type Input = Vec<CompiledClass>;
    type Output = Vec<CompiledClass>;

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let mut declared_classes = self
            .tokio_handle
            .block_on(self.declarations.next())
            .context("Getting declared classes")?;

        for class in input.iter() {
            match class.definition {
                CompiledClassDefinition::Cairo(_) => {
                    if !declared_classes.cairo.remove(&class.hash) {
                        tracing::debug!(class_hash=%class.hash, "Class hash not found in declared classes");
                        return Err(SyncError2::ClassDefinitionsDeclarationsMismatch);
                    }
                }
                CompiledClassDefinition::Sierra { .. } => {
                    let hash = SierraHash(class.hash.0);
                    declared_classes
                        .sierra
                        .remove(&hash)
                        .ok_or_else(|| {
                            tracing::debug!(class_hash=%class.hash, "Class hash not found in declared classes");
                            SyncError2::ClassDefinitionsDeclarationsMismatch})?;
                }
            }
        }
        if declared_classes.cairo.is_empty() && declared_classes.sierra.is_empty() {
            Ok(input)
        } else {
            let missing: Vec<ClassHash> = declared_classes
                .cairo
                .into_iter()
                .chain(
                    declared_classes
                        .sierra
                        .into_values()
                        .map(|casm_hash| ClassHash(casm_hash.0)),
                )
                .collect();
            tracing::trace!(?missing, "Expected class definitions are missing");
            Err(SyncError2::ClassDefinitionsDeclarationsMismatch)
        }
    }
}
