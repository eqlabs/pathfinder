use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::thread;

use anyhow::Context;
use futures::pin_mut;
use futures::stream::{BoxStream, StreamExt};
use p2p::libp2p::PeerId;
use p2p::sync::client::types::ClassDefinition as P2PClassDefinition;
use p2p::PeerData;
use p2p_proto::transaction;
use pathfinder_class_hash::from_parts::{compute_cairo_class_hash, compute_sierra_class_hash};
use pathfinder_common::class_definition::{Cairo, ClassDefinition as GwClassDefinition, Sierra};
use pathfinder_common::state_update::DeclaredClasses;
use pathfinder_common::{BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::{Storage, Transaction};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde_json::de;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::reply::call;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::{oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;

use super::storage_adapters;
use crate::sync::error::SyncError;
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
        casm_hash_v2: CasmHash,
    },
}

/// Returns the first block number which is missing at least one class
/// definition, counting from genesis or `None` if all class definitions up to
/// `head` are present.
pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    util::task::spawn_blocking(move |_| {
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
    verify_layout_impl(&peer, data).map(|x| PeerData::new(peer, x))
}

pub struct VerifyLayout;

impl ProcessStage for VerifyLayout {
    const NAME: &'static str = "Class::VerifyLayout";

    type Input = Vec<P2PClassDefinition>;
    type Output = Vec<ClassWithLayout>;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        input
            .into_par_iter()
            .map(|class| verify_layout_impl(peer, class))
            .collect()
    }
}

fn verify_layout_impl(
    peer: &PeerId,
    def: P2PClassDefinition,
) -> Result<ClassWithLayout, SyncError> {
    match def {
        P2PClassDefinition::Cairo {
            block_number,
            definition,
            hash,
        } => {
            let layout = GwClassDefinition::Cairo(
                serde_json::from_slice::<Cairo<'_>>(&definition).map_err(|error| {
                    tracing::debug!(%peer, %block_number, %error, "Bad class layout");
                    SyncError::BadClassLayout(*peer)
                })?,
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
                serde_json::from_slice::<Sierra<'_>>(&sierra_definition).map_err(|error| {
                    tracing::debug!(%peer, %block_number, %error, "Bad class layout");
                    SyncError::BadClassLayout(*peer)
                })?,
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

pub struct VerifyHash;

impl ProcessStage for VerifyHash {
    const NAME: &'static str = "Class::VerifyHash";

    type Input = Vec<ClassWithLayout>;
    type Output = Vec<Class>;

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        input
            .into_par_iter()
            .map(|class| {
                let compiled = verify_hash_impl(peer, class)?;
                Ok(compiled)
            })
            .collect::<Result<Vec<Class>, SyncError>>()
    }
}

pub(super) async fn verify_hash(
    peer_data: Vec<PeerData<ClassWithLayout>>,
) -> Result<Vec<PeerData<Class>>, SyncError> {
    use rayon::prelude::*;
    let (tx, rx) = oneshot::channel();
    rayon::spawn(move || {
        let res = peer_data
            .into_par_iter()
            .map(|PeerData { peer, data }| {
                let compiled = verify_hash_impl(&peer, data)?;
                Ok(PeerData::new(peer, compiled))
            })
            .collect::<Result<Vec<PeerData<Class>>, SyncError>>();
        tx.send(res);
    });
    rx.await.expect("Sender not to be dropped")
}

fn verify_hash_impl(peer: &PeerId, input: ClassWithLayout) -> Result<Class, SyncError> {
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
    }
    .map_err(|error| {
        tracing::debug!(%peer, %block_number, expected_hash=%hash, %error, "Class hash computation failed");
        SyncError::ClassHashComputationError(*peer)
    })?;

    if computed_hash != hash {
        tracing::debug!(%peer, %block_number, expected_hash=%hash, %computed_hash, "Class hash mismatch");
        Err(SyncError::BadClassHash(*peer))
    } else {
        Ok(Class {
            block_number,
            definition,
            hash,
        })
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
    util::make_stream::from_future(move |tx| async move {
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

                let res = maybe_class.and_then(|PeerData { peer, data: class }| {
                    // Check if the class is declared at the expected block
                    if declared_at != class.block_number {
                        tracing::debug!(%peer, expected_block_number=%declared_at, block_number=%class.block_number, %class.hash, "Unexpected class definition");
                        return Err(SyncError::UnexpectedClass(peer));
                    }

                    if declared.remove(&class.hash) {
                        Ok(PeerData::new(peer, class))
                    } else {
                        tracing::debug!(%peer, block_number=%class.block_number, %class.hash, "Unexpected class definition");
                        Err(SyncError::UnexpectedClass(peer))
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

/// Returns a stream of sets of class hashes declared at each block in the range
/// `start..=stop`.
pub(super) fn expected_declarations_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<(BlockNumber, HashSet<ClassHash>)>> {
    util::make_stream::from_blocking(move |cancellation_token, tx| {
        let mut db = match storage.connection().context("Creating database connection") {
            Ok(x) => x,
            Err(e) => {
                tx.blocking_send(Err(e));
                return;
            }
        };

        while start <= stop {
            if cancellation_token.is_cancelled() {
                return;
            }

            let db = match db.transaction().context("Creating database transaction") {
                Ok(x) => x,
                Err(e) => {
                    tx.blocking_send(Err(e));
                    return;
                }
            };
            let res = db
                .declared_classes_at(start.into())
                .context("Querying declared classes at block")
                .and_then(|x| x.context("Block header not found"))
                .map(|x| (start, x.into_iter().collect::<HashSet<_>>()));
            drop(db);
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

    type Input = Vec<Class>;
    type Output = Vec<CompiledClass>;

    fn map(&mut self, _: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        input
            .into_par_iter()
            .map(|class| {
                let compiled = compile_or_fetch_impl(class, &self.fgw, &self.tokio_handle)?;
                Ok(compiled)
            })
            .collect::<Result<Vec<CompiledClass>, SyncError>>()
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
                let compiled = compile_or_fetch_impl(data, &fgw, &tokio_handle)?;
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
) -> Result<CompiledClass, SyncError> {
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
                    .block_on(fgw.pending_casm_by_hash(hash))
                    .map_err(|error| {
                        tracing::debug!(%block_number, class_hash=%hash, %error, "Fetching casm from feeder gateway failed");
                        SyncError::FetchingCasmFailed
                    })?
                    .to_vec(),
            };

            let casm_hash_v2 = pathfinder_casm_hashes::get_precomputed_casm_v2_hash(&hash);
            let casm_hash_v2 = match casm_hash_v2 {
                Some(casm_hash_v2) => *casm_hash_v2,
                None => pathfinder_compiler::casm_class_hash_v2(&casm_definition)
                    .context("Computing CASM Blake2 hash")?,
            };

            CompiledClassDefinition::Sierra {
                sierra_definition,
                casm_definition,
                casm_hash_v2,
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

    fn map(&mut self, _: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
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
    util::task::spawn_blocking(move |_| {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
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
            let db = db.transaction().context("Creating database transaction")?;
            persist_impl(&db, hash, definition)?;
            db.commit().context("Committing db transaction")?;
        }

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
            db.update_cairo_class_definition(hash, &definition)
                .context("Updating cairo class definition")?;
        }
        CompiledClassDefinition::Sierra {
            sierra_definition,
            casm_definition,
            casm_hash_v2,
        } => {
            db.update_sierra_class_definition(
                &SierraHash(hash.0),
                &sierra_definition,
                &casm_definition,
                &casm_hash_v2,
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

    fn map(&mut self, peer: &PeerId, input: Self::Input) -> Result<Self::Output, SyncError> {
        let mut declared_classes = self
            .tokio_handle
            .block_on(self.declarations.next())
            .context("Getting declared classes")?;

        for class in input.iter() {
            match class.definition {
                CompiledClassDefinition::Cairo(_) => {
                    if !declared_classes.cairo.remove(&class.hash) {
                        tracing::debug!(%peer, block_number=%class.block_number, class_hash=%class.hash, "Class hash not found in declared classes");
                        return Err(SyncError::ClassDefinitionsDeclarationsMismatch(*peer));
                    }
                }
                CompiledClassDefinition::Sierra { .. } => {
                    let hash = SierraHash(class.hash.0);
                    declared_classes
                        .sierra
                        .remove(&hash)
                        .ok_or_else(|| {
                            tracing::debug!(%peer, block_number=%class.block_number, class_hash=%class.hash, "Class hash not found in declared classes");
                            SyncError::ClassDefinitionsDeclarationsMismatch(*peer)
                        })?;
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
            tracing::trace!(%peer, ?missing, "Expected class definitions are missing");
            Err(SyncError::ClassDefinitionsDeclarationsMismatch(*peer))
        }
    }
}
