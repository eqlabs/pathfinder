use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::thread;

use anyhow::Context;
use futures::pin_mut;
use futures::stream::{BoxStream, StreamExt};
use p2p::client::types::ClassDefinition as P2PClassDefinition;
use p2p::PeerData;
use p2p_proto::transaction;
use pathfinder_common::class_definition::{Cairo, ClassDefinition as GwClassDefinition, Sierra};
use pathfinder_common::state_update::DeclaredClasses;
use pathfinder_common::{BlockNumber, CasmHash, ClassHash, SierraHash};
use pathfinder_storage::Storage;
use serde_json::de;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::class_hash::from_parts::{
    compute_cairo_class_hash,
    compute_sierra_class_hash,
};
use starknet_gateway_types::reply::call;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
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

                // Some blocks may have no declared classes. Try the next one.
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
        let Class {
            block_number,
            hash,
            definition,
        } = input;

        let definition = match definition {
            ClassDefinition::Cairo(c) => CompiledClassDefinition::Cairo(c),
            ClassDefinition::Sierra(sierra_definition) => {
                let casm_definition = pathfinder_compiler::compile_to_casm(&sierra_definition)
                    .context("Compiling Sierra class");

                let casm_definition = match casm_definition {
                    Ok(x) => x,
                    Err(_) => self
                        .tokio_handle
                        .block_on(self.fgw.pending_casm_by_hash(hash))
                        .context("Fetching casm definition from gateway")?
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

        db.commit().context("Committing db transaction")?;

        Ok(block_number)
    }
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
                        return Err(SyncError2::ClassDefinitionsDeclarationsMismatch);
                    }
                }
                CompiledClassDefinition::Sierra { .. } => {
                    let hash = SierraHash(class.hash.0);
                    declared_classes
                        .sierra
                        .remove(&hash)
                        .ok_or(SyncError2::ClassDefinitionsDeclarationsMismatch)?;
                }
            }
        }
        if declared_classes.cairo.is_empty() && declared_classes.sierra.is_empty() {
            Ok(input)
        } else {
            Err(SyncError2::ClassDefinitionsDeclarationsMismatch)
        }
    }
}
