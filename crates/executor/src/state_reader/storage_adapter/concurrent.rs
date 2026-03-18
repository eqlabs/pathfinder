use std::sync::mpsc::{self, Receiver, Sender, SyncSender};

use blockifier::blockifier::config::{ConcurrencyConfig, TransactionExecutorConfig};
use blockifier::state::errors::StateError;
use pathfinder_common::{
    BlockHash,
    BlockId,
    BlockNumber,
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    DecidedBlocks,
    SierraHash,
    StorageAddress,
    StorageValue,
};
use pathfinder_storage::Connection;
use tokio_util::sync::CancellationToken;

use crate::state_reader::storage_adapter::{
    map_anyhow_to_state_err,
    ClassDefinitionAtWithBlockNumber,
    ClassDefinitionWithBlockNumber,
    StorageAdapter,
};

#[derive(Clone)]
pub struct ConcurrentStorageAdapter {
    tx: Sender<Command>,
    decided_blocks: DecidedBlocks,
}

enum Command {
    BlockHash(BlockId, SyncSender<anyhow::Result<Option<BlockHash>>>),
    CasmDefinition(ClassHash, SyncSender<Result<Option<Vec<u8>>, StateError>>),
    ClassDefinitionWithBlockNumber(
        ClassHash,
        SyncSender<Result<ClassDefinitionWithBlockNumber, StateError>>,
    ),
    CasmDefinitionAt(
        BlockId,
        ClassHash,
        SyncSender<Result<Option<Vec<u8>>, StateError>>,
    ),
    ClassDefinitionAtWithBlockNumber(
        BlockId,
        ClassHash,
        SyncSender<Result<ClassDefinitionAtWithBlockNumber, StateError>>,
    ),
    StorageValue(
        BlockId,
        ContractAddress,
        StorageAddress,
        SyncSender<Result<Option<StorageValue>, StateError>>,
    ),
    ContractNonce(
        ContractAddress,
        BlockId,
        SyncSender<Result<Option<ContractNonce>, StateError>>,
    ),
    ContractClassHash(
        BlockId,
        ContractAddress,
        SyncSender<Result<Option<ClassHash>, StateError>>,
    ),
    CasmHash(ClassHash, SyncSender<Result<Option<CasmHash>, StateError>>),
    CasmHashV2(ClassHash, SyncSender<Result<Option<CasmHash>, StateError>>),
    CasmHashAt(
        BlockId,
        ClassHash,
        SyncSender<Result<Option<CasmHash>, StateError>>,
    ),
}

impl ConcurrentStorageAdapter {
    pub fn new(db_conn: Connection, decided_blocks: DecidedBlocks) -> Self {
        let (tx, rx) = mpsc::channel();

        util::task::spawn_std(move |cancellation_token| db_thread(db_conn, rx, cancellation_token));

        Self { tx, decided_blocks }
    }
}

impl StorageAdapter for ConcurrentStorageAdapter {
    fn transaction_executor_config(&self) -> TransactionExecutorConfig {
        let n_workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1);

        let concurrency_config = if n_workers == 1 {
            ConcurrencyConfig::default()
        } else {
            ConcurrencyConfig {
                enabled: true,
                n_workers,
                // Based on a very limited benchmark, 8 seems to be a good chunk size.
                //
                // Sample: 617 validation compatible blocks from mainnet, from within the
                // (23173..=1473516) block range, 16 workers, 16 cores.
                //
                // | Chunk size | Total execution time (normalized)
                // +------------+-----------------------------------
                // | 1          |  2.86
                // | 2          |  1.81
                // | 4          |  1.24
                // | 8          |  1.00
                // | 16         |  1.08
                // | 32         |  1.21
                // | 64         |  1.20
                chunk_size: 8,
            }
        };

        TransactionExecutorConfig {
            concurrency_config,
            ..Default::default()
        }
    }

    fn block_hash(&self, block: BlockId) -> anyhow::Result<Option<BlockHash>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::BlockHash(block, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_definition(&self, class_hash: ClassHash) -> Result<Option<Vec<u8>>, StateError> {
        {
            let decided_blocks = self.decided_blocks.read().unwrap();
            if let Some(casm_def) = decided_blocks.iter().find_map(|(_, b)| {
                b.block.declared_classes.iter().find_map(|c| {
                    (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_def.clone())
                })
            }) {
                return Ok(Some(casm_def));
            }
            // Otherwise fetch from the database
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmDefinition(class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn class_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> Result<Option<(Option<BlockNumber>, Vec<u8>)>, StateError> {
        {
            let decided_blocks = self.decided_blocks.read().unwrap();
            if let Some(block_number_and_class_def) = decided_blocks.iter().find_map(|(n, b)| {
                b.block.declared_classes.iter().find_map(|c| {
                    (c.sierra_hash == SierraHash(class_hash.0))
                        .then_some((Some(*n), c.sierra_def.clone()))
                })
            }) {
                return Ok(Some(block_number_and_class_def));
            }
            // Otherwise fetch from the database
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::ClassDefinitionWithBlockNumber(class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<Vec<u8>>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let class_def = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(b.block.declared_classes.iter().find_map(|c| {
                            (c.sierra_hash == SierraHash(class_hash.0))
                                .then_some(c.casm_def.clone())
                        }))
                        .and_then(|x| x)
                });

                if let Some(class_def) = class_def {
                    return Ok(Some(class_def));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let class_def = decided_blocks.iter().rev().find_map(|(_, b)| {
                    b.block.declared_classes.iter().find_map(|c| {
                        (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_def.clone())
                    })
                });

                if let Some(class_def) = class_def {
                    return Ok(Some(class_def));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmDefinitionAt(block_id, class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<(BlockNumber, Vec<u8>)>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let block_number_and_class_def = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(b.block.declared_classes.iter().find_map(|c| {
                            (c.sierra_hash == SierraHash(class_hash.0))
                                .then_some(c.sierra_def.clone())
                        }))
                        .and_then(|x| x)
                        .map(|def| (*n, def))
                });

                if let Some(block_number_and_class_def) = block_number_and_class_def {
                    return Ok(Some(block_number_and_class_def));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let block_number_and_class_def = decided_blocks.iter().rev().find_map(|(n, b)| {
                    b.block
                        .declared_classes
                        .iter()
                        .find_map(|c| {
                            (c.sierra_hash == SierraHash(class_hash.0))
                                .then_some(c.sierra_def.clone())
                        })
                        .map(|def| (*n, def))
                });

                if let Some(block_number_and_class_def) = block_number_and_class_def {
                    return Ok(Some(block_number_and_class_def));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::ClassDefinitionAtWithBlockNumber(
                block_id, class_hash, tx,
            ))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn storage_value(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
        storage_address: StorageAddress,
    ) -> Result<Option<StorageValue>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let storage_value = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(
                            b.block
                                .state_update
                                .contract_updates
                                .iter()
                                .map(|(address, update)| (address, &update.storage))
                                .chain(
                                    b.block
                                        .state_update
                                        .system_contract_updates
                                        .iter()
                                        .map(|(address, update)| (address, &update.storage)),
                                )
                                .find_map(|(address, storage)| {
                                    (*address == contract_address).then_some(
                                        storage.iter().find_map(|(address, value)| {
                                            (*address == storage_address).then_some(*value)
                                        }),
                                    )
                                }),
                        )
                        .and_then(|x| x)
                        .and_then(|x| x)
                });

                if let Some(storage_value) = storage_value {
                    return Ok(Some(storage_value));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let storage_value = decided_blocks.iter().rev().find_map(|(_, b)| {
                    b.block
                        .state_update
                        .contract_updates
                        .iter()
                        .map(|(address, update)| (address, &update.storage))
                        .chain(
                            b.block
                                .state_update
                                .system_contract_updates
                                .iter()
                                .map(|(address, update)| (address, &update.storage)),
                        )
                        .find_map(|(address, storage)| {
                            (*address == contract_address).then_some(storage.iter().find_map(
                                |(address, value)| (*address == storage_address).then_some(*value),
                            ))
                        })
                        .and_then(|x| x)
                });

                if let Some(storage_value) = storage_value {
                    return Ok(Some(storage_value));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::StorageValue(
                block_id,
                contract_address,
                storage_address,
                tx,
            ))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn contract_nonce(
        &self,
        contract_address: ContractAddress,
        block_id: BlockId,
    ) -> Result<Option<ContractNonce>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let nonce = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(b.block.state_update.contract_updates.iter().find_map(
                            |(address, update)| {
                                (*address == contract_address).then_some(update.nonce)
                            },
                        ))
                        .and_then(|x| x)
                        .and_then(|x| x)
                });

                if let Some(nonce) = nonce {
                    return Ok(Some(nonce));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let nonce = decided_blocks.iter().rev().find_map(|(_, b)| {
                    b.block
                        .state_update
                        .contract_updates
                        .iter()
                        .find_map(|(address, update)| {
                            (*address == contract_address).then_some(update.nonce)
                        })
                        .and_then(|x| x)
                });

                if let Some(nonce) = nonce {
                    return Ok(Some(nonce));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::ContractNonce(contract_address, block_id, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn contract_class_hash(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> Result<Option<ClassHash>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let class_hash = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(b.block.state_update.contract_updates.iter().find_map(
                            |(address, update)| {
                                (*address == contract_address)
                                    .then_some(update.class.map(|c| c.class_hash()))
                            },
                        ))
                        .and_then(|x| x)
                        .and_then(|x| x)
                });

                if let Some(class_hash) = class_hash {
                    return Ok(Some(class_hash));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let class_hash = decided_blocks.iter().rev().find_map(|(_, b)| {
                    b.block
                        .state_update
                        .contract_updates
                        .iter()
                        .find_map(|(address, update)| {
                            (*address == contract_address)
                                .then_some(update.class.map(|c| c.class_hash()))
                        })
                        .and_then(|x| x)
                });

                if let Some(class_hash) = class_hash {
                    return Ok(Some(class_hash));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::ContractClassHash(block_id, contract_address, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_hash(&self, class_hash: ClassHash) -> Result<Option<CasmHash>, StateError> {
        // Note: Decided blocks don't store legacy casm hash
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmHash(class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_hash_v2(&self, class_hash: ClassHash) -> Result<Option<CasmHash>, StateError> {
        {
            let decided_blocks = self.decided_blocks.read().unwrap();
            if let Some(casm_def) = decided_blocks.iter().find_map(|(_, b)| {
                b.block.declared_classes.iter().find_map(|c| {
                    (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_hash_v2)
                })
            }) {
                return Ok(Some(casm_def));
            }
            // Otherwise fetch from the database
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmHashV2(class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<CasmHash>, StateError> {
        match block_id {
            BlockId::Number(block_number) => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let casm_hash = decided_blocks.iter().rev().find_map(|(n, b)| {
                    (*n <= block_number)
                        .then_some(b.block.declared_classes.iter().find_map(|c| {
                            (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_hash_v2)
                        }))
                        .and_then(|x| x)
                });

                if let Some(casm_hash) = casm_hash {
                    return Ok(Some(casm_hash));
                }
                // Otherwise fetch from the database
            }
            BlockId::Hash(_) => { /* Decided blocks don't have a hash yet */ }
            BlockId::Latest => {
                let decided_blocks = self.decided_blocks.read().unwrap();
                let casm_hash = decided_blocks.iter().rev().find_map(|(_, b)| {
                    b.block.declared_classes.iter().find_map(|c| {
                        (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_hash_v2)
                    })
                });

                if let Some(casm_hash) = casm_hash {
                    return Ok(Some(casm_hash));
                }
                // Otherwise fetch from the database
            }
        }

        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmHashAt(block_id, class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }
}

fn db_thread(
    mut db_conn: pathfinder_storage::Connection,
    rx: Receiver<Command>,
    cancellation_token: CancellationToken,
) {
    let db_tx = db_conn.transaction().expect("Failed to create transaction");

    loop {
        if cancellation_token.is_cancelled() {
            return;
        }

        let Ok(command) = rx.recv() else {
            return;
        };

        match command {
            Command::BlockHash(block_id, sender) => {
                sender
                    .send(db_tx.block_hash(block_id))
                    .expect("Receiver not to be dropped");
            }
            Command::CasmDefinition(class_hash, sender) => {
                sender
                    .send(
                        db_tx
                            .casm_definition(class_hash)
                            .map_err(map_anyhow_to_state_err),
                    )
                    .expect("Receiver not to be dropped");
            }
            Command::ClassDefinitionWithBlockNumber(class_hash, sender) => sender
                .send(
                    db_tx
                        .class_definition_with_block_number(class_hash)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::CasmDefinitionAt(block_id, class_hash, sender) => {
                sender
                    .send(
                        db_tx
                            .casm_definition_at(block_id, class_hash)
                            .map_err(map_anyhow_to_state_err),
                    )
                    .expect("Receiver not to be dropped");
            }
            Command::ClassDefinitionAtWithBlockNumber(block_id, class_hash, sender) => sender
                .send(
                    db_tx
                        .class_definition_at_with_block_number(block_id, class_hash)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::StorageValue(block_id, contract_address, storage_address, sender) => sender
                .send(
                    db_tx
                        .storage_value(block_id, contract_address, storage_address)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::ContractNonce(contract_address, block_id, sender) => sender
                .send(
                    db_tx
                        .contract_nonce(contract_address, block_id)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::ContractClassHash(block_id, contract_address, sender) => sender
                .send(
                    db_tx
                        .contract_class_hash(block_id, contract_address)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::CasmHash(class_hash, sender) => sender
                .send(db_tx.casm_hash(class_hash).map_err(map_anyhow_to_state_err))
                .expect("Receiver not to be dropped"),
            Command::CasmHashV2(class_hash, sender) => sender
                .send(
                    db_tx
                        .casm_hash_v2(class_hash)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
            Command::CasmHashAt(block_id, class_hash, sender) => sender
                .send(
                    db_tx
                        .casm_hash_at(block_id, class_hash)
                        .map_err(map_anyhow_to_state_err),
                )
                .expect("Receiver not to be dropped"),
        }
    }
}
