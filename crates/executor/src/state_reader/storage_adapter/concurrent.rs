use std::sync::mpsc::{self, Receiver, Sender, SyncSender};

use blockifier::blockifier::config::{ConcurrencyConfig, TransactionExecutorConfig};
use blockifier::state::errors::StateError;
use pathfinder_common::{
    BlockHash,
    BlockNumber,
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    StorageAddress,
    StorageValue,
};
use pathfinder_storage::{BlockId, Connection};
use tokio_util::sync::CancellationToken;

use crate::state_reader::storage_adapter::{map_anyhow_to_state_err, StorageAdapter};

#[derive(Clone)]
pub struct ConcurrentStorageAdapter {
    tx: Sender<Command>,
}

enum Command {
    BlockHash(BlockId, SyncSender<anyhow::Result<Option<BlockHash>>>),
    CasmDefinition(ClassHash, SyncSender<Result<Option<Vec<u8>>, StateError>>),
    ClassDefinitionWithBlockNumber(
        ClassHash,
        SyncSender<Result<Option<(Option<BlockNumber>, Vec<u8>)>, StateError>>,
    ),
    CasmDefinitionAt(
        BlockId,
        ClassHash,
        SyncSender<Result<Option<Vec<u8>>, StateError>>,
    ),
    ClassDefinitionAtWithBlockNumber(
        BlockId,
        ClassHash,
        SyncSender<Result<Option<(BlockNumber, Vec<u8>)>, StateError>>,
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
    CasmHashAt(
        BlockId,
        ClassHash,
        SyncSender<Result<Option<CasmHash>, StateError>>,
    ),
}

impl ConcurrentStorageAdapter {
    pub fn new(db_conn: Connection) -> Self {
        let (tx, rx) = mpsc::channel();

        util::task::spawn_std(move |cancellation_token| db_thread(db_conn, rx, cancellation_token));

        Self { tx }
    }
}

impl StorageAdapter for ConcurrentStorageAdapter {
    fn transaction_executor_config(&self) -> TransactionExecutorConfig {
        let n_workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1);

        TransactionExecutorConfig {
            concurrency_config: ConcurrencyConfig {
                enabled: true,
                n_workers,
                chunk_size: 4, // TODO(validator) make it configurable or pick a reasonable default
            },
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
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::ContractClassHash(block_id, contract_address, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_hash(&self, class_hash: ClassHash) -> Result<Option<CasmHash>, StateError> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .send(Command::CasmHash(class_hash, tx))
            .expect("Receiver not to be dropped");
        rx.recv().expect("Channel not to be closed")
    }

    fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<CasmHash>, StateError> {
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
