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
        if let Some(casm_def) = decided::casm_definition(&self.decided_blocks, class_hash) {
            return Ok(Some(casm_def));
        }
        // Otherwise fetch from the database

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
        if let Some(block_number_and_class_def) =
            decided::class_definition_with_block_number(&self.decided_blocks, class_hash)
        {
            return Ok(Some(block_number_and_class_def));
        }
        // Otherwise fetch from the database

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
        if let Some(casm_def) =
            decided::casm_definition_at(&self.decided_blocks, block_id, class_hash)
        {
            return Ok(Some(casm_def));
        }
        // Otherwise fetch from the database

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
    ) -> Result<ClassDefinitionAtWithBlockNumber, StateError> {
        if let Some(result) = decided::class_definition_at_with_block_number(
            &self.decided_blocks,
            block_id,
            class_hash,
        ) {
            return Ok(Some(result));
        }
        // Otherwise fetch from the database

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
        if let Some(value) = decided::storage_value(
            &self.decided_blocks,
            block_id,
            contract_address,
            storage_address,
        ) {
            return Ok(Some(value));
        }
        // Otherwise fetch from the database

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
        if let Some(nonce) =
            decided::contract_nonce(&self.decided_blocks, contract_address, block_id)
        {
            return Ok(Some(nonce));
        }
        // Otherwise fetch from the database

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
        if let Some(class_hash) =
            decided::contract_class_hash(&self.decided_blocks, block_id, contract_address)
        {
            return Ok(Some(class_hash));
        }
        // Otherwise fetch from the database

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
        if let Some(casm_hash) = decided::casm_hash_v2(&self.decided_blocks, class_hash) {
            return Ok(Some(casm_hash));
        }
        // Otherwise fetch from the database

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
        if let Some(casm_hash) = decided::casm_hash_at(&self.decided_blocks, block_id, class_hash) {
            return Ok(Some(casm_hash));
        }
        // Otherwise fetch from the database

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

mod decided {
    use std::collections::BTreeMap;
    use std::sync::RwLockReadGuard;

    use pathfinder_common::{
        BlockId,
        BlockNumber,
        CasmHash,
        ClassHash,
        ContractAddress,
        ContractNonce,
        DecidedBlock,
        DecidedBlocks,
        SierraHash,
        StorageAddress,
        StorageValue,
    };

    use crate::state_reader::storage_adapter::ClassDefinitionAtWithBlockNumber;

    fn rev_blocks_by_id<'a>(
        decided_blocks: &'a RwLockReadGuard<'a, BTreeMap<BlockNumber, DecidedBlock>>,
        block_id: BlockId,
    ) -> impl Iterator<Item = (BlockNumber, &'a DecidedBlock)> + 'a {
        match block_id {
            BlockId::Number(block_number) => Box::new(
                decided_blocks
                    .range(..=block_number)
                    .rev()
                    .map(|(n, b)| (*n, b)),
            ),
            BlockId::Hash(_) => {
                // Decided blocks don't have a hash yet
                Box::new(std::iter::empty())
                    as Box<dyn Iterator<Item = (BlockNumber, &DecidedBlock)>>
            }
            BlockId::Latest => Box::new(decided_blocks.iter().rev().map(|(n, b)| (*n, b))),
        }
    }

    pub fn casm_definition(
        decided_blocks: &DecidedBlocks,
        class_hash: ClassHash,
    ) -> Option<Vec<u8>> {
        let decided_blocks = decided_blocks.read().unwrap();
        decided_blocks.iter().find_map(|(_, b)| {
            b.block.declared_classes.iter().find_map(|c| {
                (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_def.clone())
            })
        })
    }

    pub fn class_definition_with_block_number(
        decided_blocks: &DecidedBlocks,
        class_hash: ClassHash,
    ) -> Option<(Option<BlockNumber>, Vec<u8>)> {
        let decided_blocks = decided_blocks.read().unwrap();
        decided_blocks.iter().find_map(|(n, b)| {
            b.block.declared_classes.iter().find_map(|c| {
                (c.sierra_hash == SierraHash(class_hash.0))
                    .then_some((Some(*n), c.sierra_def.clone()))
            })
        })
    }

    pub fn casm_definition_at(
        decided_blocks: &DecidedBlocks,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Option<Vec<u8>> {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id).find_map(|(_, b)| {
            b.block.declared_classes.iter().find_map(|c| {
                (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_def.clone())
            })
        });
        drop(guard);
        result
    }

    pub fn class_definition_at_with_block_number(
        decided_blocks: &DecidedBlocks,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> ClassDefinitionAtWithBlockNumber {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id).find_map(|(n, b)| {
            b.block
                .declared_classes
                .iter()
                .find_map(|c| {
                    (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.sierra_def.clone())
                })
                .map(|def| (n, def))
        });
        drop(guard);
        result
    }

    pub fn storage_value(
        decided_blocks: &DecidedBlocks,
        block_id: BlockId,
        contract_address: ContractAddress,
        storage_address: StorageAddress,
    ) -> Option<StorageValue> {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id).find_map(|(_, b)| {
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
                    (*address == contract_address).then_some(storage.get(&storage_address).copied())
                })
                .flatten()
        });
        drop(guard);
        result
    }

    pub fn contract_nonce(
        decided_blocks: &DecidedBlocks,
        contract_address: ContractAddress,
        block_id: BlockId,
    ) -> Option<ContractNonce> {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id)
            .find_map(|(_, b)| {
                b.block
                    .state_update
                    .contract_updates
                    .get(&contract_address)
                    .map(|update| update.nonce)
            })
            .flatten();
        drop(guard);
        result
    }

    pub fn contract_class_hash(
        decided_blocks: &DecidedBlocks,
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> Option<ClassHash> {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id)
            .find_map(|(_, b)| {
                b.block
                    .state_update
                    .contract_updates
                    .get(&contract_address)
                    .map(|update| update.class.map(|c| c.class_hash()))
            })
            .flatten();
        drop(guard);
        result
    }

    pub fn casm_hash_v2(decided_blocks: &DecidedBlocks, class_hash: ClassHash) -> Option<CasmHash> {
        let decided_blocks = decided_blocks.read().unwrap();
        decided_blocks.iter().find_map(|(_, b)| {
            b.block
                .declared_classes
                .iter()
                .find_map(|c| (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_hash_v2))
        })
    }

    pub fn casm_hash_at(
        decided_blocks: &DecidedBlocks,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Option<CasmHash> {
        let guard = decided_blocks.read().unwrap();
        // Let binding and drop to avoid: "guard` does not live long enough"
        let result = rev_blocks_by_id(&guard, block_id).find_map(|(_, b)| {
            b.block
                .declared_classes
                .iter()
                .find_map(|c| (c.sierra_hash == SierraHash(class_hash.0)).then_some(c.casm_hash_v2))
        });
        drop(guard);
        result
    }

    #[cfg(test)]
    mod tests {
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, RwLock};

        use pathfinder_common::state_update::{
            ContractClassUpdate,
            ContractUpdate,
            StateUpdateData,
            SystemContractUpdate,
        };
        use pathfinder_common::{
            BlockHash,
            BlockNumber,
            CasmHash,
            ClassHash,
            ConsensusFinalizedL2Block,
            ContractAddress,
            ContractNonce,
            DecidedBlock,
            DecidedBlocks,
            DeclaredClass,
            SierraHash,
            StorageAddress,
            StorageValue,
        };
        use pathfinder_crypto::Felt;

        fn matching_genesis() -> (BlockNumber, DecidedBlock) {
            let block = ConsensusFinalizedL2Block {
                declared_classes: vec![DeclaredClass {
                    sierra_hash: SierraHash::ZERO,
                    casm_hash_v2: CasmHash::ZERO,
                    sierra_def: vec![0],
                    casm_def: vec![1],
                }],
                state_update: StateUpdateData {
                    contract_updates: HashMap::from([
                        (
                            ContractAddress::ZERO,
                            ContractUpdate {
                                storage: HashMap::from([(
                                    StorageAddress::ZERO,
                                    StorageValue::ZERO,
                                )]),
                                nonce: Some(ContractNonce::ZERO),
                                class: Some(ContractClassUpdate::Deploy(ClassHash::ZERO)),
                            },
                        ),
                        (
                            ContractAddress::ONE,
                            ContractUpdate {
                                class: Some(ContractClassUpdate::Replace(ClassHash::ZERO)),
                                ..Default::default()
                            },
                        ),
                    ]),
                    system_contract_updates: HashMap::from([(
                        ContractAddress::TWO,
                        SystemContractUpdate {
                            storage: HashMap::from([(
                                StorageAddress(Felt::ONE),
                                StorageValue(Felt::ONE),
                            )]),
                        },
                    )]),
                    ..Default::default()
                },
                ..Default::default()
            };

            (BlockNumber::GENESIS, DecidedBlock { round: 0, block })
        }

        fn dummy_block_one() -> (BlockNumber, DecidedBlock) {
            (
                BlockNumber::GENESIS + 1,
                DecidedBlock {
                    round: 0,
                    block: Default::default(),
                },
            )
        }

        fn one() -> DecidedBlocks {
            Arc::new(RwLock::new(BTreeMap::from([matching_genesis()])))
        }

        fn two() -> DecidedBlocks {
            Arc::new(RwLock::new(BTreeMap::from([
                matching_genesis(),
                dummy_block_one(),
            ])))
        }

        mod casm_definition {
            use super::super::*;
            use super::two;

            #[test]
            fn in_empty_returns_none() {
                assert!(casm_definition(&DecidedBlocks::default(), ClassHash::ZERO).is_none());
            }

            #[test]
            fn success() {
                assert_eq!(casm_definition(&two(), ClassHash::ZERO), Some(vec![1]));
            }
        }

        mod class_definition_with_block_number {
            use super::super::*;
            use super::two;

            #[test]
            fn in_empty_returns_none() {
                assert!(class_definition_with_block_number(
                    &DecidedBlocks::default(),
                    ClassHash::ZERO
                )
                .is_none());
            }

            #[test]
            fn success() {
                assert_eq!(
                    class_definition_with_block_number(&two(), ClassHash::ZERO),
                    Some((Some(BlockNumber::GENESIS), vec![0]))
                );
            }
        }

        mod casm_definition_at {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(casm_definition_at(
                    &DecidedBlocks::default(),
                    BlockId::Number(BlockNumber::GENESIS),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                assert_eq!(
                    casm_definition_at(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ClassHash::ZERO,
                    ),
                    Some(vec![1])
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                assert_eq!(
                    casm_definition_at(
                        &two(),
                        // Note: it's the genesis block that contains the matching class
                        // definition
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ClassHash::ZERO,
                    ),
                    Some(vec![1])
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(casm_definition_at(
                    &DecidedBlocks::default(),
                    BlockId::Hash(BlockHash::ZERO),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(casm_definition_at(
                    &DecidedBlocks::default(),
                    BlockId::Latest,
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_instant_match() {
                assert_eq!(
                    casm_definition_at(&one(), BlockId::Latest, ClassHash::ZERO,),
                    Some(vec![1])
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                assert_eq!(
                    casm_definition_at(&two(), BlockId::Latest, ClassHash::ZERO,),
                    Some(vec![1])
                );
            }
        }

        mod class_definition_at_with_block_number {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(class_definition_at_with_block_number(
                    &DecidedBlocks::default(),
                    BlockId::Number(BlockNumber::GENESIS),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                assert_eq!(
                    class_definition_at_with_block_number(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ClassHash::ZERO,
                    ),
                    Some((BlockNumber::GENESIS, vec![0]))
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                assert_eq!(
                    class_definition_at_with_block_number(
                        &two(),
                        // Note: it's the genesis block that contains the matching class
                        // definition
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ClassHash::ZERO,
                    ),
                    Some((BlockNumber::GENESIS, vec![0]))
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(class_definition_at_with_block_number(
                    &DecidedBlocks::default(),
                    BlockId::Hash(BlockHash::ZERO),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(class_definition_at_with_block_number(
                    &DecidedBlocks::default(),
                    BlockId::Latest,
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_instant_match() {
                assert_eq!(
                    class_definition_at_with_block_number(&one(), BlockId::Latest, ClassHash::ZERO),
                    Some((BlockNumber::GENESIS, vec![0]))
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                assert_eq!(
                    class_definition_at_with_block_number(&two(), BlockId::Latest, ClassHash::ZERO),
                    Some((BlockNumber::GENESIS, vec![0]))
                );
            }
        }

        mod storage_value {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(storage_value(
                    &DecidedBlocks::default(),
                    BlockId::Number(BlockNumber::GENESIS),
                    ContractAddress::ZERO,
                    StorageAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                // "Normal" contract
                assert_eq!(
                    storage_value(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ContractAddress::ZERO,
                        StorageAddress::ZERO,
                    ),
                    Some(StorageValue::ZERO)
                );
                // System contract
                assert_eq!(
                    storage_value(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ContractAddress::TWO,
                        StorageAddress(Felt::ONE),
                    ),
                    Some(StorageValue(Felt::ONE))
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                // "Normal" contract
                assert_eq!(
                    storage_value(
                        &two(),
                        // Note: it's the genesis block that contains the matching storage entry
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ContractAddress::ZERO,
                        StorageAddress::ZERO,
                    ),
                    Some(StorageValue::ZERO)
                );
                // System contract
                assert_eq!(
                    storage_value(
                        &two(),
                        // Note: it's the genesis block that contains the matching storage entry
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ContractAddress::TWO,
                        StorageAddress(Felt::ONE),
                    ),
                    Some(StorageValue(Felt::ONE))
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(storage_value(
                    &DecidedBlocks::default(),
                    BlockId::Hash(BlockHash::ZERO),
                    ContractAddress::ZERO,
                    StorageAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(storage_value(
                    &DecidedBlocks::default(),
                    BlockId::Latest,
                    ContractAddress::ZERO,
                    StorageAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_instant_match() {
                // "Normal" contract
                assert_eq!(
                    storage_value(
                        &one(),
                        BlockId::Latest,
                        ContractAddress::ZERO,
                        StorageAddress::ZERO
                    ),
                    Some(StorageValue::ZERO)
                );
                // System contract
                assert_eq!(
                    storage_value(
                        &one(),
                        BlockId::Latest,
                        ContractAddress::TWO,
                        StorageAddress(Felt::ONE)
                    ),
                    Some(StorageValue(Felt::ONE))
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                // "Normal" contract
                assert_eq!(
                    storage_value(
                        &two(),
                        BlockId::Latest,
                        ContractAddress::ZERO,
                        StorageAddress::ZERO
                    ),
                    Some(StorageValue::ZERO)
                );
                // System contract
                assert_eq!(
                    storage_value(
                        &two(),
                        BlockId::Latest,
                        ContractAddress::TWO,
                        StorageAddress(Felt::ONE)
                    ),
                    Some(StorageValue(Felt::ONE))
                );
            }
        }

        mod contract_nonce {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(contract_nonce(
                    &DecidedBlocks::default(),
                    ContractAddress::ZERO,
                    BlockId::Number(BlockNumber::GENESIS),
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                assert_eq!(
                    contract_nonce(
                        &one(),
                        ContractAddress::ZERO,
                        BlockId::Number(BlockNumber::GENESIS),
                    ),
                    Some(ContractNonce::ZERO)
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                assert_eq!(
                    contract_nonce(
                        &two(),
                        // Note: it's the genesis block that contains the matching nonce
                        ContractAddress::ZERO,
                        BlockId::Number(BlockNumber::GENESIS + 1),
                    ),
                    Some(ContractNonce::ZERO)
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(contract_nonce(
                    &DecidedBlocks::default(),
                    ContractAddress::ZERO,
                    BlockId::Hash(BlockHash::ZERO),
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(contract_nonce(
                    &DecidedBlocks::default(),
                    ContractAddress::ZERO,
                    BlockId::Latest,
                )
                .is_none());
            }

            #[test]
            fn latest_instant_match() {
                assert_eq!(
                    contract_nonce(&one(), ContractAddress::ZERO, BlockId::Latest),
                    Some(ContractNonce::ZERO)
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                assert_eq!(
                    contract_nonce(&two(), ContractAddress::ZERO, BlockId::Latest),
                    Some(ContractNonce::ZERO)
                );
            }
        }

        mod contract_class_hash {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(contract_class_hash(
                    &DecidedBlocks::default(),
                    BlockId::Number(BlockNumber::GENESIS),
                    ContractAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                // Deployed
                assert_eq!(
                    contract_class_hash(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ContractAddress::ZERO,
                    ),
                    Some(ClassHash::ZERO)
                );
                // Replaced
                assert_eq!(
                    contract_class_hash(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ContractAddress::ONE,
                    ),
                    Some(ClassHash::ZERO)
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                // Deployed
                assert_eq!(
                    contract_class_hash(
                        &two(),
                        // Note: it's the genesis block that contains the matching class hash
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ContractAddress::ZERO,
                    ),
                    Some(ClassHash::ZERO)
                );
                // Replaced
                assert_eq!(
                    contract_class_hash(
                        &two(),
                        // Note: it's the genesis block that contains the matching class hash
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ContractAddress::ONE,
                    ),
                    Some(ClassHash::ZERO)
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(contract_class_hash(
                    &DecidedBlocks::default(),
                    BlockId::Hash(BlockHash::ZERO),
                    ContractAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(contract_class_hash(
                    &DecidedBlocks::default(),
                    BlockId::Latest,
                    ContractAddress::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_instant_match() {
                // Deployed
                assert_eq!(
                    contract_class_hash(&one(), BlockId::Latest, ContractAddress::ZERO),
                    Some(ClassHash::ZERO)
                );
                // Replaced
                assert_eq!(
                    contract_class_hash(&one(), BlockId::Latest, ContractAddress::ONE),
                    Some(ClassHash::ZERO)
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                // Deployed
                assert_eq!(
                    contract_class_hash(&two(), BlockId::Latest, ContractAddress::ZERO),
                    Some(ClassHash::ZERO)
                );
                // Replaced
                assert_eq!(
                    contract_class_hash(&two(), BlockId::Latest, ContractAddress::ONE),
                    Some(ClassHash::ZERO)
                );
            }
        }

        mod casm_hash_v2 {
            use super::super::*;
            use super::two;

            #[test]
            fn in_empty_returns_none() {
                assert!(casm_hash_v2(&DecidedBlocks::default(), ClassHash::ZERO).is_none());
            }

            #[test]
            fn success() {
                assert_eq!(casm_hash_v2(&two(), ClassHash::ZERO), Some(CasmHash::ZERO));
            }
        }

        mod casm_hash_at {
            use super::super::*;
            use super::*;

            #[test]
            fn by_number_in_empty_returns_none() {
                assert!(casm_hash_at(
                    &DecidedBlocks::default(),
                    BlockId::Number(BlockNumber::GENESIS),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn by_number_exact_match() {
                assert_eq!(
                    casm_hash_at(
                        &one(),
                        BlockId::Number(BlockNumber::GENESIS),
                        ClassHash::ZERO,
                    ),
                    Some(CasmHash::ZERO)
                );
            }

            #[test]
            fn by_number_skips_blocks_that_dont_match() {
                assert_eq!(
                    casm_hash_at(
                        &two(),
                        // Note: it's the genesis block that contains the matching class
                        BlockId::Number(BlockNumber::GENESIS + 1),
                        ClassHash::ZERO,
                    ),
                    Some(CasmHash::ZERO)
                );
            }

            #[test]
            fn by_hash_returns_none() {
                assert!(casm_hash_at(
                    &DecidedBlocks::default(),
                    BlockId::Hash(BlockHash::ZERO),
                    ClassHash::ZERO,
                )
                .is_none());
            }

            #[test]
            fn latest_in_empty_returns_none() {
                assert!(
                    casm_hash_at(&DecidedBlocks::default(), BlockId::Latest, ClassHash::ZERO,)
                        .is_none()
                );
            }

            #[test]
            fn latest_instant_match() {
                assert_eq!(
                    casm_hash_at(&one(), BlockId::Latest, ClassHash::ZERO),
                    Some(CasmHash::ZERO)
                );
            }

            #[test]
            fn latest_skips_blocks_that_dont_match() {
                assert_eq!(
                    casm_hash_at(&two(), BlockId::Latest, ClassHash::ZERO),
                    Some(CasmHash::ZERO)
                );
            }
        }
    }
}
