use std::rc::Rc;

use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::state::errors::StateError;
use pathfinder_common::{BlockHash, BlockId};
use pathfinder_storage::Transaction;

use crate::state_reader::storage_adapter::{map_anyhow_to_state_err, StorageAdapter};

#[derive(Clone)]
pub struct RcStorageAdapter<'tx> {
    db_tx: Rc<pathfinder_storage::Transaction<'tx>>,
}

impl<'tx> RcStorageAdapter<'tx> {
    pub fn new(db_tx: Transaction<'tx>) -> Self {
        Self {
            db_tx: Rc::new(db_tx),
        }
    }
}

impl<'tx> StorageAdapter for RcStorageAdapter<'tx> {
    fn transaction_executor_config(&self) -> TransactionExecutorConfig {
        TransactionExecutorConfig::default()
    }

    fn block_hash(&self, block: BlockId) -> anyhow::Result<Option<BlockHash>> {
        self.db_tx.block_hash(block)
    }

    fn casm_definition(
        &self,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<Vec<u8>>, StateError> {
        self.db_tx
            .casm_definition(class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn class_definition_with_block_number(
        &self,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<(Option<pathfinder_common::BlockNumber>, Vec<u8>)>, StateError> {
        self.db_tx
            .class_definition_with_block_number(class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<Vec<u8>>, StateError> {
        self.db_tx
            .casm_definition_at(block_id, class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<(pathfinder_common::BlockNumber, Vec<u8>)>, StateError> {
        self.db_tx
            .class_definition_at_with_block_number(block_id, class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn storage_value(
        &self,
        block_id: BlockId,
        contract_address: pathfinder_common::ContractAddress,
        storage_address: pathfinder_common::StorageAddress,
    ) -> Result<Option<pathfinder_common::StorageValue>, StateError> {
        self.db_tx
            .storage_value(block_id, contract_address, storage_address)
            .map_err(map_anyhow_to_state_err)
    }

    fn contract_nonce(
        &self,
        contract_address: pathfinder_common::ContractAddress,
        block_id: BlockId,
    ) -> Result<Option<pathfinder_common::ContractNonce>, StateError> {
        self.db_tx
            .contract_nonce(contract_address, block_id)
            .map_err(map_anyhow_to_state_err)
    }

    fn contract_class_hash(
        &self,
        block_id: BlockId,
        contract_address: pathfinder_common::ContractAddress,
    ) -> Result<Option<pathfinder_common::ClassHash>, StateError> {
        self.db_tx
            .contract_class_hash(block_id, contract_address)
            .map_err(map_anyhow_to_state_err)
    }

    fn casm_hash(
        &self,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<pathfinder_common::CasmHash>, StateError> {
        self.db_tx
            .casm_hash(class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn casm_hash_v2(
        &self,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<pathfinder_common::CasmHash>, StateError> {
        self.db_tx
            .casm_hash_v2(class_hash)
            .map_err(map_anyhow_to_state_err)
    }

    fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: pathfinder_common::ClassHash,
    ) -> Result<Option<pathfinder_common::CasmHash>, StateError> {
        self.db_tx
            .casm_hash_at(block_id, class_hash)
            .map_err(map_anyhow_to_state_err)
    }
}
