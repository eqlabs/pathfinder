use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::state::errors::StateError;
use pathfinder_common::{
    BlockHash,
    BlockId,
    BlockNumber,
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    StorageAddress,
    StorageValue,
};

pub mod concurrent;
pub mod rc;

// Keep clippy happy
type ClassDefinitionAtWithBlockNumber = Option<(BlockNumber, Vec<u8>)>;
type ClassDefinitionWithBlockNumber = Option<(Option<BlockNumber>, Vec<u8>)>;

pub trait StorageAdapter {
    fn transaction_executor_config(&self) -> TransactionExecutorConfig;

    fn block_hash(&self, block: BlockId) -> anyhow::Result<Option<BlockHash>>;

    fn casm_definition(&self, class_hash: ClassHash) -> Result<Option<Vec<u8>>, StateError>;

    fn class_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> Result<ClassDefinitionWithBlockNumber, StateError>;

    fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<Vec<u8>>, StateError>;

    fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<(BlockNumber, Vec<u8>)>, StateError>;

    fn storage_value(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
        storage_address: StorageAddress,
    ) -> Result<Option<StorageValue>, StateError>;

    fn contract_nonce(
        &self,
        contract_address: ContractAddress,
        block_id: BlockId,
    ) -> Result<Option<ContractNonce>, StateError>;

    fn contract_class_hash(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> Result<Option<ClassHash>, StateError>;

    fn casm_hash(&self, class_hash: ClassHash) -> Result<Option<CasmHash>, StateError>;
    fn casm_hash_v2(&self, class_hash: ClassHash) -> Result<Option<CasmHash>, StateError>;

    fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> Result<Option<CasmHash>, StateError>;
}

fn map_anyhow_to_state_err(error: anyhow::Error) -> StateError {
    tracing::error!(%error, "Internal error in execution state reader");
    StateError::StateReadError(error.to_string())
}
