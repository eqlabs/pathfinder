use std::collections::HashMap;

mod block;
mod class;
mod ethereum;
mod event;
mod reference;
mod signature;
mod state_update;
mod transaction;
mod trie;

// Re-export this so users don't require rusqlite as a direct dep.
pub use rusqlite::TransactionBehavior;

pub use event::KEY_FILTER_LIMIT as EVENT_KEY_FILTER_LIMIT;
pub use event::*;

pub use transaction::TransactionStatus;

pub use trie::{Child, Node, StoredNode};

use pathfinder_common::{
    BlockCommitmentSignature, BlockHash, BlockHeader, BlockNumber, CasmHash, ClassCommitment,
    ClassCommitmentLeafHash, ClassHash, ContractAddress, ContractNonce, ContractRoot,
    ContractStateHash, SierraHash, StateUpdate, StorageAddress, StorageCommitment, StorageValue,
    TransactionHash,
};
use pathfinder_crypto::Felt;
use pathfinder_ethereum::EthereumStateUpdate;
use starknet_gateway_types::reply::transaction as gateway;

use crate::BlockId;

type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

pub struct Connection(PooledConnection);

impl Connection {
    pub(crate) fn from_inner(inner: PooledConnection) -> Self {
        Self(inner)
    }

    pub fn transaction(&mut self) -> anyhow::Result<Transaction<'_>> {
        let tx = self.0.transaction()?;
        Ok(Transaction(tx))
    }

    pub fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> anyhow::Result<Transaction<'_>> {
        let tx = self.0.transaction_with_behavior(behavior)?;
        Ok(Transaction(tx))
    }
}

pub struct Transaction<'inner>(rusqlite::Transaction<'inner>);

impl<'inner> Transaction<'inner> {
    // The implementations here are intentionally kept as simple wrappers. This lets the real implementations
    // be kept in separate files with more reasonable LOC counts and easier test oversight.

    #[cfg(test)]
    pub(crate) fn from_inner(tx: rusqlite::Transaction<'inner>) -> Self {
        Self(tx)
    }

    pub fn insert_contract_state_hash(
        &self,
        block_number: BlockNumber,
        contract: ContractAddress,
        state_hash: ContractStateHash,
    ) -> anyhow::Result<()> {
        trie::insert_contract_state_hash(self, block_number, contract, state_hash)
    }

    pub fn contract_state_hash(
        &self,
        block: BlockNumber,
        contract: ContractAddress,
    ) -> anyhow::Result<Option<ContractStateHash>> {
        trie::contract_state_hash(self, block, contract)
    }

    pub fn insert_block_header(&self, header: &BlockHeader) -> anyhow::Result<()> {
        block::insert_block_header(self, header)
    }

    pub fn block_header(&self, block: BlockId) -> anyhow::Result<Option<BlockHeader>> {
        block::block_header(self, block)
    }

    /// Removes all data related to this block.
    ///
    /// This includes block header, block body and state update information.
    pub fn purge_block(&self, block: BlockNumber) -> anyhow::Result<()> {
        block::purge_block(self, block)
    }

    pub fn block_id(&self, block: BlockId) -> anyhow::Result<Option<(BlockNumber, BlockHash)>> {
        block::block_id(self, block)
    }

    pub fn block_exists(&self, block: BlockId) -> anyhow::Result<bool> {
        block::block_exists(self, block)
    }

    pub fn block_is_l1_accepted(&self, block: BlockId) -> anyhow::Result<bool> {
        block::block_is_l1_accepted(self, block)
    }

    pub fn update_l1_l2_pointer(&self, block: Option<BlockNumber>) -> anyhow::Result<()> {
        reference::update_l1_l2_pointer(self, block)
    }

    pub fn l1_l2_pointer(&self) -> anyhow::Result<Option<BlockNumber>> {
        reference::l1_l2_pointer(self)
    }

    pub fn upsert_l1_state(&self, update: &EthereumStateUpdate) -> anyhow::Result<()> {
        ethereum::upsert_l1_state(self, update)
    }

    pub fn l1_state_at_number(
        &self,
        block: BlockNumber,
    ) -> anyhow::Result<Option<EthereumStateUpdate>> {
        ethereum::l1_state_at_number(self, block)
    }

    pub fn latest_l1_state(&self) -> anyhow::Result<Option<EthereumStateUpdate>> {
        ethereum::latest_l1_state(self)
    }

    /// Inserts the transaction, receipt and event data.
    pub fn insert_transaction_data(
        &self,
        block_hash: BlockHash,
        block_number: BlockNumber,
        transaction_data: &[(gateway::Transaction, gateway::Receipt)],
    ) -> anyhow::Result<()> {
        transaction::insert_transactions(self, block_hash, block_number, transaction_data)
    }

    pub fn transaction_block_hash(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<BlockHash>> {
        transaction::transaction_block_hash(self, hash)
    }

    pub fn transaction(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<gateway::Transaction>> {
        transaction::transaction(self, hash)
    }

    pub fn transaction_with_receipt(
        &self,
        hash: TransactionHash,
    ) -> anyhow::Result<Option<(gateway::Transaction, gateway::Receipt, BlockHash)>> {
        transaction::transaction_with_receipt(self, hash)
    }

    pub fn transaction_at_block(
        &self,
        block: BlockId,
        index: usize,
    ) -> anyhow::Result<Option<gateway::Transaction>> {
        transaction::transaction_at_block(self, block, index)
    }

    pub fn transaction_data_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<(gateway::Transaction, gateway::Receipt)>>> {
        transaction::transaction_data_for_block(self, block)
    }

    pub fn transactions_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<gateway::Transaction>>> {
        transaction::transactions_for_block(self, block)
    }

    pub fn transaction_hashes_for_block(
        &self,
        block: BlockId,
    ) -> anyhow::Result<Option<Vec<TransactionHash>>> {
        transaction::transaction_hashes_for_block(self, block)
    }

    pub fn transaction_count(&self, block: BlockId) -> anyhow::Result<usize> {
        transaction::transaction_count(self, block)
    }

    pub fn events(
        &self,
        filter: &EventFilter<impl KeyFilter>,
    ) -> Result<PageOfEvents, EventFilterError> {
        event::get_events(self, filter)
    }

    pub fn event_count_for_block(&self, block: BlockId) -> anyhow::Result<usize> {
        event::event_count_for_block(self, block)
    }

    pub fn insert_sierra_class(
        &self,
        sierra_hash: &SierraHash,
        sierra_definition: &[u8],
        casm_hash: &CasmHash,
        casm_definition: &[u8],
        compiler_version: &str,
    ) -> anyhow::Result<()> {
        class::insert_sierra_class(
            self,
            sierra_hash,
            sierra_definition,
            casm_hash,
            casm_definition,
            compiler_version,
        )
    }

    // TODO: create a CairoHash if sensible instead.
    pub fn insert_cairo_class(
        &self,
        cairo_hash: ClassHash,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        class::insert_cairo_class(self, cairo_hash, definition)
    }

    pub fn insert_class_commitment_leaf(
        &self,
        block: BlockNumber,
        leaf: &ClassCommitmentLeafHash,
        casm_hash: &CasmHash,
    ) -> anyhow::Result<()> {
        class::insert_class_commitment_leaf(self, block, leaf, casm_hash)
    }

    pub fn class_commitment_leaf(
        &self,
        block: BlockNumber,
        casm_hash: &CasmHash,
    ) -> anyhow::Result<Option<ClassCommitmentLeafHash>> {
        class::class_commitment_leaf(self, block, casm_hash)
    }

    /// Returns whether the Sierra or Cairo class definition exists in the database.
    ///
    /// Note that this does not indicate that the class is actually declared -- only that we stored it.
    pub fn class_definitions_exist(&self, classes: &[ClassHash]) -> anyhow::Result<Vec<bool>> {
        class::classes_exist(self, classes)
    }

    /// Returns the uncompressed class definition.
    pub fn class_definition(&self, class_hash: ClassHash) -> anyhow::Result<Option<Vec<u8>>> {
        class::class_definition(self, class_hash)
    }

    /// Returns the uncompressed class definition as well as the block number at which it was declared.
    pub fn class_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        class::class_definition_with_block_number(self, class_hash)
    }

    /// Returns the compressed class definition if it has been declared at `block_id`.
    pub fn compressed_class_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        class::compressed_class_definition_at(self, block_id, class_hash)
    }

    /// Returns the uncompressed class definition if it has been declared at `block_id`.
    pub fn class_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        class::class_definition_at(self, block_id, class_hash)
    }

    /// Returns the uncompressed class definition if it has been declared at `block_id`, as well as
    /// the block number at which it was declared.
    pub fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(BlockNumber, Vec<u8>)>> {
        class::class_definition_at_with_block_number(self, block_id, class_hash)
    }

    /// Returns the uncompressed compiled class definition.
    pub fn casm_definition(&self, class_hash: ClassHash) -> anyhow::Result<Option<Vec<u8>>> {
        class::casm_definition(self, class_hash)
    }

    /// Returns the uncompressed compiled class definition, as well as the block number at which it
    ///  was declared.
    pub fn casm_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        class::casm_definition_with_block_number(self, class_hash)
    }

    /// Returns the uncompressed compiled class definition if it has been declared at `block_id`.
    pub fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        class::casm_definition_at(self, block_id, class_hash)
    }

    /// Returns the uncompressed compiled class definition if it has been declared at `block_id`, as well
    /// as the block number at which it was declared.
    pub fn casm_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        class::casm_definition_at_with_block_number(self, block_id, class_hash)
    }

    pub fn contract_class_hash(
        &self,
        block_id: BlockId,
        contract_address: ContractAddress,
    ) -> anyhow::Result<Option<ClassHash>> {
        state_update::contract_class_hash(self, block_id, contract_address)
    }

    /// Returns the compiled class hash for a class.
    pub fn casm_hash(&self, class_hash: ClassHash) -> anyhow::Result<Option<CasmHash>> {
        class::casm_hash(self, class_hash)
    }

    /// Returns the compiled class hash for a class if it has been declared at `block_id`.
    pub fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<CasmHash>> {
        class::casm_hash_at(self, block_id, class_hash)
    }

    /// Stores the class trie information.
    pub fn insert_class_trie(
        &self,
        root: ClassCommitment,
        nodes: &HashMap<Felt, Node>,
    ) -> anyhow::Result<u64> {
        trie::trie_class::insert(self, root.0, nodes)
    }

    /// Stores a single contract's storage trie information.
    pub fn insert_contract_trie(
        &self,
        root: ContractRoot,
        nodes: &HashMap<Felt, Node>,
    ) -> anyhow::Result<u64> {
        trie::trie_contracts::insert(self, root.0, nodes)
    }

    /// Stores the global starknet storage trie information.
    pub fn insert_storage_trie(
        &self,
        root: StorageCommitment,
        nodes: &HashMap<Felt, Node>,
    ) -> anyhow::Result<u64> {
        trie::trie_storage::insert(self, root.0, nodes)
    }

    pub fn class_trie_node(&self, index: u64) -> anyhow::Result<Option<StoredNode>> {
        trie::trie_class::node(self, index)
    }

    pub fn storage_trie_node(&self, index: u64) -> anyhow::Result<Option<StoredNode>> {
        trie::trie_storage::node(self, index)
    }

    pub fn contract_trie_node(&self, index: u64) -> anyhow::Result<Option<StoredNode>> {
        trie::trie_contracts::node(self, index)
    }

    pub fn class_trie_node_hash(&self, index: u64) -> anyhow::Result<Option<Felt>> {
        trie::trie_class::hash(self, index)
    }

    pub fn storage_trie_node_hash(&self, index: u64) -> anyhow::Result<Option<Felt>> {
        trie::trie_storage::hash(self, index)
    }

    pub fn contract_trie_node_hash(&self, index: u64) -> anyhow::Result<Option<Felt>> {
        trie::trie_contracts::hash(self, index)
    }

    pub fn class_root_index(&self, block: BlockNumber) -> anyhow::Result<Option<u64>> {
        trie::class_root_index(self, block)
    }

    pub fn storage_root_index(&self, block: BlockNumber) -> anyhow::Result<Option<u64>> {
        trie::storage_root_index(self, block)
    }

    pub fn contract_root_index(
        &self,
        block: BlockNumber,
        contract: ContractAddress,
    ) -> anyhow::Result<Option<u64>> {
        trie::contract_root_index(self, block, contract)
    }

    pub fn contract_root(
        &self,
        block: BlockNumber,
        contract: ContractAddress,
    ) -> anyhow::Result<Option<ContractRoot>> {
        trie::contract_root(self, block, contract)
    }

    pub fn insert_class_root(
        &self,
        block_number: BlockNumber,
        root: Option<u64>,
    ) -> anyhow::Result<()> {
        trie::insert_class_root(self, block_number, root)
    }

    pub fn insert_storage_root(
        &self,
        block_number: BlockNumber,
        root: Option<u64>,
    ) -> anyhow::Result<()> {
        trie::insert_storage_root(self, block_number, root)
    }

    pub fn insert_contract_root(
        &self,
        block_number: BlockNumber,
        contract: ContractAddress,
        root: Option<u64>,
    ) -> anyhow::Result<()> {
        trie::insert_contract_root(self, block_number, contract, root)
    }

    pub fn insert_state_update(
        &self,
        block_number: BlockNumber,
        state_update: &StateUpdate,
    ) -> anyhow::Result<()> {
        state_update::insert_state_update(self, block_number, state_update)
    }

    pub fn state_update(&self, block: BlockId) -> anyhow::Result<Option<StateUpdate>> {
        state_update::state_update(self, block)
    }

    pub fn storage_value(
        &self,
        block: BlockId,
        contract_address: ContractAddress,
        key: StorageAddress,
    ) -> anyhow::Result<Option<StorageValue>> {
        state_update::storage_value(self, block, contract_address, key)
    }

    pub fn contract_nonce(
        &self,
        contract_address: ContractAddress,
        block_id: BlockId,
    ) -> anyhow::Result<Option<ContractNonce>> {
        state_update::contract_nonce(self, contract_address, block_id)
    }

    pub fn contract_exists(
        &self,
        contract_address: ContractAddress,
        block_id: BlockId,
    ) -> anyhow::Result<bool> {
        state_update::contract_exists(self, contract_address, block_id)
    }

    pub fn insert_signature(
        &self,
        block_number: BlockNumber,
        signature: &BlockCommitmentSignature,
    ) -> anyhow::Result<()> {
        signature::insert_signature(self, block_number, signature)
    }

    pub fn signature(&self, block: BlockId) -> anyhow::Result<Option<BlockCommitmentSignature>> {
        signature::signature(self, block)
    }

    pub(self) fn inner(&self) -> &rusqlite::Transaction<'_> {
        &self.0
    }

    pub fn commit(self) -> anyhow::Result<()> {
        Ok(self.0.commit()?)
    }
}
