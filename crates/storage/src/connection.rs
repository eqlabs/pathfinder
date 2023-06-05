use std::collections::HashMap;

use pathfinder_common::trie::TrieNode;
use pathfinder_common::{
    BlockNumber, CasmHash, ClassCommitment, ClassCommitmentLeafHash, ClassHash, ContractRoot,
    SierraHash, StorageCommitment,
};
use rusqlite::TransactionBehavior;
use stark_hash::Felt;

use crate::trie::{ClassTrieReader, ContractTrieReader, StorageTrieReader};

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
    #[cfg(test)]
    pub(crate) fn from_inner(tx: rusqlite::Transaction<'inner>) -> Self {
        Self(tx)
    }

    pub fn insert_sierra_class(
        &self,
        sierra_hash: &SierraHash,
        sierra_definition: &[u8],
        casm_hash: &CasmHash,
        casm_definition: &[u8],
        compiler_version: &str,
    ) -> anyhow::Result<()> {
        crate::class::insert_sierra_class(
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
        crate::class::insert_cairo_class(self, cairo_hash, definition)
    }

    pub fn insert_class_commitment_leaf(
        &self,
        leaf: &ClassCommitmentLeafHash,
        casm_hash: &CasmHash,
    ) -> anyhow::Result<()> {
        crate::class::insert_class_commitment_leaf(&self, leaf, casm_hash)
    }

    /// Returns whether the Sierra or Cairo class definition exists in the database.
    ///
    /// Note that this does not indicate that the class is actually declared -- only that we stored it.
    pub fn class_definitions_exist(&self, classes: &[ClassHash]) -> anyhow::Result<Vec<bool>> {
        crate::class::classes_exist(&self, classes)
    }

    /// Stores the class trie information using reference counting.
    pub fn insert_class_trie(
        &self,
        root: ClassCommitment,
        nodes: &HashMap<Felt, TrieNode>,
    ) -> anyhow::Result<usize> {
        crate::trie::insert_class_trie(&self.0, root.0, nodes)
    }

    /// Stores a single contract's storage trie information using reference counting.
    pub fn insert_contract_trie(
        &self,
        root: ContractRoot,
        nodes: &HashMap<Felt, TrieNode>,
    ) -> anyhow::Result<usize> {
        crate::trie::insert_contract_trie(&self.0, root.0, nodes)
    }

    /// Stores the global starknet storage trie information using reference counting.
    pub fn insert_storage_trie(
        &self,
        root: StorageCommitment,
        nodes: &HashMap<Felt, TrieNode>,
    ) -> anyhow::Result<usize> {
        crate::trie::insert_storage_trie(&self.0, root.0, nodes)
    }

    pub fn class_trie_reader(&self) -> anyhow::Result<ClassTrieReader> {
        ClassTrieReader::new(&self)
    }

    pub fn storage_trie_reader(&self) -> anyhow::Result<StorageTrieReader> {
        StorageTrieReader::new(&self)
    }

    pub fn contract_trie_reader(&self) -> anyhow::Result<ContractTrieReader> {
        ContractTrieReader::new(&self)
    }

    pub fn insert_state_diff(
        &self,
        block_number: BlockNumber,
        state_diff: &crate::types::state_update::StateDiff,
    ) -> anyhow::Result<()> {
        crate::state_update::insert_canonical_state_diff(&self, block_number, state_diff)
    }

    pub fn commit(self) -> anyhow::Result<()> {
        Ok(self.0.commit()?)
    }
}

// TODO: this should be removed once all database methods are self-contained within this crate.
impl<'tx> std::ops::Deref for Transaction<'tx> {
    type Target = rusqlite::Transaction<'tx>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
