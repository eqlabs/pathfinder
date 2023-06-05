use std::collections::HashMap;

use pathfinder_common::trie::TrieNode;
use pathfinder_common::{ClassCommitment, ContractRoot, StorageCommitment};
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

pub struct Transaction<'tx>(rusqlite::Transaction<'tx>);

impl<'tx> Transaction<'tx> {
    #[cfg(test)]
    pub(crate) fn from_inner(tx: rusqlite::Transaction<'tx>) -> Self {
        Self(tx)
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
