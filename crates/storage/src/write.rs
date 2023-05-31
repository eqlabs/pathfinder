#![allow(unused)]

use anyhow::Context;
use pathfinder_common::BlockNumber;

use crate::types::state_update::StateDiff;
use crate::Storage;

pub struct MutStorage(rusqlite::Connection);

impl MutStorage {
    pub fn transaction(&mut self) -> anyhow::Result<WriteTransaction> {
        let tx = self.0.transaction()?;
        Ok(WriteTransaction(tx))
    }
}

pub struct WriteTransaction<'tx>(rusqlite::Transaction<'tx>);

// TODO: this should also implement the full read API i.e. write is an extension of read
impl<'tx> WriteTransaction<'tx> {
    pub fn commit(self) -> anyhow::Result<()> {
        self.0.commit()?;
        Ok(())
    }

    pub fn insert_state_diff(
        &self,
        block_number: BlockNumber,
        state_diff: &StateDiff,
    ) -> anyhow::Result<()> {
        // TODO: original should not be publicly available anymore once the switch is made.
        crate::insert_canonical_state_diff(&self.0, block_number, state_diff)
    }

    pub fn insert_block_header(&self) -> anyhow::Result<()> {
        todo!();
    }

    pub fn insert_block_body(&self) -> anyhow::Result<()> {
        todo!();
    }

    pub fn insert_sierra_class(&self) -> anyhow::Result<()> {
        todo!();
    }

    pub fn insert_cairo_class(&self) -> anyhow::Result<()> {
        todo!();
    }

    pub fn insert_trie_nodes(&self, nodes: Vec<()>) -> anyhow::Result<()> {
        todo!();
    }
}