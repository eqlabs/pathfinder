#![allow(unused)]

use anyhow::Context;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

pub struct ReadOnlyStoragePool(Pool<SqliteConnectionManager>);

impl ReadOnlyStoragePool {
    pub fn connection(&self) -> anyhow::Result<ReadOnlyConnection> {
        Ok(ReadOnlyConnection(self.0.get()?))
    }
}

pub struct ReadOnlyConnection(PooledConnection<SqliteConnectionManager>);

impl ReadOnlyConnection {
    pub fn transaction(&mut self) -> anyhow::Result<ReadOnlyTransaction> {
        Ok(ReadOnlyTransaction(self.0.transaction()?))
    }
}

pub struct ReadOnlyTransaction<'tx>(rusqlite::Transaction<'tx>);

impl<'tx> ReadOnlyTransaction<'tx> {
    pub(crate) fn from_raw(tx: rusqlite::Transaction<'tx>) -> Self {
        Self(tx)
    }

    pub fn get_header(&self) -> anyhow::Result<()> {
        todo!();
    }

    // etc..
}