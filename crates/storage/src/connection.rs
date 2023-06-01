use rusqlite::TransactionBehavior;

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
