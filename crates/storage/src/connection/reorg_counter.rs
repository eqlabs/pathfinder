use crate::prelude::*;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ReorgCounter(i64);

impl ReorgCounter {
    pub fn new(value: i64) -> Self {
        Self(value)
    }
}

impl Transaction<'_> {
    pub fn increment_reorg_counter(&self) -> anyhow::Result<()> {
        self.inner().execute(
            "UPDATE reorg_counter SET counter=counter+1 WHERE id = 1",
            [],
        )?;

        Ok(())
    }

    pub fn reorg_counter(&self) -> anyhow::Result<ReorgCounter> {
        // This table always contains exactly one row.
        self.inner()
            .query_row(
                "SELECT counter FROM reorg_counter WHERE id = 1",
                [],
                |row| row.get_reorg_counter(0),
            )
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = tx.reorg_counter().unwrap();
        assert_eq!(result, ReorgCounter::new(0));
    }

    #[test]
    fn increment() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        tx.increment_reorg_counter().unwrap();
        let result = tx.reorg_counter().unwrap();
        assert_eq!(result, ReorgCounter::new(1));

        tx.increment_reorg_counter().unwrap();
        let result = tx.reorg_counter().unwrap();
        assert_eq!(result, ReorgCounter::new(2));
    }
}
