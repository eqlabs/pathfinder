use crate::prelude::*;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ReorgCounter(i64);

impl ReorgCounter {
    pub fn new(value: i64) -> Self {
        Self(value)
    }
}

pub(super) fn increment_reorg_counter(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.inner().execute(
        "UPDATE reorg_counter SET counter=counter+1 WHERE id = 1",
        [],
    )?;

    Ok(())
}

pub(super) fn reorg_counter(tx: &Transaction<'_>) -> anyhow::Result<ReorgCounter> {
    // This table always contains exactly one row.
    tx.inner()
        .query_row(
            "SELECT counter FROM reorg_counter WHERE id = 1",
            [],
            |row| row.get_reorg_counter(0),
        )
        .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = reorg_counter(&tx).unwrap();
        assert_eq!(result, ReorgCounter::new(0));
    }

    #[test]
    fn increment() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        increment_reorg_counter(&tx).unwrap();
        let result = reorg_counter(&tx).unwrap();
        assert_eq!(result, ReorgCounter::new(1));

        increment_reorg_counter(&tx).unwrap();
        let result = reorg_counter(&tx).unwrap();
        assert_eq!(result, ReorgCounter::new(2));
    }
}
