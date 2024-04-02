use pathfinder_common::BlockNumber;

use crate::prelude::*;

impl Transaction<'_> {
    pub fn update_l1_l2_pointer(&self, head: Option<BlockNumber>) -> anyhow::Result<()> {
        self.inner().execute(
            "UPDATE refs SET l1_l2_head = ? WHERE idx = 1",
            params![&head],
        )?;

        Ok(())
    }

    pub fn l1_l2_pointer(&self) -> anyhow::Result<Option<BlockNumber>> {
        // This table always contains exactly one row.
        self.inner()
            .query_row("SELECT l1_l2_head FROM refs WHERE idx = 1", [], |row| {
                row.get_optional_block_number(0)
            })
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_none() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = tx.l1_l2_pointer().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn update_overwrites() {
        let storage = crate::StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        tx.update_l1_l2_pointer(Some(BlockNumber::new_or_panic(10)))
            .unwrap();
        let result = tx.l1_l2_pointer().unwrap();
        assert_eq!(result, Some(BlockNumber::new_or_panic(10)));

        tx.update_l1_l2_pointer(Some(BlockNumber::new_or_panic(33)))
            .unwrap();
        let result = tx.l1_l2_pointer().unwrap();
        assert_eq!(result, Some(BlockNumber::new_or_panic(33)));

        tx.update_l1_l2_pointer(None).unwrap();
        let result = tx.l1_l2_pointer().unwrap();
        assert_eq!(result, None);
    }
}
