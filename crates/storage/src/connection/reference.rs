use pathfinder_common::BlockNumber;

use crate::prelude::*;

pub(super) fn update_l1_l2_pointer(
    tx: &Transaction<'_>,
    head: Option<BlockNumber>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "UPDATE refs SET l1_l2_head = ? WHERE idx = 1",
        params![&head],
    )?;

    Ok(())
}

pub(super) fn l1_l2_pointer(tx: &Transaction<'_>) -> anyhow::Result<Option<BlockNumber>> {
    // This table always contains exactly one row.
    tx.inner()
        .query_row("SELECT l1_l2_head FROM refs WHERE idx = 1", [], |row| {
            row.get_optional_block_number(0)
        })
        .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use crate::Storage;

    use super::*;

    #[test]
    fn empty_is_none() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let result = l1_l2_pointer(&tx).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn update_overwrites() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        update_l1_l2_pointer(&tx, Some(BlockNumber::new_or_panic(10))).unwrap();
        let result = l1_l2_pointer(&tx).unwrap();
        assert_eq!(result, Some(BlockNumber::new_or_panic(10)));

        update_l1_l2_pointer(&tx, Some(BlockNumber::new_or_panic(33))).unwrap();
        let result = l1_l2_pointer(&tx).unwrap();
        assert_eq!(result, Some(BlockNumber::new_or_panic(33)));

        update_l1_l2_pointer(&tx, None).unwrap();
        let result = l1_l2_pointer(&tx).unwrap();
        assert_eq!(result, None);
    }
}
