use pathfinder_storage::BlockId;

/// Returns true if the given [block ID](BlockId) is part of the canonical block chain.
pub fn block_exists(tx: &rusqlite::Transaction<'_>, block_id: BlockId) -> anyhow::Result<bool> {
    use anyhow::Context;
    use rusqlite::params;

    match block_id {
        BlockId::Number(number) => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE number = ?)",
            params![number],
            |row| row.get(0),
        ),
        BlockId::Hash(hash) => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE hash = ?)",
            params![hash],
            |row| row.get(0),
        ),
        BlockId::Latest => return Ok(true),
    }
    .context("Querying block exists")
}

#[cfg(test)]
mod tests {
    use crate::context::RpcContext;

    use super::*;

    mod block_exists {
        use super::*;

        fn run_test<B: Into<BlockId>>(block: B) -> bool {
            let context = RpcContext::for_tests();
            let mut conn = context.storage.connection().unwrap();
            let tx = conn.transaction().unwrap();

            block_exists(&tx, block.into()).unwrap()
        }

        #[test]
        fn latest() {
            assert!(run_test(BlockId::Latest));
        }

        #[test]
        fn by_number() {
            use pathfinder_common::BlockNumber;

            assert!(
                run_test(BlockNumber::new_or_panic(2)),
                "Block two should exist"
            );

            assert!(
                !run_test(BlockNumber::new_or_panic(50_000)),
                "Block fifty thousand should not exist"
            );
        }

        #[test]
        fn by_hash() {
            use pathfinder_common::{felt_bytes, BlockHash};

            assert!(
                run_test(BlockHash(felt_bytes!(b"latest"))),
                "Block two should exist"
            );

            assert!(
                !run_test(BlockHash(felt_bytes!(b"invalid"))),
                "Invalid block hash should not exist"
            );
        }
    }
}
