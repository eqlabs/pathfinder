use pathfinder_storage::StarknetBlocksBlockId;

/// Returns true if the given [block ID](StarknetBlocksBlockId) is part of the canonical block chain.
pub fn block_exists(
    tx: &rusqlite::Transaction<'_>,
    block_id: StarknetBlocksBlockId,
) -> anyhow::Result<bool> {
    use anyhow::Context;
    use rusqlite::params;

    match block_id {
        StarknetBlocksBlockId::Number(number) => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE number = ?)",
            params![number],
            |row| row.get(0),
        ),
        StarknetBlocksBlockId::Hash(hash) => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE hash = ?)",
            params![hash],
            |row| row.get(0),
        ),
        StarknetBlocksBlockId::Latest => return Ok(true),
    }
    .context("Querying block exists")
}

#[cfg(test)]
mod tests {
    use crate::context::RpcContext;

    use super::*;

    mod block_exists {
        use super::*;

        fn run_test<B: Into<StarknetBlocksBlockId>>(block: B) -> bool {
            let context = RpcContext::for_tests();
            let mut conn = context.storage.connection().unwrap();
            let tx = conn.transaction().unwrap();

            block_exists(&tx, block.into()).unwrap()
        }

        #[test]
        fn latest() {
            assert!(run_test(StarknetBlocksBlockId::Latest));
        }

        #[test]
        fn by_number() {
            use pathfinder_common::StarknetBlockNumber;

            assert!(
                run_test(StarknetBlockNumber::new_or_panic(2)),
                "Block two should exist"
            );

            assert!(
                !run_test(StarknetBlockNumber::new_or_panic(50_000)),
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
