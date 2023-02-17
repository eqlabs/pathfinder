use crate::v02::types::reply::Transaction;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::{BlockId, StarknetTransactionIndex};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetTransactionByBlockIdAndIndexInput {
    block_id: BlockId,
    index: StarknetTransactionIndex,
}

crate::error::generate_rpc_error_subset!(
    GetTransactionByBlockIdAndIndexError: BlockNotFound,
    InvalidTxnIndex
);

pub async fn get_transaction_by_block_id_and_index(
    context: RpcContext,
    input: GetTransactionByBlockIdAndIndexInput,
) -> Result<Transaction, GetTransactionByBlockIdAndIndexError> {
    let index: usize = input
        .index
        .get()
        .try_into()
        .map_err(|_| GetTransactionByBlockIdAndIndexError::InvalidTxnIndex)?;

    let block_id = match input.block_id {
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
        BlockId::Pending => {
            return get_transaction_from_pending(&context.pending_data, index).await
        }
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Get the transaction from storage.
        match StarknetTransactionsTable::get_transaction_at_block(&db_tx, block_id, index)
            .context("Reading transaction from database")?
        {
            Some(transaction) => Ok(transaction.into()),
            None => {
                // We now need to check whether it was the block hash or transaction index which were invalid. We do this by checking if the block exists
                // at all. If no, then the block hash is invalid. If yes, then the index is invalid.
                //
                // get_storage_commitment is cheaper than querying the full block.
                match StarknetBlocksTable::get_storage_commitment(&db_tx, block_id)
                    .context("Reading block from database")?
                {
                    Some(_) => Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex),
                    None => Err(GetTransactionByBlockIdAndIndexError::BlockNotFound),
                }
            }
        }
    });

    jh.await.context("Database read panic or shutting down")?
}

async fn get_transaction_from_pending(
    pending: &Option<starknet_gateway_types::pending::PendingData>,
    index: usize,
) -> Result<Transaction, GetTransactionByBlockIdAndIndexError> {
    // We return InvalidTxnIndex even if the pending block is technically missing.
    // The absence of the pending block should be transparent to the end-user so
    // we effectively handle it as an empty pending block.
    match pending {
        Some(pending) => pending.block().await.map_or_else(
            || Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex),
            |block| {
                block.transactions.get(index).map_or(
                    Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex),
                    |txn| Ok(txn.into()),
                )
            },
        ),
        None => Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::{
        felt, felt_bytes, StarknetBlockHash, StarknetBlockNumber, StarknetTransactionHash,
    };
    use stark_hash::Felt;

    mod parsing {
        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                {"block_hash": "0xdeadbeef"},
                1
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional
                .parse::<GetTransactionByBlockIdAndIndexInput>()
                .unwrap();
            assert_eq!(
                input,
                GetTransactionByBlockIdAndIndexInput {
                    block_id: BlockId::Hash(StarknetBlockHash(felt!("0xdeadbeef"))),
                    index: StarknetTransactionIndex::new_or_panic(1),
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = r#"{
                "block_id": {"block_hash": "0xdeadbeef"},
                "index": 1
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args
                .parse::<GetTransactionByBlockIdAndIndexInput>()
                .unwrap();
            assert_eq!(
                input,
                GetTransactionByBlockIdAndIndexInput {
                    block_id: BlockId::Hash(StarknetBlockHash(felt!("0xdeadbeef"))),
                    index: StarknetTransactionIndex::new_or_panic(1),
                }
            )
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn block_not_found() {
            let context = RpcContext::for_tests();
            let input = GetTransactionByBlockIdAndIndexInput {
                block_id: BlockId::Hash(StarknetBlockHash(Felt::ZERO)),
                index: StarknetTransactionIndex::new_or_panic(0),
            };

            let result = get_transaction_by_block_id_and_index(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionByBlockIdAndIndexError::BlockNotFound)
            );
        }

        #[tokio::test]
        async fn invalid_index() {
            let context = RpcContext::for_tests();
            let input = GetTransactionByBlockIdAndIndexInput {
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"genesis"))),
                index: StarknetTransactionIndex::new_or_panic(123),
            };

            let result = get_transaction_by_block_id_and_index(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionByBlockIdAndIndexError::InvalidTxnIndex)
            );
        }
    }

    #[tokio::test]
    async fn by_block_number() {
        let context = RpcContext::for_tests();
        let input = GetTransactionByBlockIdAndIndexInput {
            block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(0)),
            index: StarknetTransactionIndex::new_or_panic(0),
        };

        let result = get_transaction_by_block_id_and_index(context, input)
            .await
            .unwrap();
        assert_eq!(
            result.hash(),
            StarknetTransactionHash(felt_bytes!(b"txn 0"))
        );
    }

    #[tokio::test]
    async fn by_block_hash() {
        let context = RpcContext::for_tests();
        let input = GetTransactionByBlockIdAndIndexInput {
            block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"genesis"))),
            index: StarknetTransactionIndex::new_or_panic(0),
        };

        let result = get_transaction_by_block_id_and_index(context, input)
            .await
            .unwrap();
        assert_eq!(
            result.hash(),
            StarknetTransactionHash(felt_bytes!(b"txn 0"))
        );
    }

    #[tokio::test]
    async fn by_latest() {
        let context = RpcContext::for_tests();
        let input = GetTransactionByBlockIdAndIndexInput {
            block_id: BlockId::Latest,
            index: StarknetTransactionIndex::new_or_panic(0),
        };

        let result = get_transaction_by_block_id_and_index(context, input)
            .await
            .unwrap();
        assert_eq!(
            result.hash(),
            StarknetTransactionHash(felt_bytes!(b"txn 3"))
        );
    }

    #[tokio::test]
    async fn by_pending() {
        let context = RpcContext::for_tests_with_pending().await;

        const TX_IDX: usize = 1;
        let expected = context
            .pending_data
            .as_ref()
            .unwrap()
            .block()
            .await
            .unwrap();
        assert!(TX_IDX <= expected.transactions.len());
        let expected: Transaction = expected.transactions.get(TX_IDX).unwrap().into();

        let input = GetTransactionByBlockIdAndIndexInput {
            block_id: BlockId::Pending,
            index: StarknetTransactionIndex::new_or_panic(TX_IDX.try_into().unwrap()),
        };

        let result = get_transaction_by_block_id_and_index(context, input)
            .await
            .unwrap();
        assert_eq!(result, expected);
    }
}
