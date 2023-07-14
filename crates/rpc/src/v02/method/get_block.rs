use crate::context::RpcContext;
use crate::v02::types::reply::BlockStatus;
use anyhow::Context;
use pathfinder_common::{BlockId, BlockNumber};
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Copy, Clone))]
pub struct GetBlockInput {
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(GetBlockError: BlockNotFound);

/// Get block information with transaction hashes given the block id
pub async fn get_block_with_tx_hashes(
    context: RpcContext,
    input: GetBlockInput,
) -> Result<types::Block, GetBlockError> {
    get_block(
        context,
        input.block_id,
        types::BlockResponseScope::TransactionHashes,
    )
    .await
}

/// Get block information with full transactions given the block id
pub async fn get_block_with_txs(
    context: RpcContext,
    input: GetBlockInput,
) -> Result<types::Block, GetBlockError> {
    get_block(
        context,
        input.block_id,
        types::BlockResponseScope::FullTransactions,
    )
    .await
}

/// Get block information given the block id
async fn get_block(
    context: RpcContext,
    block_id: BlockId,
    scope: types::BlockResponseScope,
) -> Result<types::Block, GetBlockError> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        match block_id {
            BlockId::Pending => {
                let block = context
                    .pending_block(&transaction)
                    .context("Querying pending block")?
                    .ok_or(GetBlockError::BlockNotFound)?;

                let transactions = block.body.transaction_data.iter();

                let transactions = match scope {
                    types::BlockResponseScope::TransactionHashes => {
                        types::Transactions::HashesOnly(
                            transactions
                                .map(|(tx, _)| tx.hash)
                                .collect::<Vec<_>>()
                                .into(),
                        )
                    }
                    types::BlockResponseScope::FullTransactions => types::Transactions::Full(
                        transactions
                            .map(|(tx, _)| tx.clone().into())
                            .collect::<Vec<_>>(),
                    ),
                };

                Ok(types::Block::from_parts(
                    block.header.clone(),
                    BlockStatus::Pending,
                    transactions,
                ))
            }
            other => {
                let block_id = other.try_into().expect("Only pending cast should fail");

                let header = transaction
                    .block_header(block_id)
                    .context("Reading block from database")?
                    .ok_or(GetBlockError::BlockNotFound)?;

                let l1_accepted = transaction.block_is_l1_accepted(header.number.into())?;
                let block_status = if l1_accepted {
                    BlockStatus::AcceptedOnL1
                } else {
                    BlockStatus::AcceptedOnL2
                };

                let transactions = get_block_transactions(&transaction, header.number, scope)?;

                Ok(types::Block::from_parts(header, block_status, transactions))
            }
        }
    })
    .await
    .context("Joining database task")?
}

/// This function assumes that the block ID is valid i.e. it won't check if the block hash or number exist.
fn get_block_transactions(
    db_tx: &pathfinder_storage::Transaction<'_>,
    block_number: BlockNumber,
    scope: types::BlockResponseScope,
) -> Result<types::Transactions, GetBlockError> {
    let transactions_receipts = db_tx
        .transaction_data_for_block(block_number.into())
        .context("Reading transactions from database")?
        .context("Transaction data missing for block")?;

    match scope {
        types::BlockResponseScope::TransactionHashes => Ok(types::Transactions::HashesOnly(
            transactions_receipts
                .into_iter()
                .map(|(t, _)| t.hash())
                .collect::<Vec<_>>()
                .into(),
        )),
        types::BlockResponseScope::FullTransactions => Ok(types::Transactions::Full(
            transactions_receipts
                .into_iter()
                .map(|(t, _)| t.into())
                .collect(),
        )),
    }
}

mod types {
    use crate::felt::RpcFelt;
    use crate::v02::types::reply::{BlockStatus, Transaction};
    use pathfinder_common::{
        BlockHash, BlockHeader, BlockNumber, BlockTimestamp, SequencerAddress, StateCommitment,
        TransactionHash,
    };
    use serde::Serialize;
    use serde_with::{serde_as, skip_serializing_none};

    /// Determines the type of response to block related queries.
    #[derive(Copy, Clone, Debug)]
    pub enum BlockResponseScope {
        TransactionHashes,
        FullTransactions,
    }

    /// Wrapper for transaction data returned in block related queries,
    /// chosen variant depends on [`BlockResponseScope`].
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(untagged)]
    pub enum Transactions {
        Full(Vec<Transaction>),
        HashesOnly(TransactionHashes),
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct TransactionHashes(#[serde_as(as = "Vec<RpcFelt>")] Vec<TransactionHash>);

    impl From<Vec<TransactionHash>> for TransactionHashes {
        fn from(value: Vec<TransactionHash>) -> Self {
            Self(value)
        }
    }

    /// L2 Block as returned by the RPC API.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Block {
        pub status: BlockStatus,
        #[serde_as(as = "Option<RpcFelt>")]
        pub block_hash: Option<BlockHash>,
        #[serde_as(as = "RpcFelt")]
        pub parent_hash: BlockHash,
        pub block_number: Option<BlockNumber>,
        #[serde_as(as = "Option<RpcFelt>")]
        pub new_root: Option<StateCommitment>,
        pub timestamp: BlockTimestamp,
        #[serde_as(as = "RpcFelt")]
        pub sequencer_address: SequencerAddress,
        pub transactions: Transactions,
    }

    impl Block {
        pub fn from_parts(
            header: BlockHeader,
            status: BlockStatus,
            transactions: Transactions,
        ) -> Self {
            Self {
                status,
                block_hash: Some(header.hash),
                parent_hash: header.parent_hash,
                block_number: Some(header.number),
                new_root: Some(header.state_commitment),
                timestamp: header.timestamp,
                sequencer_address: header.sequencer_address,
                transactions,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::pending::PendingData;
    use pathfinder_common::BlockNumber;

    #[test]
    fn parsing() {
        let number = BlockId::Number(BlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(block_hash!("0xbeef"));

        [
            (r#"["pending"]"#, BlockId::Pending),
            (r#"{"block_id": "pending"}"#, BlockId::Pending),
            (r#"["latest"]"#, BlockId::Latest),
            (r#"{"block_id": "latest"}"#, BlockId::Latest),
            (r#"[{"block_number":123}]"#, number),
            (r#"{"block_id": {"block_number":123}}"#, number),
            (r#"[{"block_hash": "0xbeef"}]"#, hash),
            (r#"{"block_id": {"block_hash": "0xbeef"}}"#, hash),
        ]
        .into_iter()
        .enumerate()
        .for_each(|(i, (input, expected))| {
            let actual = Params::new(Some(input))
                .parse::<GetBlockInput>()
                .unwrap_or_else(|error| panic!("test case {i}: {input}, {error}"));
            assert_eq!(
                actual,
                GetBlockInput { block_id: expected },
                "test case {i}: {input}"
            );
        });
    }

    type TestCaseHandler = Box<dyn Fn(usize, &Result<types::Block, GetBlockError>)>;

    /// Execute a single test case and check its outcome for both: `get_block_with_[txs|tx_hashes]`
    async fn check(test_case_idx: usize, test_case: &(RpcContext, BlockId, TestCaseHandler)) {
        let (context, block_id, f) = test_case;
        let result = get_block_with_txs(
            context.clone(),
            GetBlockInput {
                block_id: *block_id,
            },
        )
        .await;
        f(test_case_idx, &result);
        let _ = result.map(|block| assert_matches!(block.transactions, types::Transactions::Full(_) => {}, "test case {test_case_idx}: {block_id:?}"));

        let result = get_block_with_tx_hashes(
            context.clone(),
            GetBlockInput {
                block_id: *block_id,
            },
        )
        .await;
        f(test_case_idx, &result);
        let _ = result.map(|block| assert_matches!(block.transactions, types::Transactions::HashesOnly(_) => {}, "test case {test_case_idx}: {block_id:?}"));
    }

    /// Common assertion type for most of the test cases
    fn assert_hash(expected: &'static [u8]) -> TestCaseHandler {
        Box::new(|i: usize, result| {
            assert_matches!(result, Ok(block) => assert_eq!(
                block.block_hash,
                Some(block_hash_bytes!(expected)),
                "test case {i}"
            ));
        })
    }

    impl PartialEq for GetBlockError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Internal(l), Self::Internal(r)) => l.to_string() == r.to_string(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    /// Common assertion type for most of the error paths
    fn assert_error(expected: GetBlockError) -> TestCaseHandler {
        Box::new(move |i: usize, result| {
            assert_matches!(result, Err(error) => assert_eq!(*error, expected, "test case {i}"), "test case {i}");
        })
    }

    #[tokio::test]
    async fn happy_paths_and_major_errors() {
        let ctx = RpcContext::for_tests_with_pending().await;
        let ctx_with_pending_empty =
            RpcContext::for_tests().with_pending_data(PendingData::default());

        let cases: &[(RpcContext, BlockId, TestCaseHandler)] = &[
            // Pending
            (
                ctx.clone(),
                BlockId::Pending,
                Box::new(|i, result| {
                    assert_matches!(result, Ok(block) => assert_eq!(
                        block.parent_hash,
                        block_hash_bytes!(b"latest"),
                        "test case {i}"
                    ), "test case {i}")
                }),
            ),
            (
                ctx_with_pending_empty,
                BlockId::Pending,
                assert_error(GetBlockError::BlockNotFound),
            ),
            // Other block ids
            (ctx.clone(), BlockId::Latest, assert_hash(b"latest")),
            (
                ctx.clone(),
                BlockId::Number(BlockNumber::GENESIS),
                assert_hash(b"genesis"),
            ),
            (
                ctx.clone(),
                BlockId::Hash(block_hash_bytes!(b"genesis")),
                assert_hash(b"genesis"),
            ),
            (
                ctx.clone(),
                BlockId::Number(BlockNumber::new_or_panic(9999)),
                assert_error(GetBlockError::BlockNotFound),
            ),
            (
                ctx,
                BlockId::Hash(block_hash_bytes!(b"non-existent")),
                assert_error(GetBlockError::BlockNotFound),
            ),
        ];

        for (i, test_case) in cases.iter().enumerate() {
            check(i, test_case).await;
        }
    }
}
