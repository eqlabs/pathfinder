use crate::v02::common::get_block_status;
use crate::v02::RpcContext;
use anyhow::{anyhow, Context};
use pathfinder_common::{BlockId, StarknetBlockHash, StarknetBlockNumber, StateCommitment};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable};
use serde::Deserialize;
use stark_hash::Felt;

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
    let block_id = match block_id {
        BlockId::Pending => {
            match context
                .pending_data
                .ok_or_else(|| anyhow!("Pending data not supported in this configuration"))?
                .block()
                .await
            {
                Some(block) => {
                    return Ok(types::Block::from_sequencer_scoped(
                        block.as_ref().clone().into(),
                        scope,
                    ))
                }
                None => return Err(GetBlockError::BlockNotFound),
            }
        }
        BlockId::Hash(hash) => hash.into(),
        BlockId::Number(number) => number.into(),
        BlockId::Latest => StarknetBlocksBlockId::Latest,
    };

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        // Need to get the block status. This also tests that the block hash is valid.
        let block = get_raw_block(&transaction, block_id)?;

        let transactions = get_block_transactions(&transaction, block.number, scope)?;

        Ok(types::Block::from_raw(block, transactions))
    })
    .await
    .context("Database read panic or shutting down")?
}

/// Fetches a [RawBlock](types::RawBlock) from storage.
fn get_raw_block(
    transaction: &rusqlite::Transaction<'_>,
    block_id: StarknetBlocksBlockId,
) -> Result<types::RawBlock, GetBlockError> {
    let block = StarknetBlocksTable::get(transaction, block_id)
        .context("Read block from database")?
        .ok_or(GetBlockError::BlockNotFound)?;

    let block_status = get_block_status(transaction, block.number)?;

    let (parent_hash, parent_root) = match block.number {
        StarknetBlockNumber::GENESIS => {
            (StarknetBlockHash(Felt::ZERO), StateCommitment(Felt::ZERO))
        }
        other => {
            let parent_block = StarknetBlocksTable::get(transaction, (other - 1).into())
                .context("Read parent block from database")?
                .context("Parent block missing")?;

            (parent_block.hash, parent_block.root)
        }
    };

    let block = types::RawBlock {
        number: block.number,
        hash: block.hash,
        root: block.root,
        parent_hash,
        parent_root,
        timestamp: block.timestamp,
        status: block_status,
        gas_price: block.gas_price,
        sequencer: block.sequencer_address,
    };

    Ok(block)
}

/// This function assumes that the block ID is valid i.e. it won't check if the block hash or number exist.
fn get_block_transactions(
    db_tx: &rusqlite::Transaction<'_>,
    block_number: StarknetBlockNumber,
    scope: types::BlockResponseScope,
) -> Result<types::Transactions, GetBlockError> {
    let transactions_receipts =
        StarknetTransactionsTable::get_transaction_data_for_block(db_tx, block_number.into())
            .context("Reading transactions from database")?;

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
        GasPrice, SequencerAddress, StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
        StarknetTransactionHash, StateCommitment,
    };
    use serde::Serialize;
    use serde_with::{serde_as, skip_serializing_none};
    use stark_hash::Felt;

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
    pub struct TransactionHashes(#[serde_as(as = "Vec<RpcFelt>")] Vec<StarknetTransactionHash>);

    impl From<Vec<StarknetTransactionHash>> for TransactionHashes {
        fn from(value: Vec<StarknetTransactionHash>) -> Self {
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
        pub block_hash: Option<StarknetBlockHash>,
        #[serde_as(as = "RpcFelt")]
        pub parent_hash: StarknetBlockHash,
        pub block_number: Option<StarknetBlockNumber>,
        #[serde_as(as = "Option<RpcFelt>")]
        pub new_root: Option<StateCommitment>,
        pub timestamp: StarknetBlockTimestamp,
        #[serde_as(as = "RpcFelt")]
        pub sequencer_address: SequencerAddress,
        pub transactions: Transactions,
    }

    /// Convenience type for DB manipulation.
    #[derive(Debug)]
    pub struct RawBlock {
        pub number: StarknetBlockNumber,
        pub hash: StarknetBlockHash,
        pub root: StateCommitment,
        pub parent_hash: StarknetBlockHash,
        pub parent_root: StateCommitment,
        pub timestamp: StarknetBlockTimestamp,
        pub status: BlockStatus,
        pub sequencer: SequencerAddress,
        pub gas_price: GasPrice,
    }

    impl Block {
        /// Constructs [Block] from [RawBlock]
        pub fn from_raw(block: RawBlock, transactions: Transactions) -> Self {
            Self {
                status: block.status,
                block_hash: Some(block.hash),
                parent_hash: block.parent_hash,
                block_number: Some(block.number),
                new_root: Some(block.root),
                timestamp: block.timestamp,
                sequencer_address: block.sequencer,
                transactions,
            }
        }

        /// Constructs [Block] from [sequencer's block representation](starknet_gateway_types::reply::Block)
        pub fn from_sequencer_scoped(
            block: starknet_gateway_types::reply::MaybePendingBlock,
            scope: BlockResponseScope,
        ) -> Self {
            let transactions = match scope {
                BlockResponseScope::TransactionHashes => {
                    let hashes = block
                        .transactions()
                        .iter()
                        .map(|t| t.hash())
                        .collect::<Vec<_>>()
                        .into();

                    Transactions::HashesOnly(hashes)
                }
                BlockResponseScope::FullTransactions => {
                    let transactions = block.transactions().iter().map(|t| t.into()).collect();
                    Transactions::Full(transactions)
                }
            };

            use starknet_gateway_types::reply::MaybePendingBlock;
            match block {
                MaybePendingBlock::Block(block) => Self {
                    status: block.status.into(),
                    block_hash: Some(block.block_hash),
                    parent_hash: block.parent_block_hash,
                    block_number: Some(block.block_number),
                    new_root: Some(block.state_commitment),
                    timestamp: block.timestamp,
                    sequencer_address: block
                        .sequencer_address
                        // Default value for cairo <0.8.0 is 0
                        .unwrap_or(SequencerAddress(Felt::ZERO)),
                    transactions,
                },
                MaybePendingBlock::Pending(pending) => Self {
                    status: pending.status.into(),
                    block_hash: None,
                    parent_hash: pending.parent_hash,
                    block_number: None,
                    new_root: None,
                    timestamp: pending.timestamp,
                    sequencer_address: pending.sequencer_address,
                    transactions,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use jsonrpsee::types::Params;
    use pathfinder_common::{felt, StarknetBlockHash, StarknetBlockNumber};
    use starknet_gateway_types::pending::PendingData;

    #[test]
    fn parsing() {
        let number = BlockId::Number(StarknetBlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(StarknetBlockHash(felt!("0xbeef")));

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
                Some(StarknetBlockHash(pathfinder_common::felt_bytes!(expected))),
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
        let ctx_with_pending_disabled = RpcContext::for_tests();

        let cases: &[(RpcContext, BlockId, TestCaseHandler)] = &[
            // Pending
            (
                ctx.clone(),
                BlockId::Pending,
                Box::new(|i, result| {
                    assert_matches!(result, Ok(block) => assert_eq!(
                        block.parent_hash,
                        StarknetBlockHash(pathfinder_common::felt_bytes!(b"latest")),
                        "test case {i}"
                    ), "test case {i}")
                }),
            ),
            (
                ctx_with_pending_empty,
                BlockId::Pending,
                assert_error(GetBlockError::BlockNotFound),
            ),
            (
                ctx_with_pending_disabled,
                BlockId::Pending,
                assert_error(GetBlockError::Internal(anyhow!(
                    "Pending data not supported in this configuration"
                ))),
            ),
            // Other block ids
            (ctx.clone(), BlockId::Latest, assert_hash(b"latest")),
            (
                ctx.clone(),
                BlockId::Number(StarknetBlockNumber::GENESIS),
                assert_hash(b"genesis"),
            ),
            (
                ctx.clone(),
                BlockId::Hash(StarknetBlockHash(pathfinder_common::felt_bytes!(
                    b"genesis"
                ))),
                assert_hash(b"genesis"),
            ),
            (
                ctx.clone(),
                BlockId::Number(StarknetBlockNumber::new_or_panic(9999)),
                assert_error(GetBlockError::BlockNotFound),
            ),
            (
                ctx,
                BlockId::Hash(StarknetBlockHash(pathfinder_common::felt_bytes!(
                    b"non-existent"
                ))),
                assert_error(GetBlockError::BlockNotFound),
            ),
        ];

        for (i, test_case) in cases.iter().enumerate() {
            check(i, test_case).await;
        }
    }
}
