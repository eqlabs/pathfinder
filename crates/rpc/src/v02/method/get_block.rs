use crate::context::RpcContext;
use crate::v02::types::reply::BlockStatus;
use anyhow::Context;
use pathfinder_common::{BlockId, BlockNumber};
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Copy, Clone))]
#[serde(deny_unknown_fields)]
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

        let block_id = match block_id {
            BlockId::Pending => {
                let block = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?
                    .block
                    .clone();

                return Ok(types::Block::from_sequencer_scoped(block.into(), scope));
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

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
    })
    .await
    .context("Database read panic or shutting down")?
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
    use serde_json::{json, Value};

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockNumber;

    #[rstest::rstest]
    #[case::positional_pending(json!(["pending"]), BlockId::Pending)]
    #[case::positional_latest(json!(["latest"]), BlockId::Latest)]
    #[case::positional_number(json!([{"block_number":123}]), BlockId::Number(BlockNumber::new_or_panic(123)))]
    #[case::positional_hash(json!([{"block_hash": "0xbeef"}]), BlockId::Hash(block_hash!("0xbeef")))]
    #[case::named_pending(json!({"block_id": "pending"}), BlockId::Pending)]
    #[case::named_latest(json!({"block_id": "latest"}), BlockId::Latest)]
    #[case::named_number(json!({"block_id": {"block_number":123}}), BlockId::Number(BlockNumber::new_or_panic(123)))]
    #[case::named_hash(json!({"block_id": {"block_hash": "0xbeef"}}), BlockId::Hash(block_hash!("0xbeef")))]
    fn parsing(#[case] input: Value, #[case] expected: BlockId) {
        let expected = GetBlockInput { block_id: expected };

        let input = serde_json::from_value::<GetBlockInput>(input).unwrap();

        assert_eq!(input, expected);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Pending,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.parent_hash, block_hash_bytes!(b"latest"));
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Latest,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.block_hash, Some(block_hash_bytes!(b"latest")));
    }

    #[tokio::test]
    async fn by_number() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Number(BlockNumber::GENESIS),
            },
        )
        .await
        .unwrap();

        assert_eq!(result.block_hash, Some(block_hash_bytes!(b"genesis")));
    }

    #[tokio::test]
    async fn by_hash() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"genesis")),
            },
        )
        .await
        .unwrap();

        assert_eq!(result.block_hash, Some(block_hash_bytes!(b"genesis")));
    }

    #[tokio::test]
    async fn not_found_by_number() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Number(BlockNumber::MAX),
            },
        )
        .await;

        assert_matches::assert_matches!(result, Err(GetBlockError::BlockNotFound));
    }

    #[tokio::test]
    async fn not_found_by_hash() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_tx_hashes(
            context,
            GetBlockInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"non-existent")),
            },
        )
        .await;

        assert_matches::assert_matches!(result, Err(GetBlockError::BlockNotFound));
    }
}
