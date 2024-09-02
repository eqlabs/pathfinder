use anyhow::Context;
use pathfinder_common::{BlockId, BlockNumber};
use serde::Deserialize;

use crate::context::RpcContext;
use crate::v02::types::reply::BlockStatus;
use crate::v06::types::TransactionWithHash;

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Copy, Clone))]
#[serde(deny_unknown_fields)]
pub struct GetBlockInput {
    block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for GetBlockInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

crate::error::generate_rpc_error_subset!(GetBlockError: BlockNotFound);

/// Get block information with full transactions given the block id
pub async fn get_block_with_txs(
    context: RpcContext,
    input: GetBlockInput,
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

        let block_id = match input.block_id {
            BlockId::Pending => {
                let block = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?
                    .block;
                let block = (*block).clone();

                return Ok(types::Block::from_sequencer_pending(block));
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

        let transactions = get_block_transactions(&transaction, header.number)?;

        Ok(types::Block::from_parts(header, block_status, transactions))
    })
    .await
    .context("Database read panic or shutting down")?
}

/// This function assumes that the block ID is valid i.e. it won't check if the
/// block hash or number exist.
fn get_block_transactions(
    db_tx: &pathfinder_storage::Transaction<'_>,
    block_number: BlockNumber,
) -> Result<Vec<TransactionWithHash>, GetBlockError> {
    let txs = db_tx
        .transaction_data_for_block(block_number.into())
        .context("Reading transactions from database")?
        .context("Transaction data missing for block")?
        .into_iter()
        .map(|(tx, _rx, _ev)| tx.into())
        .collect();

    Ok(txs)
}

mod types {
    use pathfinder_common::BlockHeader;
    use serde::Serialize;
    use serde_with::{serde_as, skip_serializing_none};

    use crate::v02::types::reply::BlockStatus;
    use crate::v06::types::TransactionWithHash;

    /// L2 Block as returned by the RPC API.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    pub struct Block {
        #[serde(flatten)]
        pub header: crate::v06::types::BlockHeader,
        #[serde(skip_serializing_if = "BlockStatus::is_pending")]
        pub status: BlockStatus,
        pub transactions: Vec<TransactionWithHash>,
    }

    impl Block {
        pub fn from_parts(
            header: BlockHeader,
            status: BlockStatus,
            transactions: Vec<TransactionWithHash>,
        ) -> Self {
            Self {
                header: header.into(),
                status,
                transactions,
            }
        }

        /// Constructs [Block] from [sequencer's pending block
        /// representation](starknet_gateway_types::reply::PendingBlock)
        pub fn from_sequencer_pending(
            pending: starknet_gateway_types::reply::PendingBlock,
        ) -> Self {
            Self {
                status: pending.status.into(),
                transactions: pending
                    .transactions
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect(),
                header: crate::v06::types::BlockHeader::from_sequencer_pending(pending),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockNumber;
    use serde_json::json;

    use super::*;

    #[rstest::rstest]
    #[case::pending_by_position(json!(["pending"]), BlockId::Pending)]
    #[case::pending_by_name(json!({"block_id": "pending"}), BlockId::Pending)]
    #[case::latest_by_position(json!(["latest"]), BlockId::Latest)]
    #[case::latest_by_name(json!({"block_id": "latest"}), BlockId::Latest)]
    #[case::number_by_position(json!([{"block_number":123}]), BlockNumber::new_or_panic(123).into())]
    #[case::number_by_name(json!({"block_id": {"block_number":123}}), BlockNumber::new_or_panic(123).into())]
    #[case::hash_by_position(json!([{"block_hash": "0xbeef"}]), block_hash!("0xbeef").into())]
    #[case::hash_by_name(json!({"block_id": {"block_hash": "0xbeef"}}), block_hash!("0xbeef").into())]
    fn input_parsing(#[case] input: serde_json::Value, #[case] block_id: BlockId) {
        let input = serde_json::from_value::<GetBlockInput>(input).unwrap();

        let expected = GetBlockInput { block_id };

        assert_eq!(input, expected);
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Pending,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.header.parent_hash, block_hash_bytes!(b"latest"));
    }

    #[tokio::test]
    async fn latest() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Latest,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.header.block_hash, Some(block_hash_bytes!(b"latest")));
    }

    #[tokio::test]
    async fn by_number() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Number(BlockNumber::GENESIS),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result.header.block_hash,
            Some(block_hash_bytes!(b"genesis"))
        );
    }

    #[tokio::test]
    async fn by_hash() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"genesis")),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result.header.block_hash,
            Some(block_hash_bytes!(b"genesis"))
        );
    }

    #[tokio::test]
    async fn not_found_by_number() {
        let context = RpcContext::for_tests_with_pending().await;

        let result = get_block_with_txs(
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

        let result = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Hash(block_hash_bytes!(b"non-existent")),
            },
        )
        .await;

        assert_matches::assert_matches!(result, Err(GetBlockError::BlockNotFound));
    }

    #[tokio::test]
    async fn status_serialization() {
        // PENDING status should be skipped.

        let context = RpcContext::for_tests_with_pending().await;
        let pending = get_block_with_txs(
            context.clone(),
            GetBlockInput {
                block_id: BlockId::Pending,
            },
        )
        .await
        .unwrap();
        let latest = get_block_with_txs(
            context,
            GetBlockInput {
                block_id: BlockId::Latest,
            },
        )
        .await
        .unwrap();

        assert!(pending.status.is_pending());
        assert!(!latest.status.is_pending());

        let pending = serde_json::to_value(pending).unwrap();
        let latest = serde_json::to_value(latest).unwrap();

        assert!(pending.get("status").is_none());
        assert!(latest.get("status").is_some());
    }
}
