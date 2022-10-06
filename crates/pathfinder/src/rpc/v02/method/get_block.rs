use anyhow::Context;
use stark_hash::StarkHash;

use crate::core::{BlockId, GlobalRoot, StarknetBlockHash, StarknetBlockNumber};
use crate::rpc::v02::RpcContext;
use crate::storage::{
    RefsTable, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable,
};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetBlockInput {
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(GetBlockError: BlockNotFound);

/// Get block information with transaction hashes given the block id
pub async fn get_block_with_transaction_hashes(
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
pub async fn get_block_with_transactions(
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
        BlockId::Pending => todo!(),
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

        Result::<types::Block, GetBlockError>::Ok(types::Block::from_raw(block, transactions))
    })
    .await
    .context("Database read panic or shutting down")?
}

/// Fetches a [RawBlock] from storage.
fn get_raw_block(
    transaction: &rusqlite::Transaction<'_>,
    block_id: StarknetBlocksBlockId,
) -> Result<types::RawBlock, GetBlockError> {
    let block = StarknetBlocksTable::get(transaction, block_id)
        .context("Read block from database")?
        .ok_or(GetBlockError::BlockNotFound)?;

    let block_status = get_block_status(transaction, block.number)?;

    let (parent_hash, parent_root) = match block.number {
        StarknetBlockNumber::GENESIS => (
            StarknetBlockHash(StarkHash::ZERO),
            GlobalRoot(StarkHash::ZERO),
        ),
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

/// Determines block status based on the current L1-L2 stored in the DB.
fn get_block_status(
    db_tx: &rusqlite::Transaction<'_>,
    block_number: StarknetBlockNumber,
) -> Result<types::BlockStatus, GetBlockError> {
    // All our data is L2 accepted, check our L1-L2 head to see if this block has been accepted on L1.
    let l1_l2_head =
        RefsTable::get_l1_l2_head(db_tx).context("Read latest L1 head from database")?;
    let block_status = match l1_l2_head {
        Some(number) if number >= block_number => types::BlockStatus::AcceptedOnL1,
        _ => types::BlockStatus::AcceptedOnL2,
    };

    Ok(block_status)
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
                .collect(),
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
    use crate::core::{
        GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp, StarknetTransactionHash,
    };
    use crate::rpc::v02::types::reply::Transaction;
    use crate::sequencer;
    use serde::Serialize;
    use serde_with::{serde_as, skip_serializing_none};
    use stark_hash::StarkHash;
    use std::convert::From;

    /// Determines the type of response to block related queries.
    #[derive(Copy, Clone, Debug)]
    pub enum BlockResponseScope {
        TransactionHashes,
        FullTransactions,
    }

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum BlockStatus {
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<sequencer::reply::Status> for BlockStatus {
        fn from(status: sequencer::reply::Status) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                sequencer::reply::Status::AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                sequencer::reply::Status::AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                sequencer::reply::Status::NotReceived => BlockStatus::Rejected,
                sequencer::reply::Status::Pending => BlockStatus::Pending,
                sequencer::reply::Status::Received => BlockStatus::Pending,
                sequencer::reply::Status::Rejected => BlockStatus::Rejected,
                sequencer::reply::Status::Reverted => BlockStatus::Rejected,
                sequencer::reply::Status::Aborted => BlockStatus::Rejected,
            }
        }
    }

    /// Wrapper for transaction data returned in block related queries,
    /// chosen variant depends on [`BlockResponseScope`].
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(untagged)]
    pub enum Transactions {
        Full(Vec<Transaction>),
        HashesOnly(Vec<StarknetTransactionHash>),
    }

    /// L2 Block as returned by the RPC API.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Block {
        pub status: BlockStatus,
        pub block_hash: Option<StarknetBlockHash>,
        pub parent_hash: StarknetBlockHash,
        pub block_number: Option<StarknetBlockNumber>,
        pub new_root: Option<GlobalRoot>,
        pub timestamp: StarknetBlockTimestamp,
        pub sequencer_address: SequencerAddress,
        pub transactions: Transactions,
    }

    /// Convenience type for DB manipulation.
    #[derive(Debug)]
    pub struct RawBlock {
        pub number: StarknetBlockNumber,
        pub hash: StarknetBlockHash,
        pub root: GlobalRoot,
        pub parent_hash: StarknetBlockHash,
        pub parent_root: GlobalRoot,
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

        /// Constructs [Block] from [sequencer's block representation](crate::sequencer::reply::Block)
        pub fn from_sequencer_scoped(
            block: sequencer::reply::MaybePendingBlock,
            scope: BlockResponseScope,
        ) -> Self {
            let transactions = match scope {
                BlockResponseScope::TransactionHashes => {
                    let hashes = block.transactions().iter().map(|t| t.hash()).collect();

                    Transactions::HashesOnly(hashes)
                }
                BlockResponseScope::FullTransactions => {
                    let transactions = block.transactions().iter().map(|t| t.into()).collect();
                    Transactions::Full(transactions)
                }
            };

            use sequencer::reply::MaybePendingBlock;
            match block {
                MaybePendingBlock::Block(block) => Self {
                    status: block.status.into(),
                    block_hash: Some(block.block_hash),
                    parent_hash: block.parent_block_hash,
                    block_number: Some(block.block_number),
                    new_root: Some(block.state_root),
                    timestamp: block.timestamp,
                    sequencer_address: block
                        .sequencer_address
                        // Default value for cairo <0.8.0 is 0
                        .unwrap_or(SequencerAddress(StarkHash::ZERO)),
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
    use crate::core::{StarknetBlockHash, StarknetBlockNumber};
    use crate::starkhash;
    use jsonrpsee::types::Params;

    #[test]
    fn parsing() {
        let number = BlockId::Number(StarknetBlockNumber::new_or_panic(123));
        let hash = BlockId::Hash(StarknetBlockHash(starkhash!("beef")));

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
                .unwrap_or_else(|_| panic!("test case {i}: {input}"));
            assert_eq!(
                actual,
                GetBlockInput { block_id: expected },
                "test case {i}: {input}"
            );
        });
    }
}
