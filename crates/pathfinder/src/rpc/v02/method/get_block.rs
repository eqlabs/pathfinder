use crate::core::BlockId;
use crate::rpc::v02::RpcContext;

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
    _context: RpcContext,
    _block_id: BlockId,
    _scope: types::BlockResponseScope,
) -> Result<types::Block, GetBlockError> {
    todo!()
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
