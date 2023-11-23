mod transaction;

pub use transaction::{Transaction, TransactionWithHash};

use crate::felt::RpcFelt;
use pathfinder_common::GasPrice;
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, SequencerAddress, StarknetVersion, StateCommitment,
};
use pathfinder_crypto::Felt;
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none};

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourcePrice {
    #[serde_as(as = "pathfinder_serde::GasPriceAsHexStr")]
    pub price_in_strk: GasPrice,
    #[serde_as(as = "pathfinder_serde::GasPriceAsHexStr")]
    pub price_in_wei: GasPrice,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BlockHeader {
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
    pub l1_gas_price: ResourcePrice,
    pub starknet_version: StarknetVersion,
}

impl From<pathfinder_common::BlockHeader> for BlockHeader {
    fn from(header: pathfinder_common::BlockHeader) -> Self {
        Self {
            block_hash: Some(header.hash),
            parent_hash: header.parent_hash,
            block_number: Some(header.number),
            new_root: Some(header.state_commitment),
            timestamp: header.timestamp,
            sequencer_address: header.sequencer_address,
            l1_gas_price: ResourcePrice {
                price_in_strk: header.strk_l1_gas_price,
                price_in_wei: header.eth_l1_gas_price,
            },
            starknet_version: header.starknet_version,
        }
    }
}

impl BlockHeader {
    /// Constructs [BlockHeader] from [sequencer's block representation](starknet_gateway_types::reply::Block)
    pub fn from_sequencer(block: starknet_gateway_types::reply::MaybePendingBlock) -> Self {
        use starknet_gateway_types::reply::MaybePendingBlock;
        match block {
            MaybePendingBlock::Block(block) => Self {
                block_hash: Some(block.block_hash),
                parent_hash: block.parent_block_hash,
                block_number: Some(block.block_number),
                new_root: Some(block.state_commitment),
                timestamp: block.timestamp,
                sequencer_address: block
                    .sequencer_address
                    // Default value for cairo <0.8.0 is 0
                    .unwrap_or(SequencerAddress(Felt::ZERO)),
                l1_gas_price: ResourcePrice {
                    price_in_strk: block.strk_l1_gas_price.unwrap_or_default(),
                    price_in_wei: block.eth_l1_gas_price.unwrap_or_default(),
                },
                starknet_version: block.starknet_version,
            },
            MaybePendingBlock::Pending(pending) => Self {
                block_hash: None,
                parent_hash: pending.parent_hash,
                block_number: None,
                new_root: None,
                timestamp: pending.timestamp,
                sequencer_address: pending.sequencer_address,
                l1_gas_price: ResourcePrice {
                    price_in_strk: pending.strk_l1_gas_price.unwrap_or_default(),
                    price_in_wei: pending.eth_l1_gas_price,
                },
                starknet_version: pending.starknet_version,
            },
        }
    }
}
