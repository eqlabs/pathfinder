mod transaction;

pub use transaction::TransactionWithHash;

use crate::felt::RpcFelt;
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, SequencerAddress, StarknetVersion, StateCommitment,
};
use pathfinder_common::{GasPrice, TransactionVersion};
use serde::Serialize;
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr};

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ResourcePrice {
    #[serde_as(as = "pathfinder_serde::GasPriceAsHexStr")]
    pub price_in_fri: GasPrice,
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
    #[serde_as(as = "DisplayFromStr")]
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
                price_in_fri: header.strk_l1_gas_price,
                price_in_wei: header.eth_l1_gas_price,
            },
            starknet_version: header.starknet_version,
        }
    }
}

impl BlockHeader {
    /// Constructs [BlockHeader] from [sequencer's pending block representation](starknet_gateway_types::reply::PendingBlock)
    pub fn from_sequencer_pending(pending: starknet_gateway_types::reply::PendingBlock) -> Self {
        Self {
            block_hash: None,
            parent_hash: pending.parent_hash,
            block_number: None,
            new_root: None,
            timestamp: pending.timestamp,
            sequencer_address: pending.sequencer_address,
            l1_gas_price: ResourcePrice {
                price_in_fri: pending.l1_gas_price.price_in_fri,
                price_in_wei: pending.l1_gas_price.price_in_wei,
            },
            starknet_version: pending.starknet_version,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub enum PriceUnit {
    #[serde(rename = "WEI")]
    Wei,
    #[serde(rename = "FRI")]
    Fri,
}

impl From<pathfinder_executor::types::PriceUnit> for PriceUnit {
    fn from(value: pathfinder_executor::types::PriceUnit) -> Self {
        match value {
            pathfinder_executor::types::PriceUnit::Wei => Self::Wei,
            pathfinder_executor::types::PriceUnit::Fri => Self::Fri,
        }
    }
}

impl PriceUnit {
    pub fn for_transaction_version(version: &TransactionVersion) -> Self {
        match version.without_query_version() {
            0..=2 => PriceUnit::Wei,
            _ => PriceUnit::Fri,
        }
    }
}
