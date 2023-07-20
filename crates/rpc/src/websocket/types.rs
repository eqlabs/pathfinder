// Types used for web socket subscription events
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, GasPrice, SequencerAddress, StarknetVersion,
    StateCommitment,
};
use pathfinder_serde::GasPriceAsHexStr;
use serde::Deserialize;
use serde_with::serde_as;
use starknet_gateway_types::reply::{Block, Status};
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct SubscriptionBroadcaster<T>(pub broadcast::Sender<T>);

impl<T> SubscriptionBroadcaster<T> {
    pub fn send_if_receiving(&self, value: T) {
        if self.0.receiver_count() > 0 {
            let _ = self.0.send(value);
        }
    }
}
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,

    #[serde_as(as = "Option<GasPriceAsHexStr>")]
    #[serde(default)]
    pub gas_price: Option<GasPrice>,
    pub parent_block_hash: BlockHash,

    #[serde(default)]
    pub sequencer_address: Option<SequencerAddress>,

    #[serde(alias = "state_root")]
    pub state_commitment: StateCommitment,
    pub status: Status,
    pub timestamp: BlockTimestamp,

    #[serde(default)]
    pub starknet_version: StarknetVersion,
}

impl From<&Block> for BlockHeader {
    fn from(b: &Block) -> Self {
        Self {
            block_hash: b.block_hash,
            block_number: b.block_number,
            gas_price: b.gas_price,
            parent_block_hash: b.parent_block_hash,
            sequencer_address: b.sequencer_address,
            state_commitment: b.state_commitment,
            status: b.status,
            timestamp: b.timestamp,
            starknet_version: b.starknet_version.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebsocketSenders {
    pub new_head: SubscriptionBroadcaster<BlockHeader>,
}

impl WebsocketSenders {
    pub fn with_capacity(capacity: usize) -> WebsocketSenders {
        WebsocketSenders {
            new_head: SubscriptionBroadcaster(broadcast::channel(capacity).0),
        }
    }
}

impl WebsocketSenders {
    pub fn for_test() -> Self {
        Self::with_capacity(100)
    }
}
