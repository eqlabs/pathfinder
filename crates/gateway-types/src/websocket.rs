// Types used for web socket subscription events
use crate::reply::{Block, Status};
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, GasPrice, SequencerAddress, StarknetVersion,
    StateCommitment,
};
use pathfinder_serde::GasPriceAsHexStr;
use serde::Deserialize;
use serde_with::serde_as;
use tokio::sync::broadcast::{self};

#[derive(Debug, Clone)]
pub struct RPCSender<T>(pub broadcast::Sender<T>);

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
pub struct WebsocketEventNewHead {
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

impl WebsocketEventNewHead {
    pub fn new(block: Block) -> WebsocketEventNewHead {
        let Block {
            block_hash,
            block_number,
            gas_price,
            parent_block_hash,
            sequencer_address,
            state_commitment,
            status,
            timestamp,
            starknet_version,
            ..
        } = block;
        WebsocketEventNewHead {
            block_hash,
            block_number,
            gas_price,
            parent_block_hash,
            sequencer_address,
            state_commitment,
            status,
            timestamp,
            starknet_version,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebsocketSenders {
    pub new_head: RPCSender<WebsocketEventNewHead>,
}

impl WebsocketSenders {
    pub fn with_capacity(capacity: usize) -> WebsocketSenders {
        WebsocketSenders {
            new_head: RPCSender(broadcast::channel(capacity).0),
        }
    }
}

impl Default for WebsocketSenders {
    fn default() -> Self {
        Self::with_capacity(100)
    }
}
