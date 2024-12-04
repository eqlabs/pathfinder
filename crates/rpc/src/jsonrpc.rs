mod error;
mod request;
mod response;
mod router;
pub mod websocket;

use std::sync::Arc;

pub use error::RpcError;
use pathfinder_common::{BlockHash, BlockNumber};
pub use request::RpcRequest;
pub use response::RpcResponse;
#[cfg(test)]
pub use router::{handle_json_rpc_socket, CATCH_UP_BATCH_SIZE};
pub use router::{
    rpc_handler, CatchUp, RpcRouter, RpcRouterBuilder, RpcSubscriptionFlow, SubscriptionMessage,
};
use starknet_gateway_types::reply::Block;
use tokio::sync::broadcast;

#[derive(Debug, PartialEq, Clone)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
    Notification,
}

impl RequestId {
    pub fn is_notification(&self) -> bool {
        self == &RequestId::Notification
    }
}

/// Channels used to notify the RPC of new events. Used by the RPC subscription
/// system.
#[derive(Debug, Clone)]
pub struct Notifications {
    pub block_headers: broadcast::Sender<Arc<pathfinder_common::BlockHeader>>,
    pub l2_blocks: broadcast::Sender<Arc<Block>>,
    pub reorgs: broadcast::Sender<Arc<Reorg>>,
}

#[derive(Debug, Clone)]
pub struct Reorg {
    pub first_block_number: BlockNumber,
    pub first_block_hash: BlockHash,
    pub last_block_number: BlockNumber,
    pub last_block_hash: BlockHash,
}

impl Default for Notifications {
    fn default() -> Self {
        let (block_headers, _) = broadcast::channel(1024);
        let (l2_blocks, _) = broadcast::channel(1024);
        let (reorgs, _) = broadcast::channel(1024);
        Self {
            block_headers,
            l2_blocks,
            reorgs,
        }
    }
}
