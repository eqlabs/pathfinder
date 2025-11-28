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
pub use router::handle_json_rpc_socket;
pub use router::{
    rpc_handler,
    CatchUp,
    RpcRouter,
    RpcRouterBuilder,
    RpcSubscriptionFlow,
    SubscriptionMessage,
};
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
    pub l2_blocks: broadcast::Sender<Arc<pathfinder_common::L2Block>>,
    pub reorgs: broadcast::Sender<Arc<Reorg>>,
}

#[derive(Debug, Clone)]
pub struct Reorg {
    /// First known block of the orphaned chain.
    pub starting_block_number: BlockNumber,
    /// [BlockHash] of [Reorg::starting_block_number].
    pub starting_block_hash: BlockHash,
    /// Last known block of the orphaned chain.
    pub ending_block_number: BlockNumber,
    /// [BlockHash] of [Reorg::ending_block_number].
    pub ending_block_hash: BlockHash,
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
