mod error;
mod request;
mod response;
mod router;
pub mod websocket;

use std::sync::Arc;

pub use error::RpcError;
pub use request::RpcRequest;
pub use response::RpcResponse;
#[cfg(test)]
pub use router::handle_json_rpc_socket;
pub use router::{rpc_handler, RpcRouter, RpcRouterBuilder, RpcSubscriptionFlow};
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
}

impl Default for Notifications {
    fn default() -> Self {
        let (block_headers, _) = broadcast::channel(1024);
        Self { block_headers }
    }
}
