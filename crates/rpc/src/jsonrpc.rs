mod error;
mod request;
mod response;
mod router;
pub mod websocket;

pub use error::RpcError;
pub use request::RpcRequest;
pub use response::RpcResponse;
pub use router::{rpc_handler, RpcRouter, RpcRouterBuilder};

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
