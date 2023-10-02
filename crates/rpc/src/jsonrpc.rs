mod error;
mod request;
mod response;
mod router;
pub mod websocket;

pub use error::RpcError;
pub use request::RpcRequest;
pub use response::{RpcResponse, RpcResult};
pub use router::{rpc_handler, IntoRpcMethod, RpcMethodHandler, RpcRouter, RpcRouterBuilder};

#[derive(Debug, PartialEq, Clone)]
pub enum RequestId<'a> {
    Number(i64),
    String(std::borrow::Cow<'a, str>),
    Null,
    Notification,
}

impl RequestId<'_> {
    pub fn is_notification(&self) -> bool {
        self == &RequestId::Notification
    }
}
