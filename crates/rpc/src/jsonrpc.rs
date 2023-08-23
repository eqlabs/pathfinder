mod error;
mod request;
mod response;
mod router;

pub use error::RpcError;
pub use response::{RpcResponse, RpcResult};
pub use router::{IntoRpcMethod, RpcMethodHandler, RpcRouter, RpcRouterBuilder, is_empty_params};
pub use request::RpcRequest;

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