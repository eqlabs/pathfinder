mod error;
mod request;
mod response;
mod router;

pub use error::RpcError;
pub use response::{RpcResponse, RpcResult};
pub use router::{IntoRpcMethod, RpcMethodHandler, RpcRouter, RpcRouterBuilder};

#[derive(Debug, PartialEq, Clone)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
}
