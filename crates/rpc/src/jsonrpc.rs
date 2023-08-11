mod error;
mod request;
mod response;
mod router;

pub use error::RpcError;
pub use router::{rpc_handler, RpcMethodHandler, RpcMethod};
pub use response::{RpcResponse, RpcResult};

#[derive(Debug, PartialEq, Clone)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
}
