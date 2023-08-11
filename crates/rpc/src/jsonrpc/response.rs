use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::Value;

use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::RequestId;

#[derive(Debug, PartialEq)]
pub struct RpcResponse {
    pub output: RpcResult,
    pub id: RequestId,
}

impl RpcResponse {
    pub const PARSE_ERROR: Self = Self {
        output: Err(RpcError::ParseError),
        id: RequestId::Null,
    };

    pub const INVALID_REQUEST: Self = Self {
        output: Err(RpcError::InvalidRequest),
        id: RequestId::Null,
    };
}

pub type RpcResult = Result<Value, RpcError>;

impl Serialize for RpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut obj = serializer.serialize_map(Some(3))?;
        obj.serialize_entry("jsonrpc", "2.0")?;

        match &self.output {
            Ok(x) => obj.serialize_entry("result", &x)?,
            Err(e) => obj.serialize_entry("error", &e)?,
        };

        match &self.id {
            RequestId::Number(x) => obj.serialize_entry("id", &x)?,
            RequestId::String(x) => obj.serialize_entry("id", &x)?,
            RequestId::Null => obj.serialize_entry("id", &Value::Null)?,
        };

        obj.end()
    }
}

impl IntoResponse for RpcResponse {
    fn into_response(self) -> axum::response::Response {
        serde_json::to_vec(&self).unwrap().into_response()
    }
}
