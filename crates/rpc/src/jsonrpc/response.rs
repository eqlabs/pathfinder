use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::Value;

use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::RequestId;

#[derive(Debug, PartialEq)]
pub struct RpcResponse<'a> {
    pub output: RpcResult,
    pub id: RequestId<'a>,
}

impl<'a> RpcResponse<'a> {
    pub const PARSE_ERROR: Self = Self {
        output: Err(RpcError::ParseError),
        id: RequestId::Null,
    };

    pub const INVALID_REQUEST: Self = Self {
        output: Err(RpcError::InvalidRequest),
        id: RequestId::Null,
    };

    pub const fn method_not_found(id: RequestId<'a>, method: String) -> Self {
        Self {
            output: Err(RpcError::MethodNotFound { method }),
            id,
        }
    }
}

pub type RpcResult = Result<Value, RpcError>;

impl Serialize for RpcResponse<'_> {
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
            RequestId::Notification => {},
            
        };

        obj.end()
    }
}

impl IntoResponse for RpcResponse<'_> {
    fn into_response(self) -> axum::response::Response {
        serde_json::to_vec(&self).unwrap().into_response()
    }
}
