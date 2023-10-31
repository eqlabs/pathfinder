use std::borrow::Cow;

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug)]
pub enum RpcError {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError(anyhow::Error),
    ApplicationError(crate::error::ApplicationError),
    WebsocketSubscriptionClosed {
        subscription_id: u32,
        reason: String,
    },
}

impl PartialEq for RpcError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InternalError(l0), Self::InternalError(r0)) => l0.to_string() == r0.to_string(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl RpcError {
    pub fn code(&self) -> i32 {
        // From the json-rpc specification: https://www.jsonrpc.org/specification#error_object
        match self {
            RpcError::ParseError => -32700,
            RpcError::InvalidRequest => -32600,
            RpcError::MethodNotFound { .. } => -32601,
            RpcError::InvalidParams => -32602,
            RpcError::InternalError(_) => -32603,
            RpcError::ApplicationError(err) => err.code(),
            RpcError::WebsocketSubscriptionClosed { .. } => -32099,
        }
    }

    pub fn message(&self) -> Cow<'_, str> {
        match self {
            RpcError::ParseError => "Parse error".into(),
            RpcError::InvalidRequest => "Invalid Request".into(),
            RpcError::MethodNotFound { .. } => "Method not found".into(),
            RpcError::InvalidParams => "Invalid params".into(),
            RpcError::InternalError(_) => "Internal error".into(),
            RpcError::ApplicationError(e) => e.to_string().into(),
            RpcError::WebsocketSubscriptionClosed { .. } => "Websocket subscription closed".into(),
        }
    }

    pub fn data(&self) -> Option<Value> {
        match self {
            RpcError::WebsocketSubscriptionClosed {
                subscription_id,
                reason,
            } => Some(json!({
                "id": subscription_id,
                "reason": reason,
            })),
            RpcError::ApplicationError(e) => e.data(),
            RpcError::InternalError(_) => None,
            RpcError::ParseError => None,
            RpcError::InvalidRequest => None,
            RpcError::MethodNotFound => None,
            RpcError::InvalidParams => None,
        }
    }
}

impl Serialize for RpcError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut obj = serializer.serialize_map(Some(2))?;
        obj.serialize_entry("code", &self.code())?;
        obj.serialize_entry("message", &self.message())?;

        if let Some(data) = self.data() {
            obj.serialize_entry("data", &data)?;
        }

        obj.end()
    }
}

impl<E> From<E> for RpcError
where
    E: Into<crate::error::ApplicationError>,
{
    fn from(value: E) -> Self {
        Self::ApplicationError(value.into())
    }
}
