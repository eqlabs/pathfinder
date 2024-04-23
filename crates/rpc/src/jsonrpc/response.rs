use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::Value;

use crate::error::ApplicationError;
use crate::jsonrpc::error::RpcError;
use crate::jsonrpc::RequestId;

#[derive(Debug, PartialEq)]
pub struct RpcResponse<'a> {
    pub output: RpcResult,
    pub id: RequestId<'a>,
}

impl<'a> RpcResponse<'a> {
    pub const fn parse_error(error: String) -> RpcResponse<'a> {
        Self {
            output: Err(RpcError::ParseError(error)),
            id: RequestId::Null,
        }
    }

    pub const fn invalid_request(error: String) -> RpcResponse<'a> {
        Self {
            output: Err(RpcError::InvalidRequest(error)),
            id: RequestId::Null,
        }
    }

    pub const fn method_not_found(id: RequestId<'a>) -> RpcResponse<'a> {
        Self {
            output: Err(RpcError::MethodNotFound),
            id,
        }
    }

    pub const fn invalid_params(id: RequestId<'a>, error: String) -> RpcResponse<'a> {
        Self {
            output: Err(RpcError::InvalidParams(error)),
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
            RequestId::Notification => {}
        };

        obj.end()
    }
}

impl IntoResponse for RpcResponse<'_> {
    fn into_response(self) -> axum::response::Response {
        // Log internal errors.
        match &self.output {
            Err(RpcError::InternalError(e))
            | Err(RpcError::ApplicationError(ApplicationError::Internal(e))) => {
                tracing::warn!(backtrace = ?e, "Internal error");
            }
            Err(RpcError::ApplicationError(ApplicationError::Custom(e))) => {
                tracing::debug!(backtrace = ?e, "Custom error");
            }
            _ => {}
        }

        serde_json::to_vec(&self).unwrap().into_response()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn output_is_error() {
        let parsing_err = serde_json::from_str::<u32>("invalid")
            .unwrap_err()
            .to_string();
        let response = RpcResponse {
            output: Err(RpcError::InvalidParams(parsing_err.clone())),
            id: RequestId::Number(1),
        };
        let parsing_err = RpcError::InvalidParams(parsing_err);

        let serialized = serde_json::to_value(&response).unwrap();

        let expected = json!({
            "jsonrpc": "2.0",
            "error": {
                "code": parsing_err.code(),
                "message": parsing_err.message(),
                "data": parsing_err.data(),
            },
            "id": 1,
        });

        assert_eq!(serialized, expected);
    }

    #[test]
    fn output_is_ok() {
        let serialized = serde_json::to_value(&RpcResponse {
            output: Ok(Value::String("foobar".to_owned())),
            id: RequestId::Number(1),
        })
        .unwrap();

        let expected = json!({
            "jsonrpc": "2.0",
            "result": "foobar",
            "id": 1,
        });

        assert_eq!(serialized, expected);
    }
}
