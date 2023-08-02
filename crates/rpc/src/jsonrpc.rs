//! Contains the JSON-RPC framework and its components.

#![allow(unused)]

use std::collections::HashMap;
use std::marker::PhantomData;

use axum::async_trait;
use axum::extract::FromRequest;
use axum::response::{IntoResponse, Response};
use futures::Future;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, PartialEq)]
struct RpcRequest {
    method: String,
    // This is allowed to be missing but to reduce the indirection we
    // map None to to null in the deserialization implementation.
    params: Value,
    id: Option<IdValue>,
}

#[derive(Debug, PartialEq)]
struct RpcResponse {
    output: RpcResult,
    id: IdValue,
}

type RpcResult = Result<Value, RpcError>;

#[derive(Debug, PartialEq)]
enum IdValue {
    Number(i64),
    String(String),
    Null,
}

#[derive(Debug)]
enum RpcError {
    ParseError,
    InvalidRequest,
    MethodNotFound { method: String },
    InvalidParams,
    InternalError(anyhow::Error),
    ApplicationError { code: i32, message: String },
}

impl PartialEq for RpcError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::MethodNotFound { method: l_method },
                Self::MethodNotFound { method: r_method },
            ) => l_method == r_method,
            (Self::InternalError(l0), Self::InternalError(r0)) => l0.to_string() == r0.to_string(),
            (
                Self::ApplicationError {
                    code: l_code,
                    message: l_message,
                },
                Self::ApplicationError {
                    code: r_code,
                    message: r_message,
                },
            ) => l_code == r_code && l_message == r_message,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl RpcError {
    fn code(&self) -> i32 {
        match self {
            RpcError::ParseError => -32700,
            RpcError::InvalidRequest => -32600,
            RpcError::MethodNotFound { .. } => -32601,
            RpcError::InvalidParams => -32602,
            RpcError::InternalError(_) => 32603,
            RpcError::ApplicationError { code, .. } => *code,
        }
    }

    fn message(&self) -> &str {
        match self {
            RpcError::ParseError => "Parse error",
            RpcError::InvalidRequest => "Invalid Request",
            RpcError::MethodNotFound { method } => "Method not found",
            RpcError::InvalidParams => "Invalid params",
            RpcError::InternalError(_) => "Internal error",
            RpcError::ApplicationError { code, message } => message,
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
        obj.serialize_entry("message", self.message())?;
        obj.end()
    }
}

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
            IdValue::Number(x) => obj.serialize_entry("id", &x)?,
            IdValue::String(x) => obj.serialize_entry("id", &x)?,
            IdValue::Null => obj.serialize_entry("id", &Value::Null)?,
        };

        obj.end()
    }
}

impl<'de> Deserialize<'de> for RpcRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        /// Replaces [Option<Value>] because serde maps both `None` and `null`to [Option::None].
        ///
        /// With this helper, null is correctly mapped to [IdHelper::Some(Value::Null)].
        #[derive(Deserialize, Default)]
        #[serde(untagged)]
        enum IdHelper {
            Some(Value),
            #[default]
            None,
        }

        #[derive(Deserialize)]
        struct Helper<'a> {
            #[serde(borrow)]
            jsonrpc: std::borrow::Cow<'a, str>,
            #[serde(default)]
            id: IdHelper,
            method: String,
            #[serde(default)]
            params: Value,
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.jsonrpc != "2.0" {
            return Err(D::Error::custom("Jsonrpc version must be 2.0"));
        }

        let id = match helper.id {
            IdHelper::Some(Value::Null) => Some(IdValue::Null),
            IdHelper::Some(Value::String(x)) => Some(IdValue::String(x)),
            IdHelper::Some(Value::Number(x)) if x.is_i64() => {
                Some(IdValue::Number(x.as_i64().unwrap()))
            }
            IdHelper::Some(Value::Number(x)) if x.is_u64() => {
                return Err(D::Error::custom("id value too large"));
            }
            IdHelper::Some(Value::Number(_)) => {
                return Err(D::Error::custom("id must be an integer"));
            }
            IdHelper::Some(_other) => {
                return Err(D::Error::custom("id must be null, a number or a string"));
            }
            IdHelper::None => None,
        };

        Ok(Self {
            id,
            method: helper.method,
            params: helper.params,
        })
    }
}

impl<E> From<E> for RpcError
where
    E: Into<crate::error::RpcError>,
{
    fn from(value: E) -> Self {
        match value.into() {
            crate::error::RpcError::GatewayError(x) => RpcError::InternalError(x.into()),
            crate::error::RpcError::Internal(x) => RpcError::InternalError(x),
            other => RpcError::ApplicationError {
                code: other.code(),
                message: format!("{other}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    mod request {
        use super::*;

        #[test]
        fn with_null_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": null
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(IdValue::Null),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn with_string_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": "text"
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(IdValue::String("text".to_owned())),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn with_number_id() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: Some(IdValue::Number(456)),
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn notification() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "params": [1,2,3]
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!([1, 2, 3]),
                id: None,
            };
            assert_eq!(result, expected);
        }

        #[test]
        fn jsonrpc_version_missing() {
            let json = json!({
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            RpcRequest::deserialize(json).unwrap_err();
        }

        #[test]
        fn jsonrpc_version_is_not_2() {
            let json = json!({
                "jsonrpc": "1.0",
                "method": "sum",
                "params": [1,2,3],
                "id": 456
            });
            RpcRequest::deserialize(json).unwrap_err();
        }

        #[test]
        fn no_params() {
            let json = json!({
                "jsonrpc": "2.0",
                "method": "sum",
                "id": 456
            });
            let result = RpcRequest::deserialize(json).unwrap();
            let expected = RpcRequest {
                method: "sum".to_owned(),
                params: json!(null),
                id: Some(IdValue::Number(456)),
            };
            assert_eq!(result, expected);
        }
    }

    mod response {
        use super::*;

        #[test]
        fn output_is_error() {
            let serialized = serde_json::to_value(&RpcResponse {
                output: Err(RpcError::InvalidParams),
                id: IdValue::Number(1),
            })
            .unwrap();

            let expected = json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": RpcError::InvalidParams.code(),
                    "message": RpcError::InvalidParams.message(),
                },
                "id": 1,
            });
        }

        #[test]
        fn output_is_ok() {
            let serialized = serde_json::to_value(&RpcResponse {
                output: Ok(Value::String("foobar".to_owned())),
                id: IdValue::Number(1),
            })
            .unwrap();

            let expected = json!({
                "jsonrpc": "2.0",
                "result": "foobar",
                "id": 1,
            });
        }
    }
}
