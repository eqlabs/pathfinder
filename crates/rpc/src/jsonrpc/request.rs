use serde::Deserialize;
use serde_json::Value;

use crate::jsonrpc::RequestId;

#[derive(Debug, PartialEq)]
pub struct RpcRequest {
    pub method: String,
    // This is allowed to be missing but to reduce the indirection we
    // map None to to null in the deserialization implementation.
    pub params: Value,
    // TODO: remove the option
    pub id: Option<RequestId>,
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
            IdHelper::Some(Value::Null) => Some(RequestId::Null),
            IdHelper::Some(Value::String(x)) => Some(RequestId::String(x)),
            IdHelper::Some(Value::Number(x)) if x.is_i64() => {
                Some(RequestId::Number(x.as_i64().unwrap()))
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
