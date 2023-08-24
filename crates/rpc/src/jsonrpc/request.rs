use serde::Deserialize;
use serde_json::value::RawValue;

use crate::jsonrpc::{RequestId, RpcError};

use std::borrow::Cow;

#[derive(Debug)]
pub struct RpcRequest<'a> {
    pub method: &'a str,
    pub params: RawParams<'a>,
    pub id: RequestId<'a>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RawParams<'a> {
    #[serde(borrow)]
    inner: Option<&'a RawValue>,
}

impl<'a> RawParams<'a> {
    /// Returns true if there are no params or the list of params is empty.
    pub fn is_empty(&self) -> bool {
        let Some(params) = self.inner else {
            return true;
        };

        let params = params.get().trim().as_bytes();
        if params.is_empty() {
            return true;
        }

        let first = params.first();
        let last = params.last();

        let is_array = first == Some(&b'[') && last == Some(&b']');
        let is_object = first == Some(&b'{') && last == Some(&b'}');

        if is_array || is_object {
            return params
                .iter()
                .skip(1)
                .rev()
                .skip(1)
                .all(u8::is_ascii_whitespace);
        }

        false
    }

    pub fn deserialize<T: Deserialize<'a>>(self) -> Result<T, RpcError> {
        let s = self.inner.map(|x| x.get()).unwrap_or_default();

        serde_json::from_str::<T>(s).map_err(|_| RpcError::InvalidParams)
    }
}

impl<'de> Deserialize<'de> for RpcRequest<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        /// Replaces [Option<Value>] because serde maps both `None` and `null`to [Option::None].
        ///
        /// With this helper, null is correctly mapped to [IdHelper::Some(Value::Null)].
        #[derive(Deserialize, Debug)]
        #[serde(untagged)]
        enum IdHelper<'a> {
            Number(i64),
            #[serde(borrow)]
            String(Cow<'a, str>),
        }

        #[derive(Deserialize)]
        struct Helper<'a> {
            jsonrpc: Cow<'a, str>,
            // Double-bag the ID. This is required because serde maps both None and Null to None.
            //
            // The first Option lets us distinguish between None and null. The second Option is then
            // used to parse the null case.
            #[serde(default, borrow, deserialize_with = "deserialize_some")]
            id: Option<Option<IdHelper<'a>>>,
            method: &'a str,
            #[serde(default, borrow)]
            params: RawParams<'a>,
        }

        // Any value that is present is considered Some value, including null.
        fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            T: Deserialize<'de> + std::fmt::Debug,
            D: serde::Deserializer<'de>,
        {
            Deserialize::deserialize(deserializer).map(|x| Some(x))
        }

        let helper = Helper::deserialize(deserializer)?;

        if helper.jsonrpc != "2.0" {
            return Err(D::Error::custom("Jsonrpc version must be 2.0"));
        }

        let id = match helper.id {
            Some(Some(IdHelper::Number(x))) => RequestId::Number(x),
            Some(Some(IdHelper::String(x))) => RequestId::String(x),
            Some(None) => RequestId::Null,
            None => RequestId::Notification,
        };

        Ok(Self {
            id,
            method: helper.method,
            params: helper.params,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serde_json::value::to_raw_value;

    use super::*;

    impl PartialEq for RpcRequest<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.method == other.method && self.id == other.id && self.params == other.params
        }
    }

    impl PartialEq for RawParams<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.inner.map(|x| x.get()) == other.inner.map(|x| x.get())
        }
    }

    #[test]
    fn with_null_id() {
        let json = json!({
            "jsonrpc": "2.0",
            "method": "sum",
            "params": [1,2,3],
            "id": null
        });

        let params = json!([1, 2, 3]);
        let params = to_raw_value(&params).unwrap();

        let result = RpcRequest::deserialize(json).unwrap();
        let expected = RpcRequest {
            method: "sum",
            params: RawParams {
                inner: Some(&params),
            },
            id: RequestId::Null,
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

        let params = json!([1, 2, 3]);
        let params = to_raw_value(&params).unwrap();

        let result = RpcRequest::deserialize(json).unwrap();
        let expected = RpcRequest {
            method: "sum",
            params: RawParams {
                inner: Some(&params),
            },
            id: RequestId::String("text".into()),
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

        let params = json!([1, 2, 3]);
        let params = to_raw_value(&params).unwrap();

        let result = RpcRequest::deserialize(json).unwrap();
        let expected = RpcRequest {
            method: "sum",
            params: RawParams {
                inner: Some(&params),
            },
            id: RequestId::Number(456),
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

        let params = json!([1, 2, 3]);
        let params = to_raw_value(&params).unwrap();

        let result = RpcRequest::deserialize(json).unwrap();
        let expected = RpcRequest {
            method: "sum",
            params: RawParams {
                inner: Some(&params),
            },
            id: RequestId::Notification,
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
            method: "sum",
            params: RawParams { inner: None },
            id: RequestId::Number(456),
        };
        assert_eq!(result, expected);
    }

    mod raw_params {
        use super::*;

        #[rstest::rstest]
        #[case::array("[]")]
        #[case::array_with_spaces("[     ]")]
        #[case::array_with_newlines(
            r"[ 


        ]"
        )]
        #[case::object("{}")]
        #[case::object_with_spaces("{   }")]
        #[case::object_with_newlines(
            r"{ 

            
        }"
        )]
        fn empty(#[case] s: &str) {
            let raw_value = RawValue::from_string(s.to_owned()).unwrap();
            let uut = RawParams {
                inner: Some(&raw_value),
            };

            assert!(uut.is_empty());
        }

        #[rstest::rstest]
        #[case::array("[123]")]
        #[case::object(r#"{"a": 123}"#)]
        fn not_empty(#[case] s: &str) {
            let raw_value = RawValue::from_string(s.to_owned()).unwrap();
            let uut = RawParams {
                inner: Some(&raw_value),
            };

            assert!(!uut.is_empty());
        }
    }
}
