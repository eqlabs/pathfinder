use serde::Deserialize;
use serde_json::value::RawValue;

use crate::jsonrpc::RequestId;

use std::borrow::Cow;

#[derive(Debug)]
pub struct RpcRequest<'a> {
    pub method: &'a str,
    pub params: Option<&'a RawValue>,
    pub id: RequestId<'a>,
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
            params: Option<&'a RawValue>,
        }

        // Any value that is present is considered Some value, including null.
        fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            T: Deserialize<'de> + std::fmt::Debug,
            D: serde::Deserializer<'de>,
        {
            Deserialize::deserialize(deserializer).map(|x| Some(dbg!(x)))
        }

        println!("here");
        let helper = Helper::deserialize(deserializer).map_err(|e| dbg!(e))?;
        println!("here2");

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
            self.method == other.method
                && self.id == other.id
                && self.params.map(|x| x.get()) == other.params.map(|x| x.get())
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
            params: Some(&params),
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
            params: Some(&params),
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
            params: Some(&params),
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
            params: Some(&params),
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
            params: None,
            id: RequestId::Number(456),
        };
        assert_eq!(result, expected);
    }
}
