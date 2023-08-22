use serde::Deserialize;
use serde_json::Value;

use crate::jsonrpc::RequestId;

use std::borrow::Cow;

#[derive(Debug, PartialEq)]
pub struct RpcRequest<'a> {
    pub method: String,
    // This is allowed to be missing but to reduce the indirection we
    // map None to to null in the deserialization implementation.
    pub params: Value,
    // TODO: remove the option
    pub id: Option<RequestId<'a>>,
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
            method: String,
            #[serde(default)]
            params: Value,
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
            Some(inner) => match inner {
                Some(IdHelper::Number(x)) => Some(RequestId::Number(x)),
                Some(IdHelper::String(x)) => Some(RequestId::String(x)),
                None => Some(RequestId::Null),
            },
            None => None,
        };

        Ok(Self {
            id,
            method: helper.method,
            params: helper.params,
        })
    }
}
