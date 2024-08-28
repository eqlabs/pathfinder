#![allow(unused)]

use serde::de::{Error, IntoDeserializer};

mod block;
mod class;
mod event;
mod fee;
mod primitives;
mod receipt;
mod simulation;
mod state_update;
mod transaction;

pub mod serialize;

pub use block::*;
pub use class::*;
pub use event::*;
pub use fee::*;
pub use primitives::*;
pub use receipt::*;
pub use simulation::*;
pub use state_update::*;
pub use transaction::*;

use crate::RpcVersion;

pub trait DeserializeForVersion: Sized {
    fn deserialize(value: Value) -> Result<Self, serde_json::Error>;
}

#[derive(Debug)]
pub struct Value {
    data: serde_json::Value,
    version: RpcVersion,
    /// The name of the field that this value was deserialized from. None if
    /// this is a root value.
    name: Option<&'static str>,
}

impl Value {
    pub fn deserialize<T: DeserializeForVersion>(self) -> Result<T, serde_json::Error> {
        T::deserialize(self)
    }

    // TODO This should be removed once all existing DTOs have been migrated.
    pub fn deserialize_serde<T: for<'a> serde::Deserialize<'a>>(
        self,
    ) -> Result<T, serde_json::Error> {
        serde::Deserialize::deserialize(self.data.into_deserializer())
    }

    pub fn deserialize_map<T>(
        self,
        cb: impl FnOnce(&mut Map) -> Result<T, serde_json::Error>,
    ) -> Result<T, serde_json::Error> {
        let serde_json::Value::Object(map) = self.data else {
            return Err(serde_json::Error::custom(match self.name {
                Some(name) => format!("expected object for \"{name}\""),
                None => "expected object".to_string(),
            }));
        };
        let mut map = Map {
            data: map,
            version: self.version,
        };
        let result = cb(&mut map)?;
        if !map.data.is_empty() {
            let fields = map
                .data
                .keys()
                .map(|key| format!("\"{key}\""))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(serde_json::Error::custom(format!(
                "unexpected field{}: {fields}{}",
                if map.data.len() == 1 { "" } else { "s" },
                match self.name {
                    Some(name) => format!(" for \"{name}\""),
                    None => Default::default(),
                },
            )));
        }
        Ok(result)
    }

    pub fn deserialize_array<T>(
        self,
        cb: impl Fn(Value) -> Result<T, serde_json::Error>,
    ) -> Result<Vec<T>, serde_json::Error> {
        let serde_json::Value::Array(array) = self.data else {
            return Err(serde_json::Error::custom(match self.name {
                Some(name) => format!("expected array for \"{name}\""),
                None => "expected array".to_string(),
            }));
        };
        array
            .into_iter()
            .map(|value| {
                cb(Value {
                    data: value,
                    name: None,
                    version: self.version,
                })
            })
            .collect()
    }
}

pub struct Map {
    data: serde_json::value::Map<String, serde_json::Value>,
    version: RpcVersion,
}

impl Map {
    pub fn deserialize<T: DeserializeForVersion>(
        &mut self,
        key: &'static str,
    ) -> Result<T, serde_json::Error> {
        let value = self
            .data
            .remove(key)
            .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?;
        Value {
            data: value,
            name: Some(key),
            version: self.version,
        }
        .deserialize()
    }

    // TODO This should be removed once all existing DTOs have been migrated.
    pub fn deserialize_serde<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        key: &'static str,
    ) -> Result<T, serde_json::Error> {
        let value = self
            .data
            .remove(key)
            .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?;
        Value {
            data: value,
            name: Some(key),
            version: self.version,
        }
        .deserialize_serde()
    }

    pub fn deserialize_map<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(&mut Map) -> Result<T, serde_json::Error>,
    ) -> Result<T, serde_json::Error> {
        let value = self
            .data
            .remove(key)
            .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?;
        Value {
            data: value,
            name: Some(key),
            version: self.version,
        }
        .deserialize_map(cb)
    }

    pub fn deserialize_array<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(Value) -> Result<T, serde_json::Error>,
    ) -> Result<Vec<T>, serde_json::Error> {
        let value = self
            .data
            .remove(key)
            .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?;
        Value {
            data: value,
            name: Some(key),
            version: self.version,
        }
        .deserialize_array(cb)
    }
}
