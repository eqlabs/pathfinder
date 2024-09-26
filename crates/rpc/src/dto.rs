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
    pub version: RpcVersion,
    /// The name of the field that this value was deserialized from. None if
    /// this is a root value.
    name: Option<&'static str>,
}

impl Value {
    pub fn new(data: serde_json::Value, version: RpcVersion) -> Self {
        Self {
            data,
            version,
            name: None,
        }
    }

    pub fn is_string(&self) -> bool {
        self.data.is_string()
    }

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
        let data = match self.data {
            serde_json::Value::Object(map) => MapOrArray::Map(map),
            serde_json::Value::Array(values) => MapOrArray::Array { values, offset: 0 },
            _ => {
                return Err(serde_json::Error::custom(match self.name {
                    Some(name) => format!("expected object or array for \"{name}\""),
                    None => "expected object or array".to_string(),
                }))
            }
        };
        let mut map = Map {
            data,
            version: self.version,
        };
        let result = cb(&mut map)?;
        match map.data {
            MapOrArray::Map(map) => {
                if !map.is_empty() {
                    let fields = map
                        .keys()
                        .map(|key| format!("\"{key}\""))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(serde_json::Error::custom(format!(
                        "unexpected field{}: {fields}{}",
                        if map.len() == 1 { "" } else { "s" },
                        match self.name {
                            Some(name) => format!(" for \"{name}\""),
                            None => Default::default(),
                        },
                    )));
                }
            }
            MapOrArray::Array { values, offset } => {
                if offset < values.len() {
                    return Err(serde_json::Error::custom(format!(
                        "expected {} field{}, got {}",
                        values.len(),
                        if values.len() == 1 { "" } else { "s" },
                        offset,
                    )));
                }
            }
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
    data: MapOrArray,
    version: RpcVersion,
}

enum MapOrArray {
    Map(serde_json::value::Map<String, serde_json::Value>),
    Array {
        values: Vec<serde_json::Value>,
        offset: usize,
    },
}

impl Map {
    pub fn contains_key(&self, key: &'static str) -> bool {
        match &self.data {
            MapOrArray::Map(data) => data.contains_key(key),
            MapOrArray::Array { values, offset } => false,
        }
    }

    pub fn deserialize<T: DeserializeForVersion>(
        &mut self,
        key: &'static str,
    ) -> Result<T, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key).ok_or_else(|| {
                    serde_json::Error::custom(format!("missing field: \"{key}\""))
                })?;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize()
            }
            MapOrArray::Array { values, offset } => {
                let value = values
                    .get_mut(*offset)
                    .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?
                    .take();
                *offset += 1;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize()
            }
        }
    }

    pub fn deserialize_optional<T: DeserializeForVersion>(
        &mut self,
        key: &'static str,
    ) -> Result<Option<T>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key);
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        Ok(Some(value.deserialize()?))
                    }
                    None => Ok(None),
                }
            }
            MapOrArray::Array { values, offset } => {
                let value = values.get_mut(*offset).map(|value| value.take());
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        *offset += 1;
                        Ok(Some(value.deserialize()?))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    // TODO This should be removed once all existing DTOs have been migrated.
    pub fn deserialize_serde<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        key: &'static str,
    ) -> Result<T, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key).ok_or_else(|| {
                    serde_json::Error::custom(format!("missing field: \"{key}\""))
                })?;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_serde()
            }
            MapOrArray::Array { values, offset } => {
                let value = values
                    .get_mut(*offset)
                    .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?
                    .take();
                *offset += 1;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_serde()
            }
        }
    }

    // TODO This should be removed once all existing DTOs have been migrated.
    pub fn deserialize_optional_serde<T: for<'a> serde::Deserialize<'a>>(
        &mut self,
        key: &'static str,
    ) -> Result<Option<T>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key);
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        Ok(Some(value.deserialize_serde()?))
                    }
                    None => Ok(None),
                }
            }
            MapOrArray::Array { values, offset } => {
                let value = values.get_mut(*offset).map(|value| value.take());
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        *offset += 1;
                        Ok(Some(value.deserialize_serde()?))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    pub fn deserialize_map<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(&mut Map) -> Result<T, serde_json::Error>,
    ) -> Result<T, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key).ok_or_else(|| {
                    serde_json::Error::custom(format!("missing field: \"{key}\""))
                })?;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_map(cb)
            }
            MapOrArray::Array { values, offset } => {
                let value = values
                    .get_mut(*offset)
                    .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?
                    .take();
                *offset += 1;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_map(cb)
            }
        }
    }

    pub fn deserialize_optional_map<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(&mut Map) -> Result<T, serde_json::Error>,
    ) -> Result<Option<T>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key);
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        Ok(Some(value.deserialize_map(cb)?))
                    }
                    None => Ok(None),
                }
            }
            MapOrArray::Array { values, offset } => {
                let value = values.get_mut(*offset).map(|value| value.take());
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        *offset += 1;
                        Ok(Some(value.deserialize_map(cb)?))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    pub fn deserialize_array<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(Value) -> Result<T, serde_json::Error>,
    ) -> Result<Vec<T>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key).ok_or_else(|| {
                    serde_json::Error::custom(format!("missing field: \"{key}\""))
                })?;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_array(cb)
            }
            MapOrArray::Array { values, offset } => {
                let value = values
                    .get_mut(*offset)
                    .ok_or_else(|| serde_json::Error::custom(format!("missing field: \"{key}\"")))?
                    .take();
                *offset += 1;
                Value {
                    data: value,
                    name: Some(key),
                    version: self.version,
                }
                .deserialize_array(cb)
            }
        }
    }

    pub fn deserialize_optional_array<T>(
        &mut self,
        key: &'static str,
        cb: impl Fn(Value) -> Result<T, serde_json::Error>,
    ) -> Result<Option<Vec<T>>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key);
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        Ok(Some(value.deserialize_array(cb)?))
                    }
                    None => Ok(None),
                }
            }
            MapOrArray::Array { values, offset } => {
                let value = values.get_mut(*offset).map(|value| value.take());
                match value {
                    Some(value) => {
                        let value = Value {
                            data: value,
                            name: Some(key),
                            version: self.version,
                        };
                        *offset += 1;
                        Ok(Some(value.deserialize_array(cb)?))
                    }
                    None => Ok(None),
                }
            }
        }
    }
}
