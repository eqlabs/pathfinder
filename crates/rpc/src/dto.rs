#![allow(unused)]

use serde::de::{Error as SerdeError, IntoDeserializer};

mod block;
mod class;
mod event;
mod fee;
mod finality_status;
mod primitives;
mod receipt;
mod simulation;
mod state_update;
mod transaction;

pub use block::*;
pub use class::*;
pub use event::*;
pub use fee::*;
pub use finality_status::*;
pub use primitives::*;
pub use receipt::*;
pub use simulation::*;
pub use state_update::*;
pub use transaction::*;

use crate::RpcVersion;

#[derive(Copy, Clone)]
#[cfg_attr(test, derive(Default))]
pub struct Serializer {
    pub version: RpcVersion,
}

pub struct SerializeStruct {
    pub version: RpcVersion,
    fields: serde_json::Map<String, Ok>,
}

type BaseSerializer = serde_json::value::Serializer;
pub(crate) type Ok = <BaseSerializer as serde::Serializer>::Ok;
pub(crate) type Error = <BaseSerializer as serde::Serializer>::Error;

pub trait SerializeForVersion {
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error>;
}

impl SerializeForVersion for serde_json::Value {
    fn serialize(&self, _serializer: Serializer) -> Result<Ok, Error> {
        Ok(self.clone())
    }
}

impl SerializeForVersion for &serde_json::Value {
    fn serialize(&self, _serializer: Serializer) -> Result<Ok, Error> {
        Ok((*self).clone())
    }
}

impl Serializer {
    pub fn new(version: RpcVersion) -> Self {
        Self { version }
    }

    pub fn serialize(self, value: &dyn SerializeForVersion) -> Result<Ok, Error> {
        value.serialize(self)
    }

    pub fn serialize_unit(self) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_unit()
    }

    pub fn serialize_str(self, value: &str) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_str(value)
    }

    pub fn serialize_i32(self, value: i32) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_i32(value)
    }

    pub fn serialize_i64(self, value: i64) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_i64(value)
    }

    pub fn serialize_u32(self, value: u32) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_u32(value)
    }

    pub fn serialize_u64(self, value: u64) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_u64(value)
    }

    pub fn serialize_u128(self, value: u128) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_u128(value)
    }

    pub fn serialize_bool(self, value: bool) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_bool(value)
    }

    pub fn serialize_struct(self) -> Result<SerializeStruct, Error> {
        Ok(SerializeStruct {
            version: self.version,
            fields: Default::default(),
        })
    }

    pub fn serialize_iter(
        self,
        len: usize,
        values: &mut dyn Iterator<Item = impl SerializeForVersion>,
    ) -> Result<Ok, Error> {
        use serde::ser::SerializeSeq;
        use serde::Serializer;

        let mut serializer = BaseSerializer {}.serialize_seq(Some(len))?;
        for value in values {
            let value = self.serialize(&value)?;
            serializer.serialize_element(&value)?;
        }
        serializer.end()
    }
}

impl SerializeStruct {
    pub fn serialize_field(
        &mut self,
        key: &'static str,
        value: &dyn SerializeForVersion,
    ) -> Result<(), Error> {
        let value = value.serialize(Serializer::new(self.version))?;
        self.fields.insert(key.to_owned(), value);
        Ok(())
    }

    pub fn serialize_iter(
        &mut self,
        key: &'static str,
        len: usize,
        values: &mut dyn Iterator<Item = impl SerializeForVersion>,
    ) -> Result<(), Error> {
        let seq = Serializer::new(self.version).serialize_iter(len, values)?;
        self.serialize_field(key, &seq)
    }

    /// Skips serialization if it's [`None`].
    pub fn serialize_optional(
        &mut self,
        key: &'static str,
        value: Option<impl SerializeForVersion>,
    ) -> Result<(), Error> {
        if let Some(value) = value {
            self.serialize_field(key, &value)?;
        }

        Ok(())
    }

    /// Serializes optional value as null if it's [`None`].
    pub fn serialize_optional_with_null(
        &mut self,
        key: &'static str,
        value: Option<impl SerializeForVersion>,
    ) -> Result<(), Error> {
        if let Some(value) = value {
            self.serialize_field(key, &value)?;
        } else {
            self.serialize_field(key, &serde_json::Value::Null)?;
        }

        Ok(())
    }

    pub fn flatten(&mut self, value: &dyn SerializeForVersion) -> Result<(), Error> {
        let value = value.serialize(Serializer::new(self.version))?;

        if let serde_json::Value::Object(value) = value {
            for (k, v) in value {
                self.fields.insert(k, v);
            }
        }

        Ok(())
    }

    pub fn end(self) -> Result<Ok, Error> {
        Ok(serde_json::Value::Object(self.fields))
    }
}

pub trait DeserializeForVersion: Sized {
    fn deserialize(value: Value) -> Result<Self, serde_json::Error>;
}

#[derive(Clone, Debug)]
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

    pub fn from_str(data: &str, version: RpcVersion) -> Result<Self, serde_json::Error> {
        let data = serde_json::from_str(data)?;
        Ok(Self::new(data, version))
    }

    pub fn is_string(&self) -> bool {
        self.data.is_string()
    }

    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn json_value(&self) -> serde_json::Value {
        self.data.clone()
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

    pub fn deserialize_optional_array_or_scalar<T: DeserializeForVersion>(
        &mut self,
        key: &'static str,
        cb: impl Fn(Value) -> Result<T, serde_json::Error>,
    ) -> Result<Vec<T>, serde_json::Error> {
        match &mut self.data {
            MapOrArray::Map(data) => {
                let value = data.remove(key);
                match value {
                    Some(value) => {
                        let value1 = Value {
                            data: value.clone(),
                            name: Some(key),
                            version: self.version,
                        };
                        match value1.deserialize_array(&cb) {
                            Ok(res) => Ok(res),
                            Err(_) => {
                                let value2 = Value {
                                    data: value,
                                    name: Some(key),
                                    version: self.version,
                                };
                                let scalar = cb(value2)?;
                                Ok(vec![scalar])
                            }
                        }
                    }
                    None => Ok(vec![]),
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
                        Ok(value.deserialize_array(cb)?)
                    }
                    None => Ok(vec![]),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    mod serialize {
        use super::*;

        #[test]
        fn str() {
            let encoded = Serializer::default().serialize_str("value").unwrap();
            assert_eq!(encoded, json!("value"));
        }

        #[test]
        fn u64() {
            let encoded = Serializer::default().serialize_u64(123).unwrap();
            assert_eq!(encoded, json!(123));
        }

        #[test]
        fn bool() {
            let encoded_true = Serializer::default().serialize_bool(true).unwrap();
            assert_eq!(encoded_true, json!(true));

            let encoded_false = Serializer::default().serialize_bool(false).unwrap();
            assert_eq!(encoded_false, json!(false));
        }
    }

    mod serialize_struct {
        use super::*;

        #[test]
        fn version_carries_over() {
            let uut = Serializer::new(RpcVersion::PathfinderV01)
                .serialize_struct()
                .unwrap();
            assert_eq!(uut.version, RpcVersion::PathfinderV01);
        }

        #[test]
        fn optional() {
            let mut uut = Serializer::default().serialize_struct().unwrap();
            uut.serialize_optional("missing", None::<u64>).unwrap();
            uut.serialize_optional("present", Some(200u64)).unwrap();
            let encoded = uut.end().unwrap();
            let expected = json!({"present": 200u64});

            assert_eq!(encoded, expected);
        }

        #[test]
        fn iter() {
            let empty = vec![0u64; 0];
            let count = vec![0u64, 1, 2, 3];

            let mut uut = Serializer::default().serialize_struct().unwrap();
            uut.serialize_iter("empty", 0, &mut empty.iter()).unwrap();
            uut.serialize_iter("count", 0, &mut count.iter()).unwrap();
            let encoded = uut.end().unwrap();
            let expected = json!({
                "count": count,
                "empty": empty,
            });

            assert_eq!(encoded, expected);
        }

        #[test]
        fn flatten() {
            struct TypeX(u64);
            impl SerializeForVersion for TypeX {
                fn serialize(&self, serializer: Serializer) -> Result<Ok, Error> {
                    let mut serializer = serializer.serialize_struct()?;
                    serializer.serialize_field("x", &self.0);
                    serializer.end()
                }
            }

            let mut uut = Serializer::default().serialize_struct().unwrap();
            uut.serialize_field("y", &200u64).unwrap();
            uut.flatten(&TypeX(300)).unwrap();
            let encoded = uut.end().unwrap();

            let expected = json!({
                "x": 300,
                "y": 200,
            });

            assert_eq!(encoded, expected);
        }

        #[test]
        fn field() {
            let mut uut = Serializer::default().serialize_struct().unwrap();
            uut.serialize_field("field", &"value").unwrap();
            let encoded = uut.end().unwrap();
            let expected = json!({"field": "value"});
            assert_eq!(encoded, expected);
        }
    }
}
