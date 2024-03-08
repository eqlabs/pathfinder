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

// This blanket implementation should be removed once all existing DTOs have been migrated.
impl<T> SerializeForVersion for T
where
    T: serde::Serialize,
{
    fn serialize(&self, _serializer: Serializer) -> Result<Ok, Error> {
        self.serialize(BaseSerializer {})
    }
}

impl Serializer {
    pub fn new(version: RpcVersion) -> Self {
        Self { version }
    }

    pub fn serialize(self, value: &dyn SerializeForVersion) -> Result<Ok, Error> {
        value.serialize(self)
    }

    pub fn serialize_str(self, value: &str) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_str(value)
    }

    pub fn serialize_u64(self, value: u64) -> Result<Ok, Error> {
        use serde::Serializer;
        BaseSerializer {}.serialize_u64(value)
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

    /// Skips serialization if its [`None`].
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
