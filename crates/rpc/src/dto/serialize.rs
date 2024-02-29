use crate::RpcVersion;

#[derive(Copy, Clone, Default)]
pub struct Serializer {
    pub version: RpcVersion,
}

pub struct SerializeStruct {
    pub version: RpcVersion,
    fields: serde_json::Map<String, Ok>,
}

pub struct SerializeSeq {
    inner: <BaseSerializer as serde::Serializer>::SerializeSeq,
    pub version: RpcVersion,
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

    pub fn serialize_seq(self, len: Option<usize>) -> Result<SerializeSeq, Error> {
        use serde::Serializer;
        Ok(SerializeSeq {
            inner: BaseSerializer {}.serialize_seq(len)?,
            version: self.version,
        })
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
        let mut seq = Serializer::new(self.version).serialize_seq(Some(len))?;

        for value in values {
            seq.serialize_element(&value)?;
        }

        let field_value = seq.end()?;
        self.serialize_field(key, &field_value)
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

impl SerializeSeq {
    pub fn serialize_element(&mut self, value: &dyn SerializeForVersion) -> Result<(), Error> {
        use serde::ser::SerializeSeq;
        let value = value.serialize(Serializer::new(self.version))?;
        self.inner.serialize_element(&value)
    }

    pub fn end(self) -> Result<Ok, Error> {
        use serde::ser::SerializeSeq;
        self.inner.end()
    }
}
