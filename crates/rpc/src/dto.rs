use crate::DefaultVersion;

pub mod header;

pub struct Serializer {
    inner: BaseSerializer,
    pub version: DefaultVersion,
}
pub struct SerializeStruct {
    inner: <BaseSerializer as serde::Serializer>::SerializeStruct,
    pub version: DefaultVersion,
}

type BaseSerializer = serde_json::value::Serializer;
type Ok = <BaseSerializer as serde::Serializer>::Ok;
type Error = <BaseSerializer as serde::Serializer>::Error;

pub trait SerializeForVersion {
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error>;
}

// This blanket implementation should be removed once all existing DTOs have been migrated.
impl<T> SerializeForVersion for T
where
    T: serde::Serialize,
{
    fn serialize(&self, serializer: Serializer) -> Result<Ok, Error> {
        self.serialize(serializer.inner)
    }
}

impl Serializer {
    pub fn new(version: DefaultVersion) -> Self {
        Self {
            inner: BaseSerializer {},
            version,
        }
    }

    pub fn serialize(self, value: &dyn SerializeForVersion) -> Result<Ok, Error> {
        value.serialize(self)
    }

    pub fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<SerializeStruct, Error> {
        use serde::Serializer;
        Ok(SerializeStruct {
            inner: self.inner.serialize_struct(name, len)?,
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
        use serde::ser::SerializeStruct;
        let value = value.serialize(Serializer::new(self.version))?;
        self.inner.serialize_field(key, &value)
    }

    pub fn end(self) -> Result<Ok, Error> {
        use serde::ser::SerializeStruct;
        self.inner.end()
    }
}
