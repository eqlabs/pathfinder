use serde::ser::SerializeStruct;
use serde_json::{Error, Value};

use crate::DefaultVersion;

pub mod header;

// TODO: Maybe str is much better here actually?
type Serializer = serde_json::value::Serializer;
type StructSerializer = <Serializer as serde::Serializer>::SerializeStruct;

pub trait SerializeForVersion {
    fn serialize(&self, version: DefaultVersion) -> Result<Value, Error>;

    fn serialize_struct_field(
        &self,
        version: DefaultVersion,
        key: &'static str,
        serializer: &mut StructSerializer,
    ) -> Result<(), Error> {
        serializer.serialize_field(key, &self.serialize(version)?)
    }
}

// This blanket implementation should be removed once all existing DTOs have been migrated.
impl<T> SerializeForVersion for T
where
    T: serde::Serialize,
{
    fn serialize(&self, _version: DefaultVersion) -> Result<Value, Error> {
        self.serialize(Serializer {})
    }
}
