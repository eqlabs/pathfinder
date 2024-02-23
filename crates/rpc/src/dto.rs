pub trait SerializeForVersion {
    fn serialize(&self, version: crate::DefaultVersion) -> serde_json::Result<serde_json::Value>;
}

// This blanket implementation should be removed once all existing DTOs have been migrated.
impl<T> SerializeForVersion for T
where
    T: serde::Serialize,
{
    fn serialize(&self, _version: crate::DefaultVersion) -> serde_json::Result<serde_json::Value> {
        self.serialize(serde_json::value::Serializer)
    }
}
