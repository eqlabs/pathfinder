use super::DaMode;
use super::ResourceBoundsMapping;
use super::Signature;

use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

pub(crate) struct DeclareTxnV0<'a> {
    pub(crate) inner: &'a common::DeclareTransactionV0V1,
    pub(crate) query: bool,
}

impl SerializeForVersion for DeclareTxnV0<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DECLARE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;

        let version = if self.query {
            "0x100000000000000000000000000000000"
        } else {
            "0x0"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("class_hash", &Felt(&self.inner.class_hash.0))?;

        serializer.end()
    }
}
