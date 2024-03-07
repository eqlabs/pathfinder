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

pub(crate) struct DeclareTxnV1<'a> {
    pub(crate) inner: &'a common::DeclareTransactionV0V1,
    pub(crate) query: bool,
}

pub(crate) struct DeclareTxnV2<'a> {
    pub(crate) inner: &'a common::DeclareTransactionV2,
    pub(crate) query: bool,
}

pub(crate) struct DeclareTxnV3<'a> {
    pub(crate) inner: &'a common::DeclareTransactionV3,
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

impl SerializeForVersion for DeclareTxnV1<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DECLARE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;

        let version = if self.query {
            "0x100000000000000000000000000000001"
        } else {
            "0x1"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
        serializer.serialize_field("class_hash", &Felt(&self.inner.class_hash.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for DeclareTxnV2<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DECLARE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_field(
            "compiled_class_hash",
            &Felt(&self.inner.compiled_class_hash.0),
        )?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;

        let version = if self.query {
            "0x100000000000000000000000000000002"
        } else {
            "0x2"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
        serializer.serialize_field("class_hash", &Felt(&self.inner.class_hash.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for DeclareTxnV3<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DECLARE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_field(
            "compiled_class_hash",
            &Felt(&self.inner.compiled_class_hash.0),
        )?;

        let version = if self.query {
            "0x100000000000000000000000000000003"
        } else {
            "0x3"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
        serializer.serialize_field("class_hash", &Felt(&self.inner.class_hash.0))?;
        serializer.serialize_field(
            "resource_bounds",
            &ResourceBoundsMapping(&self.inner.resource_bounds),
        )?;
        serializer.serialize_field("tip", &U64(self.inner.tip.0))?;
        serializer.serialize_iter(
            "paymaster_data",
            self.inner.paymaster_data.len(),
            &mut self.inner.paymaster_data.iter().map(|x| Felt(&x.0)),
        )?;
        serializer.serialize_iter(
            "account_deployment_data",
            self.inner.account_deployment_data.len(),
            &mut self
                .inner
                .account_deployment_data
                .iter()
                .map(|x| Felt(&x.0)),
        )?;
        serializer.serialize_field(
            "nonce_data_availability_mode",
            &DaMode(self.inner.nonce_data_availability_mode),
        )?;
        serializer.serialize_field(
            "fee_data_availability_mode",
            &DaMode(self.inner.fee_data_availability_mode),
        )?;

        serializer.end()
    }
}
