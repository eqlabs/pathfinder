use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

use super::DaMode;
use super::ResourceBoundsMapping;
use super::Signature;

struct DeployAccountTxn<'a> {
    variant: DeployAccountVariant<'a>,
    query: bool,
}

enum DeployAccountVariant<'a> {
    V1(&'a common::DeployAccountTransactionV0V1),
    V3(&'a common::DeployAccountTransactionV3),
}

struct DeployAccountTxnV1<'a> {
    inner: &'a common::DeployAccountTransactionV0V1,
    query: bool,
}

struct DeployAccountTxnV3<'a> {
    inner: &'a common::DeployAccountTransactionV3,
    query: bool,
}

impl SerializeForVersion for DeployAccountTxn<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let query = self.query;
        match self.variant {
            DeployAccountVariant::V1(inner) => {
                DeployAccountTxnV1 { inner, query }.serialize(serializer)
            }
            DeployAccountVariant::V3(inner) => {
                DeployAccountTxnV3 { inner, query }.serialize(serializer)
            }
        }
    }
}

impl SerializeForVersion for DeployAccountTxnV1<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;
        let version = if self.query {
            "0x100000000000000000000000000000001"
        } else {
            "0x1"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
        serializer.serialize_field(
            "contract_address_salt",
            &Felt(&self.inner.contract_address_salt.0),
        )?;
        serializer.serialize_iter(
            "constructor_calldata",
            self.inner.constructor_calldata.len(),
            &mut self.inner.constructor_calldata.iter().map(|x| Felt(&x.0)),
        )?;
        serializer.serialize_field("class_hash", &Felt(&self.inner.class_hash.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for DeployAccountTxnV3<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"DEPLOY_ACCOUNT")?;
        let version = if self.query {
            "0x100000000000000000000000000000003"
        } else {
            "0x3"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
        serializer.serialize_field(
            "contract_address_salt",
            &Felt(&self.inner.contract_address_salt.0),
        )?;
        serializer.serialize_iter(
            "constructor_calldata",
            self.inner.constructor_calldata.len(),
            &mut self.inner.constructor_calldata.iter().map(|x| Felt(&x.0)),
        )?;
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
