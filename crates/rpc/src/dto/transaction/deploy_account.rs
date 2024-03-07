use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

use super::Signature;

struct DeployAccountV1<'a> {
    inner: &'a common::DeployAccountTransactionV0V1,
    query: bool,
}

impl SerializeForVersion for DeployAccountV1<'_> {
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
