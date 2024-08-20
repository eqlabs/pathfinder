use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::TransactionHash;

use crate::dto;
use crate::dto::serialize;
use crate::dto::serialize::{SerializeForVersion, Serializer};

pub struct TxnHash<'a>(pub &'a TransactionHash);

pub struct Transaction<'a>(pub &'a pathfinder_common::transaction::Transaction);

struct ResourceBounds<'a>(&'a pathfinder_common::transaction::ResourceBounds);

struct ResourceBound<'a>(&'a pathfinder_common::transaction::ResourceBound);

struct DataAvailabilityMode<'a>(&'a pathfinder_common::transaction::DataAvailabilityMode);

impl SerializeForVersion for TxnHash<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        dto::Felt(&self.0 .0).serialize(serializer)
    }
}

impl SerializeForVersion for Transaction<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("transaction_hash", &TxnHash(&self.0.hash))?;
        match &self.0.variant {
            TransactionVariant::DeclareV0(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x0")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeclareV1(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeclareV2(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_field("compiled_class_hash", &dto::Felt(&tx.compiled_class_hash.0))?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x2")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeclareV3(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_field("compiled_class_hash", &dto::Felt(&tx.compiled_class_hash.0))?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
                s.serialize_field("resource_bounds", &ResourceBounds(&tx.resource_bounds))?;
                s.serialize_field("tip", &dto::NumAsHex::U64(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_iter(
                    "account_deployment_data",
                    tx.account_deployment_data.len(),
                    &mut tx.account_deployment_data.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &DataAvailabilityMode(&tx.nonce_data_availability_mode),
                )?;
                s.serialize_field(
                    "fee_data_availability_mode",
                    &DataAvailabilityMode(&tx.fee_data_availability_mode),
                )?;
            }
            TransactionVariant::DeployV0(tx) => {
                s.serialize_field("version", &"0x0")?;
                s.serialize_field("type", &"DEPLOY")?;
                s.serialize_field(
                    "contract_address_salt",
                    &dto::Felt(&tx.contract_address_salt.0),
                )?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeployV1(tx) => {
                s.serialize_field("version", &"0x1")?;
                s.serialize_field("type", &"DEPLOY")?;
                s.serialize_field(
                    "contract_address_salt",
                    &dto::Felt(&tx.contract_address_salt.0),
                )?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeployAccountV1(tx) => {
                s.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field(
                    "contract_address_salt",
                    &dto::Felt(&tx.contract_address_salt.0),
                )?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
            }
            TransactionVariant::DeployAccountV3(tx) => {
                s.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field(
                    "contract_address_salt",
                    &dto::Felt(&tx.contract_address_salt.0),
                )?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("class_hash", &dto::Felt(&tx.class_hash.0))?;
                s.serialize_field("resource_bounds", &ResourceBounds(&tx.resource_bounds))?;
                s.serialize_field("tip", &dto::NumAsHex::U64(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &DataAvailabilityMode(&tx.nonce_data_availability_mode),
                )?;
                s.serialize_field(
                    "fee_data_availability_mode",
                    &DataAvailabilityMode(&tx.fee_data_availability_mode),
                )?;
            }
            TransactionVariant::InvokeV0(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x0")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("contract_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_field(
                    "entry_point_selector",
                    &dto::Felt(&tx.entry_point_selector.0),
                )?;
                s.serialize_iter(
                    "calldata",
                    tx.calldata.len(),
                    &mut tx.calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
            }
            TransactionVariant::InvokeV1(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_iter(
                    "calldata",
                    tx.calldata.len(),
                    &mut tx.calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("max_fee", &dto::Felt(&tx.max_fee.0))?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
            }
            TransactionVariant::InvokeV3(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("sender_address", &dto::Felt(&tx.sender_address.0))?;
                s.serialize_iter(
                    "calldata",
                    tx.calldata.len(),
                    &mut tx.calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter(
                    "signature",
                    tx.signature.len(),
                    &mut tx.signature.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field("resource_bounds", &ResourceBounds(&tx.resource_bounds))?;
                s.serialize_field("tip", &dto::NumAsHex::U64(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_iter(
                    "account_deployment_data",
                    tx.account_deployment_data.len(),
                    &mut tx.account_deployment_data.iter().map(|v| dto::Felt(&v.0)),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &DataAvailabilityMode(&tx.nonce_data_availability_mode),
                )?;
                s.serialize_field(
                    "fee_data_availability_mode",
                    &DataAvailabilityMode(&tx.fee_data_availability_mode),
                )?;
            }
            TransactionVariant::L1Handler(tx) => {
                s.serialize_field("version", &"0x0")?;
                s.serialize_field("type", &"L1_HANDLER")?;
                s.serialize_field("nonce", &dto::Felt(&tx.nonce.0))?;
                s.serialize_field("contract_address", &dto::Felt(&tx.contract_address.0))?;
                s.serialize_field(
                    "entry_point_selector",
                    &dto::Felt(&tx.entry_point_selector.0),
                )?;
                s.serialize_iter(
                    "calldata",
                    tx.calldata.len(),
                    &mut tx.calldata.iter().map(|v| dto::Felt(&v.0)),
                )?;
            }
        }
        s.end()
    }
}

impl SerializeForVersion for ResourceBounds<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("l1_gas", &ResourceBound(&self.0.l1_gas))?;
        s.serialize_field("l2_gas", &ResourceBound(&self.0.l2_gas))?;
        s.end()
    }
}

impl SerializeForVersion for ResourceBound<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("max_amount", &dto::NumAsHex::U64(self.0.max_amount.0))?;
        s.serialize_field(
            "max_price_per_unit",
            &dto::NumAsHex::U128(self.0.max_price_per_unit.0),
        )?;
        s.end()
    }
}

impl SerializeForVersion for DataAvailabilityMode<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        match self.0 {
            pathfinder_common::transaction::DataAvailabilityMode::L1 => {
                serializer.serialize_str("L1")
            }
            pathfinder_common::transaction::DataAvailabilityMode::L2 => {
                serializer.serialize_str("L2")
            }
        }
    }
}
