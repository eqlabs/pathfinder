use pathfinder_common::transaction::{
    DataAvailabilityMode, DeclareTransactionV0V1, DeclareTransactionV2, DeclareTransactionV3,
    DeployAccountTransactionV1, DeployAccountTransactionV3, DeployTransactionV0,
    DeployTransactionV1, InvokeTransactionV0, InvokeTransactionV1, InvokeTransactionV3,
    L1HandlerTransaction, ResourceBound, ResourceBounds,
};
use pathfinder_common::{
    ResourceAmount, ResourcePricePerUnit, Tip, TransactionHash, TransactionVersion,
};
use serde::ser::SerializeStruct;
use serde::Serialize;

/// Equivalent to the TXN type from the specification.
#[derive(PartialEq, Debug, Clone, Eq)]
pub struct Transaction(pub pathfinder_common::transaction::TransactionVariant);

/// A transaction and its hash, a common structure used in the spec.
#[derive(serde::Serialize, PartialEq, Debug, Clone, Eq)]
pub struct TransactionWithHash {
    pub transaction_hash: TransactionHash,
    #[serde(flatten)]
    pub txn: Transaction,
}

impl From<pathfinder_common::transaction::Transaction> for TransactionWithHash {
    fn from(value: pathfinder_common::transaction::Transaction) -> Self {
        Self {
            transaction_hash: value.hash,
            txn: Transaction(value.variant),
        }
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_common::transaction::TransactionVariant;
        match &self.0 {
            TransactionVariant::DeclareV0(x) => DeclareV0Helper(x).serialize(serializer),
            TransactionVariant::DeclareV1(x) => DeclareV1Helper(x).serialize(serializer),
            TransactionVariant::DeclareV2(x) => DeclareV2Helper(x).serialize(serializer),
            TransactionVariant::DeclareV3(x) => DeclareV3Helper(x).serialize(serializer),
            TransactionVariant::DeployV0(x) => DeployV0Helper(x).serialize(serializer),
            TransactionVariant::DeployV1(x) => DeployV1Helper(x).serialize(serializer),
            TransactionVariant::DeployAccountV1(x) => {
                DeployAccountV1Helper(x).serialize(serializer)
            }
            TransactionVariant::DeployAccountV3(x) => {
                DeployAccountV3Helper(x).serialize(serializer)
            }
            TransactionVariant::InvokeV0(x) => InvokeV0Helper(x).serialize(serializer),
            TransactionVariant::InvokeV1(x) => InvokeV1Helper(x).serialize(serializer),
            TransactionVariant::InvokeV3(x) => InvokeV3Helper(x).serialize(serializer),
            TransactionVariant::L1Handler(x) => L1HandlerHelper(x).serialize(serializer),
        }
    }
}

struct DeclareV0Helper<'a>(&'a DeclareTransactionV0V1);
struct DeclareV1Helper<'a>(&'a DeclareTransactionV0V1);
struct DeclareV2Helper<'a>(&'a DeclareTransactionV2);
struct DeclareV3Helper<'a>(&'a DeclareTransactionV3);
struct DeployV0Helper<'a>(&'a DeployTransactionV0);
struct DeployV1Helper<'a>(&'a DeployTransactionV1);

struct DeployAccountV1Helper<'a>(&'a DeployAccountTransactionV1);
struct DeployAccountV3Helper<'a>(&'a DeployAccountTransactionV3);
struct InvokeV0Helper<'a>(&'a InvokeTransactionV0);
struct InvokeV1Helper<'a>(&'a InvokeTransactionV1);
struct InvokeV3Helper<'a>(&'a InvokeTransactionV3);
struct L1HandlerHelper<'a>(&'a L1HandlerTransaction);
struct TransactionVersionHelper<'a>(&'a TransactionVersion);
struct ResourceBoundsHelper<'a>(&'a ResourceBounds);
struct ResourceBoundHelper<'a>(&'a ResourceBound);
struct ResourceAmountHelper<'a>(&'a ResourceAmount);
struct ResourcePricePerUnitHelper<'a>(&'a ResourcePricePerUnit);
struct DataAvailabilityModeHelper<'a>(&'a DataAvailabilityMode);
struct TipHelper<'a>(&'a Tip);

impl Serialize for DeclareV0Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV0", 6)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x0")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeclareV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV1", 7)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x1")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeclareV2Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV2", 8)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("compiled_class_hash", &self.0.compiled_class_hash)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x2")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeclareV3Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeclareV3", 13)?;
        s.serialize_field("type", "DECLARE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("compiled_class_hash", &self.0.compiled_class_hash)?;
        s.serialize_field("version", "0x3")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.serialize_field(
            "resource_bounds",
            &ResourceBoundsHelper(&self.0.resource_bounds),
        )?;
        s.serialize_field("tip", &TipHelper(&self.0.tip))?;
        s.serialize_field("paymaster_data", &self.0.paymaster_data)?;
        s.serialize_field("account_deployment_data", &self.0.account_deployment_data)?;
        s.serialize_field(
            "nonce_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.nonce_data_availability_mode),
        )?;
        s.serialize_field(
            "fee_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.fee_data_availability_mode),
        )?;
        s.end()
    }
}

impl Serialize for DeployV0Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("Deploy", 5)?;
        s.serialize_field(
            "version",
            &TransactionVersionHelper(&TransactionVersion::ZERO),
        )?;
        s.serialize_field("type", "DEPLOY")?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeployV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("Deploy", 5)?;
        s.serialize_field(
            "version",
            &TransactionVersionHelper(&TransactionVersion::ONE),
        )?;
        s.serialize_field("type", "DEPLOY")?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeployAccountV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeployAccount", 8)?;
        s.serialize_field("type", "DEPLOY_ACCOUNT")?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x1")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.end()
    }
}

impl Serialize for DeployAccountV3Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("DeployAccount", 12)?;
        s.serialize_field("type", "DEPLOY_ACCOUNT")?;
        s.serialize_field("version", "0x3")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("contract_address_salt", &self.0.contract_address_salt)?;
        s.serialize_field("constructor_calldata", &self.0.constructor_calldata)?;
        s.serialize_field("class_hash", &self.0.class_hash)?;
        s.serialize_field(
            "resource_bounds",
            &ResourceBoundsHelper(&self.0.resource_bounds),
        )?;
        s.serialize_field("tip", &TipHelper(&self.0.tip))?;
        s.serialize_field("paymaster_data", &self.0.paymaster_data)?;
        s.serialize_field(
            "nonce_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.nonce_data_availability_mode),
        )?;
        s.serialize_field(
            "fee_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.fee_data_availability_mode),
        )?;
        s.end()
    }
}

impl Serialize for InvokeV0Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("InvokeV0", 7)?;
        s.serialize_field("type", "INVOKE")?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x0")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("contract_address", &self.0.sender_address)?;
        s.serialize_field("entry_point_selector", &self.0.entry_point_selector)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.end()
    }
}

impl Serialize for InvokeV1Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("InvokeV1", 7)?;
        s.serialize_field("type", "INVOKE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.serialize_field("max_fee", &self.0.max_fee)?;
        s.serialize_field("version", "0x1")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.end()
    }
}

impl Serialize for InvokeV3Helper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("InvokeV3", 12)?;
        s.serialize_field("type", "INVOKE")?;
        s.serialize_field("sender_address", &self.0.sender_address)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.serialize_field("version", "0x3")?;
        s.serialize_field("signature", &self.0.signature)?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field(
            "resource_bounds",
            &ResourceBoundsHelper(&self.0.resource_bounds),
        )?;
        s.serialize_field("tip", &TipHelper(&self.0.tip))?;
        s.serialize_field("paymaster_data", &self.0.paymaster_data)?;
        s.serialize_field("account_deployment_data", &self.0.account_deployment_data)?;
        s.serialize_field(
            "nonce_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.nonce_data_availability_mode),
        )?;
        s.serialize_field(
            "fee_data_availability_mode",
            &DataAvailabilityModeHelper(&self.0.fee_data_availability_mode),
        )?;
        s.end()
    }
}

impl Serialize for L1HandlerHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("L1Handler", 6)?;
        s.serialize_field(
            "version",
            &TransactionVersionHelper(&TransactionVersion::ZERO),
        )?;
        s.serialize_field("type", "L1_HANDLER")?;
        s.serialize_field("nonce", &self.0.nonce)?;
        s.serialize_field("contract_address", &self.0.contract_address)?;
        s.serialize_field("entry_point_selector", &self.0.entry_point_selector)?;
        s.serialize_field("calldata", &self.0.calldata)?;
        s.end()
    }
}

impl Serialize for TransactionVersionHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_serde::bytes_to_hex_str;
        serializer.serialize_str(&bytes_to_hex_str(self.0 .0.as_be_bytes()))
    }
}

impl Serialize for ResourceBoundsHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("ResourceBounds", 2)?;
        s.serialize_field("l1_gas", &ResourceBoundHelper(&self.0.l1_gas))?;
        s.serialize_field("l2_gas", &ResourceBoundHelper(&self.0.l2_gas))?;
        s.end()
    }
}

impl Serialize for ResourceBoundHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("ResourceBound", 2)?;
        s.serialize_field("max_amount", &ResourceAmountHelper(&self.0.max_amount))?;
        s.serialize_field(
            "max_price_per_unit",
            &ResourcePricePerUnitHelper(&self.0.max_price_per_unit),
        )?;
        s.end()
    }
}

impl Serialize for ResourceAmountHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_serde::bytes_to_hex_str;
        serializer.serialize_str(&bytes_to_hex_str(&self.0 .0.to_be_bytes()))
    }
}

impl Serialize for ResourcePricePerUnitHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_serde::bytes_to_hex_str;
        serializer.serialize_str(&bytes_to_hex_str(&self.0 .0.to_be_bytes()))
    }
}

impl Serialize for DataAvailabilityModeHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            DataAvailabilityMode::L1 => serializer.serialize_str("L1"),
            DataAvailabilityMode::L2 => serializer.serialize_str("L2"),
        }
    }
}

impl Serialize for TipHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use pathfinder_serde::bytes_to_hex_str;
        serializer.serialize_str(&bytes_to_hex_str(&self.0 .0.to_be_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    mod serialization {
        use pathfinder_common::transaction::*;
        use pathfinder_common::{ResourceAmount, ResourcePricePerUnit, Tip};
        use pretty_assertions_sorted::assert_eq;
        use serde_json::json;

        use super::*;

        #[test]
        fn declare_v0() {
            let original = DeclareTransactionV0V1 {
                class_hash: class_hash!("0x123"),
                max_fee: fee!("0x1111"),
                nonce: transaction_nonce!("0xaabbcc"),
                sender_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
            };

            let expected = json!({
                "type": "DECLARE",
                "version": "0x0",
                "sender_address": "0xabc",
                "max_fee": "0x1111",
                "signature": ["0xa1b1", "0x1a1b"],
                "class_hash": "0x123",
            });
            let uut = Transaction(TransactionVariant::DeclareV0(original));
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn declare_v1() {
            let original = DeclareTransactionV0V1 {
                class_hash: class_hash!("0x123"),
                max_fee: fee!("0x1111"),
                nonce: transaction_nonce!("0xaabbcc"),
                sender_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
            };

            let expected = json!({
                "type": "DECLARE",
                "version": "0x1",
                "sender_address": "0xabc",
                "max_fee": "0x1111",
                "signature": ["0xa1b1", "0x1a1b"],
                "class_hash": "0x123",
                "nonce": "0xaabbcc",
            });
            let uut = Transaction(TransactionVariant::DeclareV1(original));
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn declare_v2() {
            let original: TransactionVariant = DeclareTransactionV2 {
                class_hash: class_hash!("0x123"),
                max_fee: fee!("0x1111"),
                nonce: transaction_nonce!("0xaabbcc"),
                sender_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                compiled_class_hash: casm_hash!("0xbbbbb"),
            }
            .into();

            let expected = json!({
                "type": "DECLARE",
                "version": "0x2",
                "sender_address": "0xabc",
                "max_fee": "0x1111",
                "signature": ["0xa1b1", "0x1a1b"],
                "class_hash": "0x123",
                "nonce": "0xaabbcc",
                "compiled_class_hash": "0xbbbbb",
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn declare_v3() {
            let original: TransactionVariant = DeclareTransactionV3 {
                class_hash: class_hash!("0x123"),
                nonce: transaction_nonce!("0xaabbcc"),
                sender_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                compiled_class_hash: casm_hash!("0xbbbbb"),
                nonce_data_availability_mode: DataAvailabilityMode::L1,
                fee_data_availability_mode: DataAvailabilityMode::L1,
                resource_bounds: ResourceBounds {
                    l1_gas: ResourceBound {
                        max_amount: ResourceAmount(256),
                        max_price_per_unit: ResourcePricePerUnit(10),
                    },
                    l2_gas: Default::default(),
                    l1_data_gas: Default::default(),
                },
                tip: Tip(5),
                paymaster_data: vec![],
                account_deployment_data: vec![],
            }
            .into();

            let expected = json!({
                "type": "DECLARE",
                "version": "0x3",
                "sender_address": "0xabc",
                "signature": ["0xa1b1", "0x1a1b"],
                "class_hash": "0x123",
                "nonce": "0xaabbcc",
                "compiled_class_hash": "0xbbbbb",
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1",
                "resource_bounds": {
                    "l1_gas": {
                        "max_amount": "0x100",
                        "max_price_per_unit": "0xa",
                    },
                    "l2_gas": {
                        "max_amount": "0x0",
                        "max_price_per_unit": "0x0",
                    }
                },
                "tip": "0x5",
                "paymaster_data": [],
                "account_deployment_data": [],
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn deploy() {
            let original: TransactionVariant = DeployTransactionV0 {
                contract_address: contract_address!("0xabc"),
                contract_address_salt: contract_address_salt!("0xeeee"),
                class_hash: class_hash!("0x123"),
                constructor_calldata: vec![
                    constructor_param!("0xbbb0"),
                    constructor_param!("0xbbb1"),
                ],
            }
            .into();

            let expected = json!({
                "type": "DEPLOY",
                "contract_address_salt": "0xeeee",
                "class_hash": "0x123",
                "constructor_calldata": ["0xbbb0","0xbbb1"],
                "version": "0x0",
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn deploy_account_v1() {
            let original: TransactionVariant = DeployAccountTransactionV1 {
                contract_address: contract_address!("0xabc"),
                max_fee: fee!("0x1111"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                nonce: transaction_nonce!("0xaabbcc"),
                contract_address_salt: contract_address_salt!("0xeeee"),
                constructor_calldata: vec![call_param!("0xbbb0"), call_param!("0xbbb1")],
                class_hash: class_hash!("0x123"),
            }
            .into();

            let expected = json!({
                "type": "DEPLOY_ACCOUNT",
                "max_fee": "0x1111",
                "version": "0x1",
                "signature": ["0xa1b1", "0x1a1b"],
                "nonce": "0xaabbcc",
                "contract_address_salt": "0xeeee",
                "constructor_calldata": ["0xbbb0","0xbbb1"],
                "class_hash": "0x123",
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn deploy_account_v3() {
            let original: TransactionVariant = DeployAccountTransactionV3 {
                contract_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                nonce: transaction_nonce!("0xaabbcc"),
                contract_address_salt: contract_address_salt!("0xeeee"),
                constructor_calldata: vec![call_param!("0xbbb0"), call_param!("0xbbb1")],
                class_hash: class_hash!("0x123"),
                nonce_data_availability_mode: DataAvailabilityMode::L1,
                fee_data_availability_mode: DataAvailabilityMode::L1,
                resource_bounds: ResourceBounds {
                    l1_gas: ResourceBound {
                        max_amount: ResourceAmount(256),
                        max_price_per_unit: ResourcePricePerUnit(10),
                    },
                    l2_gas: Default::default(),
                    l1_data_gas: Default::default(),
                },
                tip: Tip(5),
                paymaster_data: vec![],
            }
            .into();

            let expected = json!({
                "type": "DEPLOY_ACCOUNT",
                "version": "0x3",
                "signature": ["0xa1b1", "0x1a1b"],
                "nonce": "0xaabbcc",
                "contract_address_salt": "0xeeee",
                "constructor_calldata": ["0xbbb0","0xbbb1"],
                "class_hash": "0x123",
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1",
                "resource_bounds": {
                    "l1_gas": {
                        "max_amount": "0x100",
                        "max_price_per_unit": "0xa",
                    },
                    "l2_gas": {
                        "max_amount": "0x0",
                        "max_price_per_unit": "0x0",
                    }
                },
                "tip": "0x5",
                "paymaster_data": [],
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn invoke_v0() {
            let original: TransactionVariant = InvokeTransactionV0 {
                calldata: vec![call_param!("0xfff1"), call_param!("0xfff0")],
                sender_address: contract_address!("0xabc"),
                entry_point_selector: entry_point!("0xdead"),
                entry_point_type: Some(EntryPointType::External),
                max_fee: fee!("0x1111"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
            }
            .into();

            let expected = json!({
                "type": "INVOKE",
                "version": "0x0",
                "calldata": ["0xfff1","0xfff0"],
                "contract_address": "0xabc",
                "entry_point_selector": "0xdead",
                "max_fee": "0x1111",
                "signature": ["0xa1b1", "0x1a1b"],
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn invoke_v1() {
            let original: TransactionVariant = InvokeTransactionV1 {
                calldata: vec![call_param!("0xfff1"), call_param!("0xfff0")],
                sender_address: contract_address!("0xabc"),
                max_fee: fee!("0x1111"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                nonce: transaction_nonce!("0xaabbcc"),
            }
            .into();

            let expected = json!({
                "type": "INVOKE",
                "version": "0x1",
                "calldata": ["0xfff1","0xfff0"],
                "sender_address": "0xabc",
                "max_fee": "0x1111",
                "signature": ["0xa1b1", "0x1a1b"],
                "nonce": "0xaabbcc",
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn invoke_v3() {
            let original: TransactionVariant = InvokeTransactionV3 {
                calldata: vec![call_param!("0xfff1"), call_param!("0xfff0")],
                sender_address: contract_address!("0xabc"),
                signature: vec![
                    transaction_signature_elem!("0xa1b1"),
                    transaction_signature_elem!("0x1a1b"),
                ],
                nonce: transaction_nonce!("0xaabbcc"),
                nonce_data_availability_mode: DataAvailabilityMode::L1,
                fee_data_availability_mode: DataAvailabilityMode::L1,
                resource_bounds: ResourceBounds {
                    l1_gas: ResourceBound {
                        max_amount: ResourceAmount(256),
                        max_price_per_unit: ResourcePricePerUnit(10),
                    },
                    l2_gas: Default::default(),
                    l1_data_gas: Default::default(),
                },
                tip: Tip(5),
                paymaster_data: vec![],
                account_deployment_data: vec![],
            }
            .into();

            let expected = json!({
                "type": "INVOKE",
                "version": "0x3",
                "calldata": ["0xfff1","0xfff0"],
                "sender_address": "0xabc",
                "signature": ["0xa1b1", "0x1a1b"],
                "nonce": "0xaabbcc",
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1",
                "resource_bounds": {
                    "l1_gas": {
                        "max_amount": "0x100",
                        "max_price_per_unit": "0xa",
                    },
                    "l2_gas": {
                        "max_amount": "0x0",
                        "max_price_per_unit": "0x0",
                    }
                },
                "tip": "0x5",
                "paymaster_data": [],
                "account_deployment_data": [],
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }

        #[test]
        fn l1_handler() {
            let original: TransactionVariant = L1HandlerTransaction {
                contract_address: contract_address!("0xabc"),
                entry_point_selector: entry_point!("0xdead"),
                nonce: transaction_nonce!("0xaabbcc"),
                calldata: vec![call_param!("0xfff1"), call_param!("0xfff0")],
            }
            .into();

            let expected = json!({
                "type": "L1_HANDLER",
                "contract_address": "0xabc",
                "entry_point_selector": "0xdead",
                "nonce": "0xaabbcc",
                "calldata": ["0xfff1","0xfff0"],
                "version": "0x0",
            });
            let uut = Transaction(original);
            let result = serde_json::to_value(uut).unwrap();

            assert_eq!(result, expected);
        }
    }
}
