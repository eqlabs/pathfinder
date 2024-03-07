use super::DaMode;
use super::ResourceBoundsMapping;
use super::Signature;

use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

pub(crate) struct InvokeTxn<'a> {
    pub(crate) variant: CommonInvokeVariant<'a>,
    pub(crate) query: bool,
}

pub(crate) enum CommonInvokeVariant<'a> {
    V0(&'a common::InvokeTransactionV0),
    V1(&'a common::InvokeTransactionV1),
    V3(&'a common::InvokeTransactionV3),
}

pub(crate) struct InvokeTxnV0<'a> {
    pub(crate) inner: &'a common::InvokeTransactionV0,
    pub(crate) query: bool,
}

pub(crate) struct InvokeTxnV1<'a> {
    pub(crate) inner: &'a common::InvokeTransactionV1,
    pub(crate) query: bool,
}

pub(crate) struct InvokeTxnV3<'a> {
    pub(crate) inner: &'a common::InvokeTransactionV3,
    pub(crate) query: bool,
}

impl SerializeForVersion for InvokeTxn<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let query = self.query;
        match self.variant {
            CommonInvokeVariant::V0(inner) => InvokeTxnV0 { inner, query }.serialize(serializer),
            CommonInvokeVariant::V1(inner) => InvokeTxnV1 { inner, query }.serialize(serializer),
            CommonInvokeVariant::V3(inner) => InvokeTxnV3 { inner, query }.serialize(serializer),
        }
    }
}

impl SerializeForVersion for InvokeTxnV0<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"INVOKE")?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;

        let version = if self.query {
            "0x100000000000000000000000000000000"
        } else {
            "0x0"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("contract_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_field(
            "entry_point_selector",
            &Felt(&self.inner.entry_point_selector.0),
        )?;
        serializer.serialize_iter(
            "calldata",
            self.inner.calldata.len(),
            &mut self.inner.calldata.iter().map(|x| Felt(&x.0)),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for InvokeTxnV1<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"INVOKE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_iter(
            "calldata",
            self.inner.calldata.len(),
            &mut self.inner.calldata.iter().map(|x| Felt(&x.0)),
        )?;
        serializer.serialize_field("max_fee", &Felt(&self.inner.max_fee.0))?;

        let version = if self.query {
            "0x100000000000000000000000000000001"
        } else {
            "0x1"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for InvokeTxnV3<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("type", &"INVOKE")?;
        serializer.serialize_field("sender_address", &Address(&self.inner.sender_address))?;
        serializer.serialize_iter(
            "calldata",
            self.inner.calldata.len(),
            &mut self.inner.calldata.iter().map(|x| Felt(&x.0)),
        )?;

        let version = if self.query {
            "0x100000000000000000000000000000003"
        } else {
            "0x3"
        };
        serializer.serialize_field("version", &version)?;
        serializer.serialize_field("signature", &Signature(&self.inner.signature))?;
        serializer.serialize_field("nonce", &Felt(&self.inner.nonce.0))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
    use rstest::rstest;
    use serde_json::json;

    use pretty_assertions_sorted::assert_eq;

    #[rstest]
    #[case::without_query(false, "0x0")]
    #[case::with_query(true, "0x100000000000000000000000000000000")]
    fn invoke_txn_v0(#[case] query: bool, #[case] expected_version: &str) {
        let s = Serializer::default();
        let tx = common::InvokeTransactionV0 {
            calldata: vec![
                call_param!("0x11"),
                call_param!("0x33"),
                call_param!("0x22"),
            ],
            sender_address: contract_address!("0x999"),
            entry_point_selector: entry_point!("0x44"),
            entry_point_type: None,
            max_fee: fee!("0x123"),
            signature: vec![
                transaction_signature_elem!("0x1"),
                transaction_signature_elem!("0x2"),
                transaction_signature_elem!("0x3"),
                transaction_signature_elem!("0x4"),
            ],
        };

        let expected = json!({
            "type": "INVOKE",
            "max_fee": s.serialize(&Felt(&tx.max_fee.0)).unwrap(),
            "version": s.serialize_str(expected_version).unwrap(),
            "signature": s.serialize(&Signature(&tx.signature)).unwrap(),
            "contract_address": s.serialize(&Address(&tx.sender_address)).unwrap(),
            "entry_point_selector": s.serialize(&Felt(&tx.entry_point_selector.0)).unwrap(),
            "calldata": s.serialize_iter(
                tx.calldata.len(),
                &mut tx.calldata.iter().map(|x| Felt(&x.0))
            ).unwrap(),
        });

        let encoded = InvokeTxnV0 { inner: &tx, query }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::without_query(false, "0x1")]
    #[case::with_query(true, "0x100000000000000000000000000000001")]
    fn invoke_txn_v1(#[case] query: bool, #[case] expected_version: &str) {
        let s = Serializer::default();
        let tx = common::InvokeTransactionV1 {
            calldata: vec![
                call_param!("0x11"),
                call_param!("0x33"),
                call_param!("0x22"),
            ],
            sender_address: contract_address!("0x999"),
            max_fee: fee!("0x123"),
            signature: vec![
                transaction_signature_elem!("0x1"),
                transaction_signature_elem!("0x2"),
                transaction_signature_elem!("0x3"),
                transaction_signature_elem!("0x4"),
            ],
            nonce: transaction_nonce!("0x88129"),
        };

        let expected = json!({
            "type": "INVOKE",
            "max_fee": s.serialize(&Felt(&tx.max_fee.0)).unwrap(),
            "version": s.serialize_str(expected_version).unwrap(),
            "signature": s.serialize(&Signature(&tx.signature)).unwrap(),
            "sender_address": s.serialize(&Address(&tx.sender_address)).unwrap(),
            "calldata": tx.calldata.iter().map(|x| s.serialize(&Felt(&x.0)).unwrap()).collect::<Vec<_>>(),
            "nonce": s.serialize(&Felt(&tx.nonce.0)).unwrap(),
        });

        let encoded = InvokeTxnV1 { inner: &tx, query }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::without_query(false, "0x3")]
    #[case::with_query(true, "0x100000000000000000000000000000003")]
    fn invoke_txn_v3(#[case] query: bool, #[case] expected_version: &str) {
        let s = Serializer::default();
        let tx = common::InvokeTransactionV3 {
            calldata: vec![
                call_param!("0x11"),
                call_param!("0x33"),
                call_param!("0x22"),
            ],
            sender_address: contract_address!("0x999"),
            signature: vec![
                transaction_signature_elem!("0x1"),
                transaction_signature_elem!("0x2"),
                transaction_signature_elem!("0x3"),
                transaction_signature_elem!("0x4"),
            ],
            nonce: transaction_nonce!("0x88129"),
            resource_bounds: common::ResourceBounds {
                l1_gas: common::ResourceBound {
                    max_amount: pathfinder_common::ResourceAmount(123786),
                    max_price_per_unit: pathfinder_common::ResourcePricePerUnit(9807123),
                },
                l2_gas: common::ResourceBound {
                    max_amount: pathfinder_common::ResourceAmount(123786),
                    max_price_per_unit: pathfinder_common::ResourcePricePerUnit(9807123),
                },
            },
            tip: pathfinder_common::Tip(100),
            paymaster_data: vec![
                paymaster_data_elem!("0x12333"),
                paymaster_data_elem!("0x123338"),
            ],
            account_deployment_data: vec![
                account_deployment_data_elem!("0x24"),
                account_deployment_data_elem!("0x192"),
                account_deployment_data_elem!("0x908123"),
            ],
            fee_data_availability_mode: Default::default(),
            nonce_data_availability_mode: Default::default(),
        };

        let expected = json!({
            "type": "INVOKE",
            "version": s.serialize_str(expected_version).unwrap(),
            "signature": s.serialize(&Signature(&tx.signature)).unwrap(),
            "sender_address": s.serialize(&Address(&tx.sender_address)).unwrap(),
            "calldata": tx.calldata.iter().map(|x| s.serialize(&Felt(&x.0)).unwrap()).collect::<Vec<_>>(),
            "nonce": s.serialize(&Felt(&tx.nonce.0)).unwrap(),
            "resource_bounds": s.serialize(&ResourceBoundsMapping(&tx.resource_bounds)).unwrap(),
            "tip": s.serialize(&U64(tx.tip.0)).unwrap(),
            "paymaster_data": s.serialize_iter(
                tx.paymaster_data.len(),
                &mut tx.paymaster_data.iter().map(|x| Felt(&x.0))
            ).unwrap(),
            "account_deployment_data": s.serialize_iter(
                tx.account_deployment_data.len(),
                &mut tx.account_deployment_data.iter().map(|x| Felt(&x.0))
            ).unwrap(),
            "nonce_data_availability_mode": s.serialize(&DaMode(tx.nonce_data_availability_mode)).unwrap(),
            "fee_data_availability_mode": s.serialize(&DaMode(tx.fee_data_availability_mode)).unwrap(),
        });

        let encoded = InvokeTxnV3 { inner: &tx, query }.serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }
}
