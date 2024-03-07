use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

struct InvokeTxnV0<'a> {
    inner: &'a common::InvokeTransactionV0,
    query: bool,
}

struct InvokeTxnV1<'a> {
    inner: &'a common::InvokeTransactionV1,
    query: bool,
}

struct Signature<'a>(&'a [pathfinder_common::TransactionSignatureElem]);

struct ResourceBoundsMapping<'a>(&'a common::ResourceBounds);

struct ResourceBounds<'a>(&'a common::ResourceBound);

struct DaMode(common::DataAvailabilityMode);

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

impl SerializeForVersion for Signature<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_iter(self.0.len(), &mut self.0.iter().map(|x| Felt(&x.0)))
    }
}

impl SerializeForVersion for ResourceBoundsMapping<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("l1_gas", &ResourceBounds(&self.0.l1_gas))?;
        serializer.serialize_field("l2_gas", &ResourceBounds(&self.0.l2_gas))?;

        serializer.end()
    }
}

impl SerializeForVersion for ResourceBounds<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("max_amount", &U64(self.0.max_amount.0))?;
        serializer.serialize_field("max_price_per_unit", &U128(self.0.max_price_per_unit.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for DaMode {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let da_mode = match self.0 {
            common::DataAvailabilityMode::L1 => "L1",
            common::DataAvailabilityMode::L2 => "L2",
        };
        serializer.serialize_str(da_mode)
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

    #[test]
    fn signature() {
        let s = Serializer::default();
        let signature = vec![
            transaction_signature_elem!("0x1"),
            transaction_signature_elem!("0x2"),
            transaction_signature_elem!("0x3"),
            transaction_signature_elem!("0x4"),
        ];

        let expected = signature
            .iter()
            .map(|x| s.serialize(&Felt(&x.0)).unwrap())
            .collect::<Vec<_>>();
        let expected = json!(expected);

        let encoded = Signature(&signature).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn resource_bounds_mapping() {
        let s = Serializer::default();

        let bounds = common::ResourceBounds {
            l1_gas: common::ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(30),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(200),
            },
            l2_gas: common::ResourceBound {
                max_amount: pathfinder_common::ResourceAmount(123),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(1293),
            },
        };

        let expected = json!({
            "l1_gas": s.serialize(&ResourceBounds(&bounds.l1_gas)).unwrap(),
            "l2_gas": s.serialize(&ResourceBounds(&bounds.l2_gas)).unwrap(),
        });

        let encoded = ResourceBoundsMapping(&bounds).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn resource_bounds() {
        let s = Serializer::default();

        let bound = common::ResourceBound {
            max_amount: pathfinder_common::ResourceAmount(30),
            max_price_per_unit: pathfinder_common::ResourcePricePerUnit(200),
        };

        let expected = json!({
            "max_amount": s.serialize(&U64(bound.max_amount.0)).unwrap(),
            "max_price_per_unit": s.serialize(&U128(bound.max_price_per_unit.0)).unwrap(),
        });

        let encoded = ResourceBounds(&bound).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[rstest]
    #[case::l1(common::DataAvailabilityMode::L1, "L1")]
    #[case::l2(common::DataAvailabilityMode::L2, "L2")]
    fn da_mode(#[case] mode: common::DataAvailabilityMode, #[case] expected: &str) {
        let s = Serializer::default();
        let expected = s.serialize_str(expected).unwrap();
        let encoded = DaMode(mode).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }
}
