use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

mod invoke;

pub use invoke::*;

use pathfinder_common::transaction as common;
use pathfinder_common::TransactionVersion;

struct FunctionCall<'a> {
    pub contract_address: &'a pathfinder_common::ContractAddress,
    pub entry_point_selector: &'a pathfinder_common::EntryPoint,
    pub calldata: &'a [pathfinder_common::CallParam],
}

struct Signature<'a>(&'a [pathfinder_common::TransactionSignatureElem]);
struct ResourceBoundsMapping<'a>(&'a common::ResourceBounds);
struct ResourceBounds<'a>(&'a common::ResourceBound);
struct DaMode(common::DataAvailabilityMode);

impl SerializeForVersion for FunctionCall<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("contract_address", &Address(&self.contract_address))?;
        serializer.serialize_field("entry_point_selector", &Felt(&self.entry_point_selector.0))?;
        serializer.serialize_iter(
            "calldata",
            self.calldata.len(),
            &mut self.calldata.iter().map(|x| Felt(&x.0)),
        )?;

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
