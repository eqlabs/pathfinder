use crate::dto;
use crate::dto::serialize;


pub struct ResourcePrice<'a> {
    price_in_fri: &'a pathfinder_common::GasPrice,
    price_in_wei: &'a pathfinder_common::GasPrice,
}

impl serialize::SerializeForVersion for ResourcePrice<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        // unwraps are safe as u128 always fit into a felt.
        let fri = self.price_in_fri.0.to_be_bytes();
        let fri = pathfinder_crypto::Felt::from_be_slice(&fri).unwrap();
        let wei = self.price_in_wei.0.to_be_bytes();
        let wei = pathfinder_crypto::Felt::from_be_slice(&wei).unwrap();

        serializer.serialize_field("price_in_fri", &dto::Felt(&fri))?;
        serializer.serialize_field("price_in_wei", &dto::Felt(&wei))?;

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::serialize::SerializeForVersion;
    use crate::dto::*;
    use pathfinder_common::macro_prelude::*;
    use serde_json::json;

    use pretty_assertions_sorted::assert_eq;

    #[test]
    fn resource_price() {
        let expected = json!({
            "price_in_fri": Felt(&felt!("0x1234")).serialize(Default::default()).unwrap(),
            "price_in_wei": Felt(&felt!("0x5678")).serialize(Default::default()).unwrap(),
        });

        let encoded = ResourcePrice {
            price_in_fri: &pathfinder_common::GasPrice(0x1234),
            price_in_wei: &pathfinder_common::GasPrice(0x5678),
        }
        .serialize(Default::default())
        .unwrap();

        assert_eq!(encoded, expected);
    }
}
