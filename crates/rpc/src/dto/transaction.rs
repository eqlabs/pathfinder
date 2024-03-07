use crate::dto::serialize::SerializeForVersion;
use crate::dto::serialize::Serializer;
use crate::dto::*;

use pathfinder_common::transaction as common;

struct Signature<'a>(&'a [pathfinder_common::TransactionSignatureElem]);

impl SerializeForVersion for Signature<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;

        for x in self.0 {
            serializer.serialize_element(&Felt(&x.0))?;
        }

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
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
}
