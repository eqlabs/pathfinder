use crate::dto::serialize;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::*;

struct BlockBodyWithTxHashes<'a>(&'a [pathfinder_common::TransactionHash]);

impl SerializeForVersion for BlockBodyWithTxHashes<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_iter(
            "transactions",
            self.0.len(),
            &mut self.0.iter().map(|x| TxnHash(x)),
        )?;

        serializer.end()
    }
}
