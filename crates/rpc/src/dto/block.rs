use crate::dto::serialize;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::*;

struct BlockBodyWithTxHashes<'a>(&'a [pathfinder_common::TransactionHash]);
struct BlockBodyWithTxs<'a>(&'a [(&'a pathfinder_common::transaction::Transaction, bool)]);

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

impl SerializeForVersion for BlockBodyWithTxs<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct Item<'a> {
            transaction: &'a pathfinder_common::transaction::Transaction,
            query: bool,
        }
        impl SerializeForVersion for Item<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("transaction_hash", &TxnHash(&self.transaction.hash))?;
                serializer.flatten(&Txn {
                    variant: &self.transaction.variant,
                    query: self.query,
                })?;

                serializer.end()
            }
        }

        serializer.serialize_iter(
            self.0.len(),
            &mut self.0.iter().map(|(t, query)| Item {
                transaction: *t,
                query: *query,
            }),
        )
    }
}
