use crate::dto::serialize;
use crate::dto::serialize::SerializeForVersion;
use crate::dto::*;

struct BlockBodyWithTxHashes<'a>(&'a [pathfinder_common::TransactionHash]);
struct BlockBodyWithTxs<'a>(&'a [(&'a pathfinder_common::transaction::Transaction, bool)]);
struct BlockBodyWithReceipts<'a> {
    body: &'a [(
        &'a pathfinder_common::transaction::Transaction,
        &'a pathfinder_common::receipt::Receipt,
        bool,
    )],
    block_hash: &'a pathfinder_common::BlockHash,
    block_number: pathfinder_common::BlockNumber,
    finality: TxnFinalityStatus,
}

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

impl SerializeForVersion for BlockBodyWithReceipts<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct Item<'a> {
            transaction: &'a pathfinder_common::transaction::Transaction,
            receipt: &'a pathfinder_common::receipt::Receipt,
            block_hash: &'a pathfinder_common::BlockHash,
            block_number: pathfinder_common::BlockNumber,
            finality: TxnFinalityStatus,
            query: bool,
        }
        impl SerializeForVersion for Item<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field(
                    "receipt",
                    &TxnReceipt {
                        receipt: self.receipt,
                        transaction: self.transaction,
                        finality: self.finality,
                        block_hash: self.block_hash,
                        block_number: self.block_number,
                    },
                )?;
                serializer.flatten(&Txn {
                    variant: &self.transaction.variant,
                    query: self.query,
                })?;

                serializer.end()
            }
        }

        serializer.serialize_iter(
            self.body.len(),
            &mut self.body.iter().map(|(t, r, query)| Item {
                transaction: *t,
                query: *query,
                receipt: *r,
                block_hash: self.block_hash,
                block_number: self.block_number,
                finality: self.finality,
            }),
        )
    }
}
