use anyhow::Context;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash};

use crate::context::RpcContext;
use crate::dto;

pub struct Input {
    pub transaction_hash: TransactionHash,
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                transaction_hash: value.deserialize("transaction_hash").map(TransactionHash)?,
            })
        })
    }
}

pub enum Output {
    Full {
        block_hash: BlockHash,
        block_number: BlockNumber,
        receipt: Receipt,
        transaction: Transaction,
        events: Vec<Event>,
        finality: dto::TxnFinalityStatus,
    },
    Pending {
        receipt: Receipt,
        transaction: Transaction,
        events: Vec<Event>,
    },
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            Output::Full {
                block_hash,
                block_number,
                receipt,
                transaction,
                events,
                finality,
            } => dto::TxnReceiptWithBlockInfo {
                block_hash: Some(block_hash),
                block_number: Some(*block_number),
                receipt,
                transaction,
                events,
                finality: *finality,
            },
            Output::Pending {
                receipt,
                transaction,
                events,
            } => dto::TxnReceiptWithBlockInfo {
                block_hash: None,
                block_number: None,
                receipt,
                transaction,
                events,
                finality: dto::TxnFinalityStatus::AcceptedOnL2,
            },
        }
        .serialize(serializer)
    }
}

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub async fn get_transaction_receipt(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();
    util::task::spawn_blocking(move |_| {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Check pending transactions.
        let pending = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?;

        if let Some((transaction, (receipt, events))) = pending
            .block
            .transactions
            .iter()
            .zip(pending.block.transaction_receipts.iter())
            .find_map(|(t, r)| (t.hash == input.transaction_hash).then(|| (t.clone(), r.clone())))
        {
            return Ok(Output::Pending {
                receipt,
                transaction,
                events,
            });
        }

        let (transaction, receipt, events, block_number) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Reading transaction receipt from database")?
            .ok_or(Error::TxnHashNotFound)?;

        let block_hash = db_tx
            .block_hash(block_number.into())
            .context("Querying block hash")?
            .context("Block hash info missing")?;

        let l1_accepted = db_tx
            .block_is_l1_accepted(block_number.into())
            .context("Querying block status")?;

        let finality = if l1_accepted {
            dto::TxnFinalityStatus::AcceptedOnL1
        } else {
            dto::TxnFinalityStatus::AcceptedOnL2
        };

        Ok(Output::Full {
            transaction,
            receipt,
            events,
            block_hash,
            block_number,
            finality,
        })
    })
    .await
    .context("Joining blocking task")?
}

#[cfg(test)]
mod tests {
    use pathfinder_common::transaction_hash_bytes;

    use super::*;
    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn l2_accepted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests();
        // This transaction is in block 1 which is not L1 accepted.
        let tx_hash = transaction_hash_bytes!(b"txn 1");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let output = get_transaction_receipt(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/receipt_l2_accepted.json"
        );
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn pending(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let tx_hash = transaction_hash_bytes!(b"pending tx hash 0");
        let input = Input {
            transaction_hash: tx_hash,
        };
        let output = get_transaction_receipt(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/receipt_pending.json"
        );
    }

    #[rstest::rstest]
    #[case::v06(RpcVersion::V06)]
    #[case::v07(RpcVersion::V07)]
    #[case::v08(RpcVersion::V08)]
    #[tokio::test]
    async fn reverted(#[case] version: RpcVersion) {
        let context = RpcContext::for_tests_with_pending().await;
        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"txn reverted"),
        };
        let output = get_transaction_receipt(context.clone(), input)
            .await
            .unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/receipt_reverted.json"
        );

        let input = Input {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
        };
        let output = get_transaction_receipt(context, input).await.unwrap();

        let output_json = output.serialize(Serializer { version }).unwrap();

        crate::assert_json_matches_fixture!(
            output_json,
            version,
            "transactions/receipt_reverted_pending.json"
        );
    }
}
