use crate::{
    context::RpcContext,
    dto::{self, TxnFinalityStatus},
};
use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber, TransactionHash};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub transaction_hash: TransactionHash,
}

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub enum Output {
    Full {
        receipt: pathfinder_common::receipt::Receipt,
        transaction: pathfinder_common::transaction::Transaction,
        finality: TxnFinalityStatus,
        block_hash: BlockHash,
        block_number: BlockNumber,
    },
    Pending {
        receipt: pathfinder_common::receipt::Receipt,
        transaction: pathfinder_common::transaction::Transaction,
    },
}

impl dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: dto::serialize::Serializer,
    ) -> Result<dto::serialize::Ok, dto::serialize::Error> {
        match self {
            Output::Full {
                receipt,
                transaction,
                finality,
                block_hash,
                block_number,
            } => dto::TxnReceipt {
                receipt,
                transaction,
                finality: *finality,
                block_hash,
                block_number: *block_number,
            }
            .serialize(serializer),
            Output::Pending {
                receipt,
                transaction,
            } => dto::PendingTxnReceipt {
                receipt,
                transaction,
            }
            .serialize(serializer),
        }
    }
}

pub async fn get_transaction_receipt_impl(
    context: RpcContext,
    input: Input,
) -> Result<Output, Error> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Check pending transactions.
        let pending = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?;

        if let Some((transaction, receipt)) = pending
            .block
            .transactions
            .iter()
            .zip(pending.block.transaction_receipts.iter())
            .find_map(|(t, r)| (t.hash == input.transaction_hash).then(|| (t.clone(), r.clone())))
        {
            return Ok(Output::Pending {
                receipt,
                transaction,
            });
        }

        let (transaction, receipt, block_hash) = db_tx
            .transaction_with_receipt(input.transaction_hash)
            .context("Reading transaction receipt from database")?
            .ok_or(Error::TxnHashNotFound)?;

        let block_number = db_tx
            .block_id(block_hash.into())
            .context("Querying block number")?
            .context("Block number info missing")?
            .0;

        let l1_accepted = db_tx
            .block_is_l1_accepted(block_number.into())
            .context("Querying block status")?;

        let finality = if l1_accepted {
            dto::TxnFinalityStatus::AcceptedOnL1
        } else {
            dto::TxnFinalityStatus::AcceptedOnL2
        };

        Ok(Output::Full {
            receipt,
            transaction,
            finality,
            block_hash,
            block_number,
        })
    });

    jh.await.context("Database read panic or shutting down")?
}
