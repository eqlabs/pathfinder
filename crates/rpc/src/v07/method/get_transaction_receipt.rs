use crate::context::RpcContext;
use crate::v06::method::get_transaction_receipt::types::FinalityStatus;
use crate::v07::dto;
use anyhow::Context;
use pathfinder_common::TransactionHash;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub transaction_hash: TransactionHash,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Output {
    Full(dto::receipt::TxnReceipt),
    Pending(dto::receipt::PendingTxnReceipt),
}

crate::error::generate_rpc_error_subset!(Error: TxnHashNotFound);

pub async fn get_transaction_receipt(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
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

        if let Some((transaction, receipt)) = pending
            .block
            .transactions
            .iter()
            .zip(pending.block.transaction_receipts.iter())
            .find_map(|(t, r)| (t.hash == input.transaction_hash).then(|| (t.clone(), r.clone())))
        {
            let receipt = dto::receipt::PendingTxnReceipt::from_common(
                &transaction,
                receipt,
                FinalityStatus::AcceptedOnL2,
            );

            return Ok(Output::Pending(receipt));
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

        let finality_status = if l1_accepted {
            FinalityStatus::AcceptedOnL1
        } else {
            FinalityStatus::AcceptedOnL2
        };

        Ok(Output::Full(dto::receipt::TxnReceipt::from_common(
            &transaction,
            receipt,
            block_hash,
            block_number,
            finality_status,
        )))
    })
    .await
    .context("Joining blocking task")?
}
