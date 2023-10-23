use anyhow::Context;

use crate::context::RpcContext;
use crate::v04::types::TransactionWithHash;

crate::error::generate_rpc_error_subset!(PendingTransactionsError:);

pub async fn pending_transactions(
    context: RpcContext,
) -> Result<Vec<TransactionWithHash>, PendingTransactionsError> {
    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        let transactions = context
            .pending_data
            .get(&db_tx)
            .context("Querying pending data")?
            .block
            .transactions
            .iter()
            .map(|x| {
                let common_tx = pathfinder_common::transaction::Transaction::from(x.clone());
                common_tx.into()
            })
            .collect();

        Ok(transactions)
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use crate::v04::types::Transaction;

    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::transaction::DeployTransaction;
    use pathfinder_common::transaction::EntryPointType::External;
    use pathfinder_common::transaction::InvokeTransactionV0;
    use pathfinder_common::transaction::TransactionVariant;

    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn pending() {
        // Transcribed from the `RpcContext::for_tests_with_pending` transactions.
        let tx0 = TransactionWithHash {
            transaction_hash: transaction_hash_bytes!(b"pending tx hash 0"),
            txn: Transaction(TransactionVariant::InvokeV0(InvokeTransactionV0 {
                sender_address: contract_address_bytes!(b"pending contract addr 0"),
                entry_point_selector: entry_point_bytes!(b"entry point 0"),
                entry_point_type: Some(External),
                ..Default::default()
            })),
        };

        let tx1 = TransactionWithHash {
            transaction_hash: transaction_hash_bytes!(b"pending tx hash 1"),
            txn: Transaction(TransactionVariant::Deploy(DeployTransaction {
                contract_address: contract_address!("0x1122355"),
                class_hash: class_hash_bytes!(b"pending class hash 1"),
                contract_address_salt: contract_address_salt_bytes!(b"salty"),
                ..Default::default()
            })),
        };

        let tx2 = TransactionWithHash {
            transaction_hash: transaction_hash_bytes!(b"pending reverted"),
            txn: Transaction(TransactionVariant::InvokeV0(InvokeTransactionV0 {
                sender_address: contract_address_bytes!(b"pending contract addr 0"),
                entry_point_selector: entry_point_bytes!(b"entry point 0"),
                entry_point_type: Some(External),
                ..Default::default()
            })),
        };

        let expected = vec![tx0, tx1, tx2];

        let context = RpcContext::for_tests_with_pending().await;
        let result = pending_transactions(context).await.unwrap();

        assert_eq!(result, expected);
    }
}
