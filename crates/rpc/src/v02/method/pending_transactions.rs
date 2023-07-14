use anyhow::Context;

use crate::context::RpcContext;
use crate::v02::types::reply::Transaction;

crate::error::generate_rpc_error_subset!(PendingTransactionsError:);

pub async fn pending_transactions(
    context: RpcContext,
) -> Result<Vec<Transaction>, PendingTransactionsError> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        let pending = context
            .pending_block(&db_tx)
            .context("Querying pending block")?;

        let pending = pending
            .map(|b| {
                b.body
                    .transaction_data
                    .iter()
                    .map(|(tx, _rx)| tx.clone().into())
                    .collect::<Vec<Transaction>>()
            })
            .unwrap_or_default();

        Ok(pending)
    })
    .await
    .context("Joining database task")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::reply::{
        CommonDeclareInvokeTransactionProperties, DeployTransaction, InvokeTransaction,
        InvokeTransactionV0,
    };
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{TransactionNonce, TransactionVersion};

    #[tokio::test]
    async fn pending() {
        // Transcribed from the `RpcContext::for_tests_with_pending` transactions.
        let tx0 = InvokeTransactionV0 {
            common: CommonDeclareInvokeTransactionProperties {
                hash: transaction_hash_bytes!(b"pending tx hash 0"),
                max_fee: crate::v02::types::request::Call::DEFAULT_MAX_FEE,
                signature: vec![],
                nonce: TransactionNonce::ZERO,
            },
            contract_address: contract_address_bytes!(b"pending contract addr 0"),
            entry_point_selector: entry_point_bytes!(b"entry point 0"),
            calldata: vec![],
        };

        let tx1 = DeployTransaction {
            hash: transaction_hash_bytes!(b"pending tx hash 1"),
            class_hash: class_hash_bytes!(b"pending class hash 1"),
            version: TransactionVersion::ZERO,
            contract_address_salt: contract_address_salt_bytes!(b"salty"),
            constructor_calldata: vec![],
        };

        let expected = vec![
            Transaction::Invoke(InvokeTransaction::V0(tx0)),
            Transaction::Deploy(tx1),
        ];

        let context = RpcContext::for_tests_with_pending().await;
        let result = pending_transactions(context).await.unwrap();

        assert_eq!(result, expected);
    }
}
