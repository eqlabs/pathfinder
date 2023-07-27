use crate::context::RpcContext;
use crate::v02::types::reply::Transaction;
use anyhow::Context;
use pathfinder_common::TransactionHash;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetTransactionByHashInput {
    transaction_hash: TransactionHash,
}

crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFoundV03);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: GetTransactionByHashInput,
) -> Result<Transaction, GetTransactionByHashError> {
    if let Some(pending) = &context.pending_data {
        let pending_tx = pending.block().await.and_then(|block| {
            block
                .transactions
                .iter()
                .find(|tx| tx.hash() == input.transaction_hash)
                .cloned()
        });

        if let Some(pending_tx) = pending_tx {
            return Ok(pending_tx.into());
        }
    }

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let jh = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = storage
            .connection()
            .context("Opening database connection")?;

        let db_tx = db.transaction().context("Creating database transaction")?;

        // Get the transaction from storage.
        db_tx
            .transaction(input.transaction_hash)
            .context("Reading transaction from database")?
            .ok_or(GetTransactionByHashError::TxnHashNotFoundV03)
            .map(|tx| tx.into())
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{EntryPoint, Fee, TransactionNonce};
    use stark_hash::Felt;

    mod parsing {
        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                "0xdeadbeef"
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<GetTransactionByHashInput>().unwrap();
            assert_eq!(
                input,
                GetTransactionByHashInput {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }

        #[test]
        fn named_args() {
            let named_args = r#"{
                "transaction_hash": "0xdeadbeef"
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<GetTransactionByHashInput>().unwrap();
            assert_eq!(
                input,
                GetTransactionByHashInput {
                    transaction_hash: transaction_hash!("0xdeadbeef")
                }
            )
        }
    }

    mod errors {
        use super::*;

        #[tokio::test]
        async fn hash_not_found() {
            let context = RpcContext::for_tests();
            let input = GetTransactionByHashInput {
                transaction_hash: transaction_hash_bytes!(b"non_existent"),
            };

            let result = get_transaction_by_hash(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionByHashError::TxnHashNotFoundV03)
            );
        }
    }

    #[tokio::test]
    async fn success() {
        let context = RpcContext::for_tests();
        let input = GetTransactionByHashInput {
            transaction_hash: transaction_hash_bytes!(b"txn 0"),
        };

        let result = get_transaction_by_hash(context, input).await.unwrap();
        use crate::v02::types::reply;
        assert_eq!(
            result,
            Transaction::Invoke(reply::InvokeTransaction::V0(reply::InvokeTransactionV0 {
                common: reply::CommonDeclareInvokeTransactionProperties {
                    hash: transaction_hash_bytes!(b"txn 0"),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                    nonce: TransactionNonce(Felt::ZERO),
                },
                contract_address: contract_address_bytes!(b"contract 0"),
                entry_point_selector: EntryPoint(Felt::ZERO),
                calldata: vec![],
            }))
        )
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        let input = GetTransactionByHashInput {
            transaction_hash: transaction_hash_bytes!(b"pending tx hash 0"),
        };

        let result = get_transaction_by_hash(context, input).await.unwrap();
        use crate::v02::types::reply;
        assert_eq!(
            result,
            Transaction::Invoke(reply::InvokeTransaction::V0(reply::InvokeTransactionV0 {
                common: reply::CommonDeclareInvokeTransactionProperties {
                    hash: transaction_hash_bytes!(b"pending tx hash 0"),
                    max_fee: Fee::ZERO,
                    signature: vec![],
                    nonce: TransactionNonce(Felt::ZERO),
                },
                contract_address: contract_address_bytes!(b"pending contract addr 0"),
                entry_point_selector: entry_point_bytes!(b"entry point 0"),
                calldata: vec![],
            }))
        )
    }
}
