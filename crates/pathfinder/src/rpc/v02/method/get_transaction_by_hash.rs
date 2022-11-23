use crate::rpc::v02::types::reply::Transaction;
use crate::rpc::v02::RpcContext;
use crate::storage::StarknetTransactionsTable;
use anyhow::Context;
use pathfinder_core::StarknetTransactionHash;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct GetTransactionByHashInput {
    transaction_hash: StarknetTransactionHash,
}

crate::rpc::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFound);

#[allow(dead_code)]
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
        StarknetTransactionsTable::get_transaction(&db_tx, input.transaction_hash)
            .context("Reading transaction from database")?
            .ok_or(GetTransactionByHashError::TxnHashNotFound)
            .map(|tx| tx.into())
    });

    jh.await.context("Database read panic or shutting down")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_core::{
        starkhash, starkhash_bytes, ContractAddress, EntryPoint, Fee, StarknetTransactionHash,
        TransactionNonce,
    };
    use stark_hash::StarkHash;

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
                    transaction_hash: StarknetTransactionHash(starkhash!("deadbeef"))
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
                    transaction_hash: StarknetTransactionHash(starkhash!("deadbeef"))
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
                transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"non_existent")),
            };

            let result = get_transaction_by_hash(context, input).await;

            assert_matches::assert_matches!(
                result,
                Err(GetTransactionByHashError::TxnHashNotFound)
            );
        }
    }

    #[tokio::test]
    async fn success() {
        let context = RpcContext::for_tests();
        let input = GetTransactionByHashInput {
            transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"txn 0")),
        };

        let result = get_transaction_by_hash(context, input).await.unwrap();
        use crate::rpc::v02::types::reply;
        assert_eq!(
            result,
            Transaction::Invoke(reply::InvokeTransaction::V0(reply::InvokeTransactionV0 {
                common: reply::CommonInvokeTransactionProperties {
                    hash: StarknetTransactionHash(starkhash_bytes!(b"txn 0")),
                    max_fee: Fee(web3::types::H128::zero()),
                    signature: vec![],
                    nonce: TransactionNonce(StarkHash::ZERO),
                },
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0")),
                entry_point_selector: EntryPoint(StarkHash::ZERO),
                calldata: vec![],
            }))
        )
    }

    #[tokio::test]
    async fn pending() {
        let context = RpcContext::for_tests_with_pending().await;

        let input = GetTransactionByHashInput {
            transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 0")),
        };

        let result = get_transaction_by_hash(context, input).await.unwrap();
        use crate::rpc::v02::types::reply;
        assert_eq!(
            result,
            Transaction::Invoke(reply::InvokeTransaction::V0(reply::InvokeTransactionV0 {
                common: reply::CommonInvokeTransactionProperties {
                    hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 0")),
                    max_fee: Fee(web3::types::H128::zero()),
                    signature: vec![],
                    nonce: TransactionNonce(StarkHash::ZERO),
                },
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract addr 0"
                )),
                entry_point_selector: EntryPoint(starkhash_bytes!(b"entry point 0")),
                calldata: vec![],
            }))
        )
    }
}
