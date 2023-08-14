use pathfinder_common::TransactionHash;

use crate::context::RpcContext;
use crate::v04::types::Transaction;

use crate::v02::method::get_transaction_by_hash as v02_get_transaction_by_hash;

crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFoundV04);

#[derive(serde::Serialize)]
pub struct GetTransactionByHashOutput {
    transaction_hash: TransactionHash,
    #[serde(flatten)]
    txn: Transaction,
}

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: v02_get_transaction_by_hash::GetTransactionByHashInput,
) -> Result<GetTransactionByHashOutput, GetTransactionByHashError> {
    v02_get_transaction_by_hash::get_transaction_by_hash_impl(context, input)
        .await?
        .map(|x| {
            let common_tx = pathfinder_common::transaction::Transaction::from(x);
            GetTransactionByHashOutput {
                transaction_hash: common_tx.hash,
                txn: Transaction(common_tx.variant),
            }
        })
        .ok_or(GetTransactionByHashError::TxnHashNotFoundV04)
}
