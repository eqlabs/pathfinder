use crate::context::RpcContext;
use crate::v04::types::TransactionWithHash;

use crate::v02::method::get_transaction_by_hash as v02_get_transaction_by_hash;

crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFoundV04);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: v02_get_transaction_by_hash::GetTransactionByHashInput,
) -> Result<TransactionWithHash, GetTransactionByHashError> {
    v02_get_transaction_by_hash::get_transaction_by_hash_impl(context, input)
        .await?
        .map(|x| {
            let common_tx = pathfinder_common::transaction::Transaction::from(x);
            common_tx.into()
        })
        .ok_or(GetTransactionByHashError::TxnHashNotFoundV04)
}
