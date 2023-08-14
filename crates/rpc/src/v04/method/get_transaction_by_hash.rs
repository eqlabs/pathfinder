use crate::context::RpcContext;
use crate::v02::types::reply::Transaction;

use crate::v02::method::get_transaction_by_hash as v02_get_transaction_by_hash;

crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFoundV04);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: v02_get_transaction_by_hash::GetTransactionByHashInput,
) -> Result<Transaction, GetTransactionByHashError> {
    // v0.4 is a complete copy except we use a different error code.
    v02_get_transaction_by_hash::get_transaction_by_hash_impl(context, input)
        .await?
        .map(Into::into)
        .ok_or(GetTransactionByHashError::TxnHashNotFoundV04)
}
