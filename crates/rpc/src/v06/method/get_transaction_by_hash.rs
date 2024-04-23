use crate::context::RpcContext;
use crate::v02::method::get_transaction_by_hash as v02_get_transaction_by_hash;
use crate::v06::types::TransactionWithHash;

crate::error::generate_rpc_error_subset!(GetTransactionByHashError: TxnHashNotFound);

pub async fn get_transaction_by_hash(
    context: RpcContext,
    input: v02_get_transaction_by_hash::GetTransactionByHashInput,
) -> Result<TransactionWithHash, GetTransactionByHashError> {
    v02_get_transaction_by_hash::get_transaction_by_hash_impl(context, input)
        .await?
        .map(Into::into)
        .ok_or(GetTransactionByHashError::TxnHashNotFound)
}
