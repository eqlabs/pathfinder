use crate::context::RpcContext;
use crate::v02::method::get_transaction_by_block_id_and_index::{
    get_transaction_by_block_id_and_index_impl, GetTransactionByBlockIdAndIndexError,
    GetTransactionByBlockIdAndIndexInput,
};
use crate::v06::types::TransactionWithHash;

pub async fn get_transaction_by_block_id_and_index(
    context: RpcContext,
    input: GetTransactionByBlockIdAndIndexInput,
) -> Result<TransactionWithHash, GetTransactionByBlockIdAndIndexError> {
    get_transaction_by_block_id_and_index_impl(context, input)
        .await
        .map(Into::into)
}
