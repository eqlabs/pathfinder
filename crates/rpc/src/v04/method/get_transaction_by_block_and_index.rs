use crate::context::RpcContext;
use crate::v02::method::get_transaction_by_block_id_and_index::{
    get_transaction_by_block_id_and_index_impl, GetTransactionByBlockIdAndIndexError,
    GetTransactionByBlockIdAndIndexInput,
};
use crate::v04::types::Transaction;
use pathfinder_common::TransactionHash;

#[derive(serde::Serialize)]
pub struct GetTransactionByBlockIdAndIndexOutput {
    transaction_hash: TransactionHash,
    #[serde(flatten)]
    txn: Transaction,
}

pub async fn get_transaction_by_block_id_and_index(
    context: RpcContext,
    input: GetTransactionByBlockIdAndIndexInput,
) -> Result<GetTransactionByBlockIdAndIndexOutput, GetTransactionByBlockIdAndIndexError> {
    get_transaction_by_block_id_and_index_impl(context, input)
        .await
        .map(|x| {
            let common_tx = pathfinder_common::transaction::Transaction::from(x);
            GetTransactionByBlockIdAndIndexOutput {
                transaction_hash: common_tx.hash,
                txn: Transaction(common_tx.variant),
            }
        })
}
