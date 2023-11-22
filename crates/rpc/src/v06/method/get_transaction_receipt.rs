use crate::context::RpcContext;
use crate::v05::method::get_transaction_receipt as v05;

pub async fn get_transaction_receipt(
    context: RpcContext,
    input: v05::GetTransactionReceiptInput,
) -> Result<v05::types::MaybePendingTransactionReceipt, v05::GetTransactionReceiptError> {
    // v0.5 has a different fee structure, but that gets handled in the v0.5 method. We can
    // safely use the impl as is.
    v05::get_transaction_receipt_impl(context, input).await
}
