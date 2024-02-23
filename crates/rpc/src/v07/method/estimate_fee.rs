use crate::context::RpcContext;

use crate::v06::method::estimate_fee as v06;

pub async fn estimate_fee(
    context: RpcContext,
    input: v06::EstimateFeeInput,
) -> Result<Vec<v06::FeeEstimate>, v06::EstimateFeeError> {
    v06::estimate_fee_impl(context, input).await
}
