use crate::context::RpcContext;
use crate::v06::method::estimate_fee::FeeEstimate;
use crate::v06::method::estimate_message_fee as v06;

pub async fn estimate_message_fee(
    context: RpcContext,
    input: v06::EstimateMessageFeeInput,
) -> Result<FeeEstimate, v06::EstimateMessageFeeError> {
    let result = v06::estimate_message_fee_impl(context, input).await?;

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed,
        gas_price: result.gas_price,
        overall_fee: result.overall_fee,
        unit: result.unit.into(),
        data_gas_consumed: Some(result.data_gas_consumed),
        data_gas_price: Some(result.data_gas_price),
    })
}
