use crate::context::RpcContext;
use crate::v05::method::estimate_message_fee::EstimateMessageFeeInput;

crate::error::generate_rpc_error_subset!(
    EstimateMessageFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<crate::v05::method::estimate_message_fee::EstimateMessageFeeError>
    for EstimateMessageFeeError
{
    fn from(value: crate::v05::method::estimate_message_fee::EstimateMessageFeeError) -> Self {
        use crate::v05::method::estimate_message_fee::EstimateMessageFeeError::*;

        match value {
            Internal(e) => Self::Internal(e),
            BlockNotFound => Self::BlockNotFound,
            ContractNotFound => Self::ContractNotFound,
            ContractErrorV05 { revert_error } => {
                Self::Internal(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
        }
    }
}

// The implementation is the same as for v05 -- the only difference is that we have to map
// ContractErrorV05 to an internal error.
pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<crate::v05::method::estimate_fee::FeeEstimate, EstimateMessageFeeError> {
    crate::v05::method::estimate_message_fee::estimate_message_fee(context, input)
        .await
        .map_err(Into::into)
}
