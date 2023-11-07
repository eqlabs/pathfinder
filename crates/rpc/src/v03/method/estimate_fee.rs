use crate::{
    context::RpcContext,
    v05::method::estimate_fee::{EstimateFeeInput, FeeEstimate},
};

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<crate::v05::method::estimate_fee::EstimateFeeError> for EstimateFeeError {
    fn from(value: crate::v05::method::estimate_fee::EstimateFeeError) -> Self {
        use crate::v05::method::estimate_fee::EstimateFeeError::*;
        match value {
            Internal(e) => Self::Internal(e),
            BlockNotFound => Self::BlockNotFound,
            ContractNotFound => Self::ContractNotFound,
            ContractErrorV05 { revert_error } => {
                Self::Custom(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Custom(e) => Self::Custom(e),
        }
    }
}

// The implementation is the same as for v05 -- the only difference is that we have to map
// ContractErrorV05 to an internal error.
pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    crate::v05::method::estimate_fee::estimate_fee(context, input)
        .await
        .map_err(Into::into)
}
