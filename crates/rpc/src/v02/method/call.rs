use crate::context::RpcContext;
use crate::v05::method::call::{CallInput, CallOutput};

crate::error::generate_rpc_error_subset!(CallError: BlockNotFound, ContractNotFound, ContractError);

impl From<crate::v05::method::call::CallError> for CallError {
    fn from(value: crate::v05::method::call::CallError) -> Self {
        match value {
            crate::v05::method::call::CallError::Internal(e) => Self::Internal(e),
            crate::v05::method::call::CallError::BlockNotFound => Self::BlockNotFound,
            crate::v05::method::call::CallError::ContractNotFound => Self::ContractNotFound,
            crate::v05::method::call::CallError::ContractErrorV05 { revert_error } => {
                Self::Custom(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            crate::v05::method::call::CallError::Custom(e) => Self::Custom(e),
        }
    }
}

// The implementation is the same as for v05 -- the only difference is that we have to map
// ContractErrorV05 to an internal error.
pub async fn call(context: RpcContext, input: CallInput) -> Result<CallOutput, CallError> {
    crate::v05::method::call::call(context, input)
        .await
        .map_err(Into::into)
}
