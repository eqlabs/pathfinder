use crate::{
    context::RpcContext,
    v02::{
        method::call::FunctionCall,
        types::reply::FeeEstimate,
    },
};
use pathfinder_common::{BlockId, EthereumAddress};

use super::common::prepare_handle_and_block;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateMessageFeeInput {
    message: FunctionCall,
    sender_address: EthereumAddress,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateMessageFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<crate::cairo::ext_py::CallFailure> for EstimateMessageFeeError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            ExecutionFailed(_) | InvalidEntryPoint => Self::ContractError,
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let (handle, gas_price, when, pending_timestamp, pending_update) =
        prepare_handle_and_block(&context, input.block_id).await?;

    let result = handle
        .estimate_message_fee(
            input.message.into(),
            when,
            gas_price,
            pending_update,
            pending_timestamp,
        )
        .await?;

    Ok(result)
}
