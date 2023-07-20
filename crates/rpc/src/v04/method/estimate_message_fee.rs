use pathfinder_common::{BlockId, CallParam, ContractAddress, EntryPoint, EthereumAddress};

use crate::context::RpcContext;
use crate::v02::method::call::FunctionCall;
use crate::v02::types::reply::FeeEstimate;
use crate::v03::method::estimate_message_fee::EstimateMessageFeeError;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateMessageFeeInput {
    message: MsgFromL1,
    block_id: BlockId,
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct MsgFromL1 {
    pub from_address: EthereumAddress,
    pub to_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub payload: Vec<CallParam>,
}

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let input = crate::v03::method::estimate_message_fee::EstimateMessageFeeInput {
        message: FunctionCall {
            contract_address: input.message.to_address,
            entry_point_selector: input.message.entry_point_selector,
            calldata: input.message.payload,
        },
        sender_address: input.message.from_address,
        block_id: input.block_id,
    };

    crate::v03::method::estimate_message_fee(context, input).await
}
