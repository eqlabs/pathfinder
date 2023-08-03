use std::sync::Arc;

use blockifier::{
    execution::entry_point::{CallEntryPoint, EntryPointExecutionContext, ExecutionResources},
    transaction::objects::AccountTransactionContext,
};
use pathfinder_common::{CallParam, CallResultValue, ContractAddress, EntryPoint};
use starknet_api::core::PatriciaKey;

use super::{
    error::CallError,
    execution_state::ExecutionState,
    felt::{IntoFelt, IntoStarkFelt},
};

pub fn call(
    mut execution_state: ExecutionState,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
) -> Result<Vec<CallResultValue>, CallError> {
    let (mut state, block_context) = execution_state.starknet_state()?;

    let contract_address = starknet_api::core::ContractAddress(PatriciaKey::try_from(
        contract_address.0.into_starkfelt(),
    )?);
    let entry_point_selector =
        starknet_api::core::EntryPointSelector(entry_point_selector.0.into_starkfelt());
    let calldata = calldata
        .into_iter()
        .map(|param| param.0.into_starkfelt())
        .collect();

    let call_entry_point = CallEntryPoint {
        storage_address: contract_address,
        entry_point_type: starknet_api::deprecated_contract_class::EntryPointType::External,
        entry_point_selector,
        calldata: starknet_api::transaction::Calldata(Arc::new(calldata)),
        initial_gas: blockifier::abi::constants::INITIAL_GAS_COST,
        call_type: blockifier::execution::entry_point::CallType::Call,
        ..Default::default()
    };

    let mut resources = ExecutionResources::default();
    let mut context = EntryPointExecutionContext::new_invoke(
        &block_context,
        &AccountTransactionContext::default(),
    );

    let call_info = call_entry_point.execute(&mut state, &mut resources, &mut context)?;

    let result = call_info
        .execution
        .retdata
        .0
        .iter()
        .map(|f| CallResultValue(f.into_felt()))
        .collect();

    Ok(result)
}
