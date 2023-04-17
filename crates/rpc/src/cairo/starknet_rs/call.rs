use anyhow::Context;
use pathfinder_common::{CallParam, CallResultValue, ContractAddress, EntryPoint};
use stark_hash::Felt;
use starknet_in_rust::execution::execution_entry_point::ExecutionEntryPoint;
use starknet_in_rust::execution::TransactionExecutionContext;

use starknet_in_rust::state::ExecutionResourcesManager;
use starknet_in_rust::utils::Address;
use starknet_in_rust::{felt::Felt252, EntryPointType};

use super::{error::CallError, ExecutionState};

pub fn call(
    mut execution_state: ExecutionState,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
) -> Result<Vec<CallResultValue>, CallError> {
    let (mut state, block_context) = execution_state.starknet_state()?;

    let contract_address = Address(Felt252::from_bytes_be(contract_address.get().as_be_bytes()));
    let calldata = calldata
        .iter()
        .map(|p| Felt252::from_bytes_be(p.0.as_be_bytes()))
        .collect();
    let entry_point_selector = Felt252::from_bytes_be(entry_point_selector.0.as_be_bytes());
    let caller_address = Address(0.into());
    let exec_entry_point = ExecutionEntryPoint::new(
        contract_address,
        calldata,
        entry_point_selector,
        caller_address.clone(),
        EntryPointType::External,
        None,
        None,
        starknet_in_rust::definitions::constants::INITIAL_GAS_COST,
    );

    let mut execution_context = TransactionExecutionContext::new(
        caller_address,
        0.into(),
        Vec::new(),
        0,
        1.into(),
        block_context.invoke_tx_max_n_steps(),
        1.into(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let execution_result = exec_entry_point.execute(
        &mut state,
        &block_context,
        &mut resources_manager,
        &mut execution_context,
        false,
        block_context.invoke_tx_max_n_steps(),
    )?;

    let call_info = execution_result
        .call_info
        .ok_or(anyhow::anyhow!("Call info is missing"))?;

    let result = call_info
        .retdata
        .iter()
        .map(|f| Felt::from_be_slice(&f.to_bytes_be()).map(CallResultValue))
        .collect::<Result<Vec<CallResultValue>, _>>()
        .context("Converting results to felts")?;

    Ok(result)
}
