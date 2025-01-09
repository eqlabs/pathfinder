use std::sync::Arc;

use blockifier::context::TransactionContext;
use blockifier::execution::entry_point::{CallEntryPoint, EntryPointExecutionContext};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::{DeprecatedTransactionInfo, TransactionInfo};
use blockifier::versioned_constants::VersionedConstants;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use pathfinder_common::{CallParam, CallResultValue, ContractAddress, EntryPoint};
use starknet_api::core::PatriciaKey;

use super::error::CallError;
use super::execution_state::ExecutionState;
use super::felt::{IntoFelt, IntoStarkFelt};

pub fn call(
    execution_state: ExecutionState<'_>,
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
    let class_hash = state.get_class_hash_at(contract_address)?;

    let call_entry_point = CallEntryPoint {
        storage_address: contract_address,
        entry_point_type: starknet_api::deprecated_contract_class::EntryPointType::External,
        entry_point_selector,
        calldata: starknet_api::transaction::Calldata(Arc::new(calldata)),
        initial_gas: VersionedConstants::latest_constants().tx_initial_gas(),
        call_type: blockifier::execution::entry_point::CallType::Call,
        ..Default::default()
    };

    let mut resources = ExecutionResources::default();
    let mut context = EntryPointExecutionContext::new_invoke(
        Arc::new(TransactionContext {
            block_context,
            tx_info: TransactionInfo::Deprecated(DeprecatedTransactionInfo::default()),
        }),
        false,
    )?;

    let call_info = call_entry_point
        .execute(&mut state, &mut resources, &mut context)
        .map_err(|e| {
            CallError::from_entry_point_execution_error(
                e,
                &contract_address,
                &class_hash,
                &entry_point_selector,
            )
        })?;

    let result = call_info
        .execution
        .retdata
        .0
        .iter()
        .map(|f| CallResultValue(f.into_felt()))
        .collect();

    Ok(result)
}
