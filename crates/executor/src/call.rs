use std::sync::Arc;

use blockifier::context::TransactionContext;
use blockifier::execution::entry_point::{
    CallEntryPoint,
    EntryPointExecutionContext,
    SierraGasRevertTracker,
};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::{DeprecatedTransactionInfo, TransactionInfo};
use blockifier::versioned_constants::VersionedConstants;
use pathfinder_common::{felt, CallParam, CallResultValue, ContractAddress, EntryPoint};
use starknet_api::contract_class::EntryPointType;
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

    let starknet_api_contract_address = starknet_api::core::ContractAddress(PatriciaKey::try_from(
        contract_address.0.into_starkfelt(),
    )?);
    let starknet_api_entry_point_selector =
        starknet_api::core::EntryPointSelector(entry_point_selector.0.into_starkfelt());
    let calldata = calldata
        .into_iter()
        .map(|param| param.0.into_starkfelt())
        .collect();
    let class_hash = state.get_class_hash_at(starknet_api_contract_address)?;

    let initial_gas = VersionedConstants::latest_constants()
        .os_constants
        .gas_costs
        .base
        .default_initial_gas_cost;

    let call_entry_point = CallEntryPoint {
        storage_address: starknet_api_contract_address,
        entry_point_type: EntryPointType::External,
        entry_point_selector: starknet_api_entry_point_selector,
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(calldata)),
        initial_gas,
        call_type: blockifier::execution::entry_point::CallType::Call,
        ..Default::default()
    };

    let mut context = EntryPointExecutionContext::new_invoke(
        Arc::new(TransactionContext {
            block_context,
            tx_info: TransactionInfo::Deprecated(DeprecatedTransactionInfo::default()),
        }),
        false,
        SierraGasRevertTracker::new(starknet_api::execution_resources::GasAmount(initial_gas)),
    );

    let mut remaining_gas = call_entry_point.initial_gas;
    let call_info = call_entry_point
        .execute(&mut state, &mut context, &mut remaining_gas)
        .map_err(|e| {
            CallError::from_entry_point_execution_error(
                e,
                &starknet_api_contract_address,
                &class_hash,
                &starknet_api_entry_point_selector,
            )
        })?;

    let error_stack_call_frame = crate::Frame::CallFrame(crate::CallFrame {
        storage_address: contract_address,
        class_hash: pathfinder_common::ClassHash(class_hash.0.into_felt()),
        selector: Some(entry_point_selector),
    });

    // Sierra 1.7 classes can return a failure without reverting.
    if call_info.execution.failed {
        match call_info.execution.retdata.0.as_slice() {
            [error_code]
                if error_code.into_felt()
                    == felt!(
                        blockifier::execution::syscalls::hint_processor::ENTRYPOINT_NOT_FOUND_ERROR
                    ) =>
            {
                return Err(CallError::InvalidMessageSelector);
            }
            [error_code]
                if error_code.into_felt()
                    == felt!(blockifier::execution::syscalls::hint_processor::OUT_OF_GAS_ERROR) =>
            {
                let error_message = "Out of gas";
                let error_stack = crate::ErrorStack(vec![
                    error_stack_call_frame,
                    crate::Frame::StringFrame(error_message.to_owned()),
                ]);

                return Err(CallError::ContractError(
                    anyhow::anyhow!(error_message),
                    error_stack,
                ));
            }
            _ => {
                let error_message =
                    format!("Failed with retdata: {:?}", call_info.execution.retdata);
                let error_stack = crate::ErrorStack(vec![
                    error_stack_call_frame,
                    crate::Frame::StringFrame(error_message.clone()),
                ]);

                return Err(CallError::ContractError(
                    anyhow::Error::msg(error_message),
                    error_stack,
                ));
            }
        }
    }

    let result = call_info
        .execution
        .retdata
        .0
        .iter()
        .map(|f| CallResultValue(f.into_felt()))
        .collect();

    Ok(result)
}
