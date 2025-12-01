use std::sync::Arc;

use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::context::TransactionContext;
use blockifier::execution::entry_point::{
    CallEntryPoint,
    EntryPointExecutionContext,
    SierraGasRevertTracker,
};
use blockifier::execution::stack_trace::{
    extract_trailing_cairo1_revert_trace,
    Cairo1RevertHeader,
};
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::{DeprecatedTransactionInfo, TransactionInfo};
use pathfinder_common::{felt, CallParam, CallResultValue, ContractAddress, EntryPoint};
use starknet_api::contract_class::EntryPointType;
use starknet_api::core::PatriciaKey;
use starknet_api::versioned_constants_logic::VersionedConstantsTrait;

use super::error::CallError;
use super::execution_state::ExecutionState;
use super::felt::{IntoFelt, IntoStarkFelt};
use crate::state_reader::RcStorageAdapter;

pub fn call(
    db_tx: pathfinder_storage::Transaction<'_>,
    execution_state: ExecutionState,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
) -> Result<Vec<CallResultValue>, CallError> {
    let storage_adapter = RcStorageAdapter::new(db_tx);
    let (mut state, block_context) = execution_state.starknet_state(storage_adapter)?;

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
            block_context: Arc::new(block_context),
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

    // In Starknet 0.13.4 calls return a failure which is not an error.
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
            _ => {
                let revert_trace =
                    extract_trailing_cairo1_revert_trace(&call_info, Cairo1RevertHeader::Execution);

                return Err(CallError::ContractError(
                    anyhow::Error::msg(revert_trace.to_string()),
                    revert_trace.into(),
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
