use starknet_in_rust::definitions::block_context::{BlockContext, StarknetOsConfig};

use super::{felt::IntoFelt252, ExecutionState};

pub(super) fn construct_block_context(
    execution_state: &ExecutionState,
) -> anyhow::Result<BlockContext> {
    let starknet_os_config = StarknetOsConfig::new(
        execution_state.chain_id.0.into_felt252(),
        starknet_in_rust::utils::Address(0.into()),
        execution_state.gas_price.as_u128(),
    );

    let mut block_context = BlockContext::default();
    *block_context.starknet_os_config_mut() = starknet_os_config;
    let block_info = block_context.block_info_mut();
    block_info.gas_price = execution_state.gas_price.as_u64();
    block_info.block_number = execution_state.block_number.get();
    block_info.block_timestamp = execution_state.block_timestamp.get();
    block_info.sequencer_address =
        starknet_in_rust::utils::Address(execution_state.sequencer_address.0.into_felt252());

    Ok(block_context)
}
