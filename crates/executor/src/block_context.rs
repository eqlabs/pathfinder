use std::{collections::HashMap, sync::Arc};

use blockifier::block_context::BlockContext;
use starknet_api::{core::PatriciaKey, hash::StarkHash, patricia_key};

use super::execution_state::ExecutionState;

use super::felt::IntoStarkFelt;

pub(super) fn construct_block_context(
    execution_state: &ExecutionState,
) -> anyhow::Result<BlockContext> {
    // NOTE: this is currently the same for _all_ networks
    let fee_token_address = starknet_api::core::ContractAddress(patricia_key!(
        "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
    ));

    let chain_id: Vec<_> = execution_state
        .chain_id
        .0
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let chain_id = String::from_utf8(chain_id)?;

    Ok(BlockContext {
        chain_id: starknet_api::core::ChainId(chain_id),
        block_number: starknet_api::block::BlockNumber(execution_state.block_number.get()),
        block_timestamp: starknet_api::block::BlockTimestamp(execution_state.block_timestamp.get()),
        sequencer_address: starknet_api::core::ContractAddress(
            PatriciaKey::try_from(execution_state.sequencer_address.0.into_starkfelt())
                .expect("Sequencer address overflow"),
        ),
        fee_token_address,
        vm_resource_fee_cost: Arc::new(default_resource_fee_costs()),
        gas_price: execution_state.gas_price.as_u128(),
        invoke_tx_max_n_steps: 1_000_000,
        validate_max_n_steps: 1_000_000,
        max_recursion_depth: 50,
    })
}

fn default_resource_fee_costs() -> HashMap<String, f64> {
    use cairo_vm::vm::runners::builtin_runner::{
        BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
        OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME,
        SIGNATURE_BUILTIN_NAME,
    };

    const N_STEPS_FEE_WEIGHT: f64 = 0.01;

    HashMap::from([
        (
            blockifier::abi::constants::N_STEPS_RESOURCE.to_string(),
            N_STEPS_FEE_WEIGHT,
        ),
        (HASH_BUILTIN_NAME.to_string(), 32.0 * N_STEPS_FEE_WEIGHT),
        (
            RANGE_CHECK_BUILTIN_NAME.to_string(),
            16.0 * N_STEPS_FEE_WEIGHT,
        ),
        (
            SIGNATURE_BUILTIN_NAME.to_string(),
            2048.0 * N_STEPS_FEE_WEIGHT,
        ),
        (BITWISE_BUILTIN_NAME.to_string(), 64.0 * N_STEPS_FEE_WEIGHT),
        (POSEIDON_BUILTIN_NAME.to_string(), 32.0 * N_STEPS_FEE_WEIGHT),
        (OUTPUT_BUILTIN_NAME.to_string(), 0.0 * N_STEPS_FEE_WEIGHT),
        (EC_OP_BUILTIN_NAME.to_string(), 1024.0 * N_STEPS_FEE_WEIGHT),
        (KECCAK_BUILTIN_NAME.to_string(), 2048.0 * N_STEPS_FEE_WEIGHT),
    ])
}
