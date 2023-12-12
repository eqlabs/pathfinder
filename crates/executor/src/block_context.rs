use std::{collections::HashMap, sync::Arc};

use blockifier::block_context::BlockContext;
use pathfinder_common::{contract_address, ContractAddress};
use starknet_api::core::PatriciaKey;

use super::execution_state::ExecutionState;

use super::felt::IntoStarkFelt;

// NOTE: this is currently the same for _all_ networks
pub const ETH_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
pub const STRK_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

pub(super) fn construct_block_context(
    execution_state: &ExecutionState<'_>,
) -> anyhow::Result<BlockContext> {
    let eth_fee_token_address = starknet_api::core::ContractAddress(
        PatriciaKey::try_from(ETH_FEE_TOKEN_ADDRESS.0.into_starkfelt())
            .expect("ETH fee token address overflow"),
    );
    let strk_fee_token_address = starknet_api::core::ContractAddress(
        PatriciaKey::try_from(STRK_FEE_TOKEN_ADDRESS.0.into_starkfelt())
            .expect("STRK fee token address overflow"),
    );

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
        block_number: starknet_api::block::BlockNumber(execution_state.header.number.get()),
        block_timestamp: starknet_api::block::BlockTimestamp(
            execution_state.header.timestamp.get(),
        ),
        sequencer_address: starknet_api::core::ContractAddress(
            PatriciaKey::try_from(execution_state.header.sequencer_address.0.into_starkfelt())
                .expect("Sequencer address overflow"),
        ),
        fee_token_addresses: blockifier::block_context::FeeTokenAddresses {
            strk_fee_token_address,
            eth_fee_token_address,
        },
        vm_resource_fee_cost: Arc::new(default_resource_fee_costs()),
        gas_prices: blockifier::block_context::GasPrices {
            eth_l1_gas_price: execution_state.header.eth_l1_gas_price.0,
            strk_l1_gas_price: execution_state.header.strk_l1_gas_price.0,
        },
        invoke_tx_max_n_steps: 3_000_000,
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

    const N_STEPS_FEE_WEIGHT: f64 = 0.005;

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
