use pathfinder_common::macro_prelude::*;
use pathfinder_common::prelude::*;
use pathfinder_storage::Storage;

use crate::context::{RpcContext, ETH_FEE_TOKEN_ADDRESS, STRK_FEE_TOKEN_ADDRESS};

pub const OPENZEPPELIN_ACCOUNT_CLASS_HASH: ClassHash =
    class_hash!("0x019cabebe31b9fb6bf5e7ce9a971bd7d06e9999e0b97eee943869141a46fd978");

pub async fn test_storage<F: FnOnce(StateUpdate) -> StateUpdate>(
    version: StarknetVersion,
    customize_state_update: F,
) -> (Storage, BlockHeader, ContractAddress, ContractAddress) {
    let storage = pathfinder_storage::StorageBuilder::in_memory_with_trie_pruning_and_pool_size(
        pathfinder_storage::TriePruneMode::Archive,
        std::num::NonZeroU32::new(2).unwrap(),
    )
    .unwrap();
    let mut db = storage.connection().unwrap();
    let tx = db.transaction().unwrap();

    // Empty genesis block
    let genesis = BlockHeader::builder()
        .number(BlockNumber::GENESIS)
        .timestamp(BlockTimestamp::new_or_panic(0))
        .starknet_version(version)
        .finalize_with_hash(BlockHash(felt!("0xb00")));
    tx.insert_block_header(&genesis).unwrap();

    // Declare a modified OpenZeppelin AccountUpgradeable account class that does
    // _no_ signature checks.
    let openzeppelin_account_class_definition = include_bytes!(
        "../fixtures/contracts/openzeppelin/openzeppelin_presets_AccountUpgradeable.\
         starknet_contract_class.json"
    );
    let openzeppelin_account_sierra_hash = SierraHash(OPENZEPPELIN_ACCOUNT_CLASS_HASH.0);
    let openzeppelin_account_casm_definition = include_bytes!(
        "../fixtures/contracts/openzeppelin/openzeppelin_presets_AccountUpgradeable.\
         compiled_contract_class.json"
    );
    let openzeppelin_account_casm_hash =
        casm_hash!("0x0224b815fab6827eb21993e02e45e532e5476af6536dcf1f7085989ba9dc5bf0");
    tx.insert_sierra_class_definition(
        &openzeppelin_account_sierra_hash,
        openzeppelin_account_class_definition,
        openzeppelin_account_casm_definition,
        &casm_hash_bytes!(b"casm hash blake"),
    )
    .unwrap();

    // Declare universal deployer class
    let universal_deployer_definition =
        include_bytes!("../fixtures/contracts/universal_deployer.json");
    let universal_deployer_class_hash =
        class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");
    tx.insert_cairo_class_definition(universal_deployer_class_hash, universal_deployer_definition)
        .unwrap();

    // Declare ERC20 fee token contract class
    let erc20_class_hash =
        starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION_CLASS_HASH;
    let erc20_class_definition =
        starknet_gateway_test_fixtures::class_definitions::ERC20_CONTRACT_DEFINITION;
    tx.insert_cairo_class_definition(erc20_class_hash, erc20_class_definition)
        .unwrap();

    let header = BlockHeader::child_builder(&genesis)
        .timestamp(BlockTimestamp::new_or_panic(1))
        .eth_l1_gas_price(GasPrice(1))
        .strk_l1_gas_price(GasPrice(2))
        .eth_l1_data_gas_price(GasPrice(2))
        .strk_l1_data_gas_price(GasPrice(2))
        .eth_l2_gas_price(GasPrice(1))
        .strk_l2_gas_price(GasPrice(1))
        .l1_da_mode(pathfinder_common::L1DataAvailabilityMode::Blob)
        .sequencer_address(sequencer_address!(
            "0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"
        ))
        .starknet_version(version)
        .finalize_with_hash(block_hash!("0xb01"));
    tx.insert_block_header(&header).unwrap();

    let account_contract_address = contract_address!("0xc01");
    let universal_deployer_address = contract_address!("0xc02");

    let account_balance_key =
        StorageAddress::from_map_name_and_key(b"ERC20_balances", account_contract_address.0);

    let state_update = StateUpdate::default()
        .with_block_hash(header.hash)
        .with_declared_cairo_class(universal_deployer_class_hash)
        .with_declared_cairo_class(erc20_class_hash)
        .with_declared_sierra_class(
            openzeppelin_account_sierra_hash,
            openzeppelin_account_casm_hash,
        )
        .with_deployed_contract(account_contract_address, OPENZEPPELIN_ACCOUNT_CLASS_HASH)
        .with_deployed_contract(universal_deployer_address, universal_deployer_class_hash)
        .with_deployed_contract(ETH_FEE_TOKEN_ADDRESS, erc20_class_hash)
        .with_deployed_contract(STRK_FEE_TOKEN_ADDRESS, erc20_class_hash)
        .with_storage_update(
            ETH_FEE_TOKEN_ADDRESS,
            account_balance_key,
            storage_value!("0x10000000000000000000000000000"),
        )
        .with_storage_update(
            STRK_FEE_TOKEN_ADDRESS,
            account_balance_key,
            storage_value!("0x10000000000000000000000000000"),
        );
    let state_update = customize_state_update(state_update);
    tx.insert_state_update(header.number, &state_update)
        .unwrap();

    tx.commit().unwrap();

    (
        storage,
        header,
        account_contract_address,
        universal_deployer_address,
    )
}

pub async fn test_context() -> (RpcContext, BlockHeader, ContractAddress, ContractAddress) {
    test_context_with_starknet_version(StarknetVersion::new(0, 13, 0, 0)).await
}

pub async fn test_context_with_starknet_version(
    version: StarknetVersion,
) -> (RpcContext, BlockHeader, ContractAddress, ContractAddress) {
    let (storage, header, account_contract_address, universal_deployer_address) =
        test_storage(version, |state_update| state_update).await;

    let context = RpcContext::for_tests().with_storage(storage);

    (
        context,
        header,
        account_contract_address,
        universal_deployer_address,
    )
}
