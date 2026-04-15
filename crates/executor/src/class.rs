use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use pathfinder_common::class_definition::{SerializedCasmDefinition, SerializedOpaqueClassDefinition};

pub fn parse_deprecated_class_definition(
    definition: SerializedOpaqueClassDefinition,
) -> anyhow::Result<starknet_api::contract_class::ContractClass> {
    let class: starknet_api::deprecated_contract_class::ContractClass =
        serde_json::from_slice(definition.as_bytes())?;

    Ok(starknet_api::contract_class::ContractClass::V0(class))
}

pub fn parse_casm_definition(
    casm_definition: SerializedCasmDefinition,
    sierra_version: starknet_api::contract_class::SierraVersion,
) -> anyhow::Result<starknet_api::contract_class::ContractClass> {
    let class: CasmContractClass = serde_json::from_slice(casm_definition.as_bytes())?;

    Ok(starknet_api::contract_class::ContractClass::V1((
        class,
        sierra_version,
    )))
}
