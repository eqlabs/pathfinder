use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use starknet_api::contract_class::SierraVersion;

pub fn parse_deprecated_class_definition(
    definition: Vec<u8>,
) -> anyhow::Result<starknet_api::contract_class::ContractClass> {
    let definition = String::from_utf8(definition)?;

    let class: starknet_api::deprecated_contract_class::ContractClass =
        serde_json::from_str(&definition)?;

    Ok(starknet_api::contract_class::ContractClass::V0(class))
}

pub fn parse_casm_definition(
    casm_definition: Vec<u8>,
) -> anyhow::Result<starknet_api::contract_class::ContractClass> {
    // TODO: Is this the right way to extract the sierra version?
    let sierra_version = SierraVersion::extract_from_program(&casm_definition)?;
    let casm_definition = String::from_utf8(casm_definition)?;

    let class: CasmContractClass = serde_json::from_str(&casm_definition)?;

    Ok(starknet_api::contract_class::ContractClass::V1((
        class,
        sierra_version,
    )))
}
