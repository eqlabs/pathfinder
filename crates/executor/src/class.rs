pub fn parse_deprecated_class_definition(
    definition: Vec<u8>,
) -> anyhow::Result<blockifier::execution::contract_class::ContractClass> {
    let definition = String::from_utf8(definition)?;

    let class =
        blockifier::execution::contract_class::ContractClassV0::try_from_json_string(&definition)?;

    Ok(blockifier::execution::contract_class::ContractClass::V0(
        class,
    ))
}

pub fn parse_casm_definition(
    casm_definition: Vec<u8>,
) -> anyhow::Result<blockifier::execution::contract_class::ContractClass> {
    let casm_definition = String::from_utf8(casm_definition)?;

    let class = blockifier::execution::contract_class::ContractClassV1::try_from_json_string(
        &casm_definition,
    )?;

    Ok(blockifier::execution::contract_class::ContractClass::V1(
        class,
    ))
}
