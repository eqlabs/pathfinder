use std::borrow::Cow;

use anyhow::Context;
use cairo_lang_starknet::allowed_libfuncs::{validate_compatible_sierra_version, ListSelector};
use cairo_lang_starknet::{casm_contract_class::CasmContractClass, contract_class::ContractClass};

pub const COMPILER_VERSION: &str = env!("SIERRA_CASM_COMPILER_VERSION");

/// Compile a Sierra class definition into CASM.
///
/// The class representation expected by the compiler doesn't match the representation used
/// by the feeder gateway for Sierra classes, so we have to convert the JSON to something
/// that can be parsed into the expected input format for the compiler.
pub fn compile_to_casm(sierra_definition: &[u8]) -> anyhow::Result<Vec<u8>> {
    let feeder_gateway_class_definition =
        serde_json::from_slice::<FeederGatewayContractClass<'_>>(sierra_definition)
            .context("Parsing Sierra class")?;
    let sierra_class: ContractClass = feeder_gateway_class_definition
        .try_into()
        .context("Converting to Sierra class")?;

    validate_compatible_sierra_version(&sierra_class, ListSelector::DefaultList)?;

    let casm_class =
        CasmContractClass::from_contract_class(sierra_class).context("Compiling to CASM")?;
    let casm_definition = serde_json::to_vec(&casm_class)?;

    Ok(casm_definition)
}

impl<'a> TryFrom<FeederGatewayContractClass<'a>> for ContractClass {
    type Error = serde_json::Error;

    fn try_from(value: FeederGatewayContractClass<'a>) -> Result<Self, Self::Error> {
        let json = serde_json::json!({
            "abi": [],
            "sierra_program": value.sierra_program,
            "contract_class_version": value.contract_class_version,
            "entry_points_by_type": value.entry_points_by_type,
        });
        serde_json::from_value::<ContractClass>(json)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FeederGatewayContractClass<'a> {
    #[serde(borrow)]
    pub abi: Cow<'a, str>,

    #[serde(borrow)]
    pub sierra_program: &'a serde_json::value::RawValue,

    #[serde(borrow)]
    pub contract_class_version: &'a serde_json::value::RawValue,

    #[serde(borrow)]
    pub entry_points_by_type: &'a serde_json::value::RawValue,
}

#[cfg(test)]
mod tests {
    use super::{compile_to_casm, FeederGatewayContractClass};

    use starknet_gateway_test_fixtures::zstd_compressed_contracts::CAIRO_0_11_SIERRA;

    #[test]
    fn test_feeder_gateway_contract_conversion() {
        let contract_definition = zstd::decode_all(CAIRO_0_11_SIERRA).unwrap();

        let class =
            serde_json::from_slice::<FeederGatewayContractClass<'_>>(&contract_definition).unwrap();

        let _: super::ContractClass = class.try_into().unwrap();
    }

    #[test]
    fn test_compile() {
        let contract_definition = zstd::decode_all(CAIRO_0_11_SIERRA).unwrap();
        compile_to_casm(&contract_definition).unwrap();
    }
}
