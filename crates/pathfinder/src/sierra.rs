use std::borrow::Cow;

use anyhow::Context;
use pathfinder_common::StarknetVersion;

pub const COMPILER_VERSION: &str = env!("SIERRA_CASM_COMPILER_VERSION");

/// Compile a Sierra class definition into CASM.
///
/// The class representation expected by the compiler doesn't match the representation used
/// by the feeder gateway for Sierra classes, so we have to convert the JSON to something
/// that can be parsed into the expected input format for the compiler.
pub fn compile_to_casm(
    sierra_definition: &[u8],
    version: &StarknetVersion,
) -> anyhow::Result<Vec<u8>> {
    let definition = serde_json::from_slice::<FeederGatewayContractClass<'_>>(sierra_definition)
        .context("Parsing Sierra class")?;

    const V_0_11_0: semver::Version = semver::Version::new(0, 11, 0);

    match version
        .parse_as_semver()
        .context("Deciding on compiler version")?
    {
        Some(v) if v > V_0_11_0 => post_0_11_1::compile(definition),
        _ => pre_0_11_1::compile(definition),
    }
}

mod pre_0_11_1 {
    use anyhow::Context;
    use casm_compiler_historic::allowed_libfuncs::{
        validate_compatible_sierra_version, ListSelector,
    };
    use casm_compiler_historic::casm_contract_class::CasmContractClass;
    use casm_compiler_historic::contract_class::ContractClass;

    use crate::sierra::FeederGatewayContractClass;

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

    pub(super) fn compile(definition: FeederGatewayContractClass<'_>) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = definition
            .try_into()
            .context("Converting to Sierra class")?;

        validate_compatible_sierra_version(
            &sierra_class,
            ListSelector::ListName(
                casm_compiler_historic::allowed_libfuncs::DEFAULT_EXPERIMENTAL_LIBFUNCS_LIST
                    .to_string(),
            ),
        )
        .context("Validating Sierra class")?;

        let casm_class = CasmContractClass::from_contract_class(sierra_class, true)
            .context("Compiling to CASM")?;
        let casm_definition = serde_json::to_vec(&casm_class)?;

        Ok(casm_definition)
    }
}

mod post_0_11_1 {
    use anyhow::Context;
    use casm_compiler::allowed_libfuncs::{validate_compatible_sierra_version, ListSelector};
    use casm_compiler::casm_contract_class::CasmContractClass;
    use casm_compiler::contract_class::ContractClass;

    use crate::sierra::FeederGatewayContractClass;

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

    pub(super) fn compile(definition: FeederGatewayContractClass<'_>) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = definition
            .try_into()
            .context("Converting to Sierra class")?;

        validate_compatible_sierra_version(
            &sierra_class,
            ListSelector::ListName(
                casm_compiler_historic::allowed_libfuncs::DEFAULT_EXPERIMENTAL_LIBFUNCS_LIST
                    .to_string(),
            ),
        )
        .context("Validating Sierra class")?;

        let casm_class = CasmContractClass::from_contract_class(sierra_class, true)
            .context("Compiling to CASM")?;
        let casm_definition = serde_json::to_vec(&casm_class)?;

        Ok(casm_definition)
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

    use pathfinder_common::StarknetVersion;

    mod pre_v0_11_0 {
        use super::*;
        use starknet_gateway_test_fixtures::zstd_compressed_contracts::CAIRO_1_0_0_ALPHA5_SIERRA;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let contract_definition = zstd::decode_all(CAIRO_1_0_0_ALPHA5_SIERRA).unwrap();

            let class =
                serde_json::from_slice::<FeederGatewayContractClass<'_>>(&contract_definition)
                    .unwrap();

            let _: casm_compiler_historic::contract_class::ContractClass =
                class.try_into().unwrap();
        }

        #[test]
        fn test_compile() {
            let contract_definition = zstd::decode_all(CAIRO_1_0_0_ALPHA5_SIERRA).unwrap();
            compile_to_casm(&contract_definition, &StarknetVersion::default()).unwrap();
        }
    }

    mod post_v0_11_0 {
        use super::*;
        use starknet_gateway_test_fixtures::zstd_compressed_contracts::CAIRO_1_0_0_RC0_SIERRA;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let contract_definition = zstd::decode_all(CAIRO_1_0_0_RC0_SIERRA).unwrap();

            let class =
                serde_json::from_slice::<FeederGatewayContractClass<'_>>(&contract_definition)
                    .unwrap();

            let _: casm_compiler::contract_class::ContractClass = class.try_into().unwrap();
        }

        #[test]
        fn test_compile() {
            let contract_definition = zstd::decode_all(CAIRO_1_0_0_RC0_SIERRA).unwrap();
            compile_to_casm(&contract_definition, &StarknetVersion::new(0, 11, 1)).unwrap();
        }
    }
}
