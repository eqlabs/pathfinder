use std::borrow::Cow;

use anyhow::Context;
use pathfinder_common::StarknetVersion;

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
    const V_0_11_1: semver::Version = semver::Version::new(0, 11, 1);
    const V_0_11_2: semver::Version = semver::Version::new(0, 11, 2);

    let result = std::panic::catch_unwind(|| {
        match version
            .parse_as_semver()
            .context("Deciding on compiler version")?
        {
            Some(v) if v > V_0_11_2 => v2::compile(definition),
            Some(v) if v > V_0_11_1 => v1_1_1::compile(definition),
            Some(v) if v > V_0_11_0 => v1_0_0_rc0::compile(definition),
            _ => v1_0_0_alpha6::compile(definition),
        }
    });

    result.unwrap_or_else(|e| Err(panic_error(e)))
}

/// Compile a Sierra class definition to CASM _with the latest compiler we support_.
///
/// Execution depends on our ability to compile a Sierra class to CASM for which we
/// always want to use the latest compiler.
pub fn compile_to_casm_with_latest_compiler(sierra_definition: &[u8]) -> anyhow::Result<Vec<u8>> {
    let definition = serde_json::from_slice::<FeederGatewayContractClass<'_>>(sierra_definition)
        .context("Parsing Sierra class")?;

    let result = std::panic::catch_unwind(|| v2::compile(definition));
    result.unwrap_or_else(|e| Err(panic_error(e)))
}

fn panic_error(e: Box<dyn std::any::Any>) -> anyhow::Error {
    match e.downcast_ref::<&str>() {
        Some(e) => anyhow::anyhow!("Compiler panicked: {}", e),
        None => match e.downcast_ref::<String>() {
            Some(e) => anyhow::anyhow!("Compiler panicked: {}", e),
            None => anyhow::anyhow!("Compiler panicked"),
        },
    }
}

mod v1_0_0_alpha6 {
    use anyhow::Context;
    use casm_compiler_v1_0_0_alpha6::allowed_libfuncs::{
        validate_compatible_sierra_version, ListSelector,
    };
    use casm_compiler_v1_0_0_alpha6::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_0_0_alpha6::contract_class::ContractClass;

    use super::FeederGatewayContractClass;

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
                casm_compiler_v1_0_0_alpha6::allowed_libfuncs::DEFAULT_EXPERIMENTAL_LIBFUNCS_LIST
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

mod v1_0_0_rc0 {
    use anyhow::Context;
    use casm_compiler_v1_0_0_rc0::allowed_libfuncs::{
        validate_compatible_sierra_version, ListSelector,
    };
    use casm_compiler_v1_0_0_rc0::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_0_0_rc0::contract_class::ContractClass;

    use super::FeederGatewayContractClass;

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
                casm_compiler_v1_0_0_rc0::allowed_libfuncs::DEFAULT_EXPERIMENTAL_LIBFUNCS_LIST
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

mod v1_1_1 {
    use anyhow::Context;
    use casm_compiler_v1_1_1::allowed_libfuncs::{
        validate_compatible_sierra_version, ListSelector,
    };
    use casm_compiler_v1_1_1::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_1_1::contract_class::ContractClass;

    use super::FeederGatewayContractClass;

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
                casm_compiler_v1_0_0_rc0::allowed_libfuncs::DEFAULT_EXPERIMENTAL_LIBFUNCS_LIST
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

// This compiler is backwards compatible with v1.1.
mod v2 {
    use anyhow::Context;
    use casm_compiler_v2::allowed_libfuncs::{validate_compatible_sierra_version, ListSelector};
    use casm_compiler_v2::casm_contract_class::CasmContractClass;
    use casm_compiler_v2::contract_class::ContractClass;

    use super::FeederGatewayContractClass;

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
                casm_compiler_v2::allowed_libfuncs::BUILTIN_ALL_LIBFUNCS_LIST.to_string(),
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

    mod starknet_v0_11_0 {
        use super::*;
        use starknet_gateway_test_fixtures::class_definitions::CAIRO_1_0_0_ALPHA5_SIERRA;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<FeederGatewayContractClass<'_>>(CAIRO_1_0_0_ALPHA5_SIERRA)
                    .unwrap();

            let _: casm_compiler_v1_0_0_rc0::contract_class::ContractClass =
                class.try_into().unwrap();
        }

        #[test]
        fn test_compile() {
            compile_to_casm(CAIRO_1_0_0_ALPHA5_SIERRA, &StarknetVersion::default()).unwrap();
        }
    }

    mod starknet_v0_11_1 {
        use super::*;
        use starknet_gateway_test_fixtures::class_definitions::CAIRO_1_0_0_RC0_SIERRA;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<FeederGatewayContractClass<'_>>(CAIRO_1_0_0_RC0_SIERRA)
                    .unwrap();

            let _: casm_compiler_v1_0_0_rc0::contract_class::ContractClass =
                class.try_into().unwrap();
        }

        #[test]
        fn test_compile() {
            compile_to_casm(CAIRO_1_0_0_RC0_SIERRA, &StarknetVersion::new(0, 11, 1)).unwrap();
        }
    }

    mod starknet_v0_11_2_onwards {
        use super::*;
        use starknet_gateway_test_fixtures::class_definitions::{
            CAIRO_1_1_0_RC0_SIERRA, CAIRO_2_0_0_STACK_OVERFLOW,
        };

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<FeederGatewayContractClass<'_>>(CAIRO_1_1_0_RC0_SIERRA)
                    .unwrap();

            let _: casm_compiler_v2::contract_class::ContractClass = class.try_into().unwrap();
        }

        #[test]
        fn test_compile() {
            compile_to_casm(CAIRO_1_1_0_RC0_SIERRA, &StarknetVersion::new(0, 11, 2)).unwrap();
        }

        #[test]
        fn regression_stack_overflow() {
            // This class caused a stack-overflow in v2 compilers <= v2.0.1
            compile_to_casm(CAIRO_2_0_0_STACK_OVERFLOW, &StarknetVersion::new(0, 12, 0)).unwrap();
        }
    }
}
