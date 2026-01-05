use anyhow::Context;
use pathfinder_common::{class_definition, felt, CasmHash};
use pathfinder_crypto::Felt;

/// Compile a serialized Sierra class definition into CASM.
///
/// The class representation expected by the compiler doesn't match the
/// representation used by the feeder gateway for Sierra classes, so we have to
/// convert the JSON to something that can be parsed into the expected input
/// format for the compiler.
pub fn compile_to_casm_ser(sierra_definition: &[u8]) -> anyhow::Result<Vec<u8>> {
    serde_json::from_slice::<class_definition::Sierra<'_>>(sierra_definition)
        .context("Parsing Sierra class")
        .map(compile_to_casm_deser)?
        .context("Compiling to CASM")
}

/// Compile a deserialized Sierra class definition into CASM.
///
/// The class representation expected by the compiler doesn't match the
/// representation used by the feeder gateway for Sierra classes, so we have to
/// convert the JSON to something that can be parsed into the expected input
/// format for the compiler.
pub fn compile_to_casm_deser(definition: class_definition::Sierra<'_>) -> anyhow::Result<Vec<u8>> {
    let sierra_version =
        parse_sierra_version(&definition.sierra_program).context("Parsing Sierra version")?;

    let started_at = std::time::Instant::now();

    let result = std::panic::catch_unwind(|| match sierra_version {
        SierraVersion(0, 1, 0) => v1_0_0_alpha6::compile(definition),
        SierraVersion(1, 0, 0) => v1_0_0_rc0::compile(definition),
        SierraVersion(1, 1, 0) => v1_1_1::compile(definition),
        _ => v2::compile(definition),
    });

    tracing::trace!(elapsed=?started_at.elapsed(), "Sierra class compilation finished");

    result.unwrap_or_else(|e| Err(panic_error(e)))
}

fn panic_error(e: Box<dyn std::any::Any>) -> anyhow::Error {
    match e.downcast_ref::<&str>() {
        Some(e) => anyhow::anyhow!("Compiler panicked: {e}"),
        None => match e.downcast_ref::<String>() {
            Some(e) => anyhow::anyhow!("Compiler panicked: {e}"),
            None => anyhow::anyhow!("Compiler panicked"),
        },
    }
}

#[derive(Debug, PartialEq)]
struct SierraVersion(u64, u64, u64);

/// Parse Sierra version from a [Felt] slice representation of the program.
///
/// Sierra programs contain the version number in two possible formats.
/// For pre-1.0-rc0 Cairo versions the program contains the Sierra version
/// "0.1.0" as a shortstring in its first Felt (0x302e312e30 = "0.1.0").
/// For all subsequent versions the version number is the first three felts
/// representing the three parts of a semantic version number.
fn parse_sierra_version(program: &[Felt]) -> anyhow::Result<SierraVersion> {
    const VERSION_0_1_0_AS_SHORTSTRING: Felt = felt!("0x302e312e30");

    match program {
        [VERSION_0_1_0_AS_SHORTSTRING, ..] => Ok(SierraVersion(0, 1, 0)),
        [a, b, c, ..] => {
            let (a, b, c) = ((*a).try_into()?, (*b).try_into()?, (*c).try_into()?);

            Ok(SierraVersion(a, b, c))
        }
        _ => Err(anyhow::anyhow!("Invalid version felts")),
    }
}

/// Parse CASM class definition and return _Blake2_ CASM class hash.
///
/// Uses the _latest_ compiler for the parsing and starknet_api for the hashing.
pub fn casm_class_hash_v2(casm_definition: &[u8]) -> anyhow::Result<CasmHash> {
    v2::casm_class_hash_v2(casm_definition)
}

mod v1_0_0_alpha6 {
    use anyhow::Context;
    use casm_compiler_v1_0_0_alpha6::allowed_libfuncs::{
        validate_compatible_sierra_version,
        ListSelector,
    };
    use casm_compiler_v1_0_0_alpha6::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_0_0_alpha6::contract_class::ContractClass;
    use pathfinder_common::class_definition;

    pub(super) fn pathfinder_to_starknet_contract_class(
        definition: class_definition::Sierra<'_>,
    ) -> Result<ContractClass, serde_json::Error> {
        let json = serde_json::json!({
            "abi": [],
            "sierra_program": definition.sierra_program,
            "contract_class_version": definition.contract_class_version,
            "entry_points_by_type": definition.entry_points_by_type,
        });
        serde_json::from_value::<ContractClass>(json)
    }

    pub(super) fn compile(definition: class_definition::Sierra<'_>) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = pathfinder_to_starknet_contract_class(definition)
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
        validate_compatible_sierra_version,
        ListSelector,
    };
    use casm_compiler_v1_0_0_rc0::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_0_0_rc0::contract_class::ContractClass;
    use pathfinder_common::class_definition;

    pub(super) fn pathfinder_to_starknet_contract_class(
        definition: class_definition::Sierra<'_>,
    ) -> Result<ContractClass, serde_json::Error> {
        let json = serde_json::json!({
            "abi": [],
            "sierra_program": definition.sierra_program,
            "contract_class_version": definition.contract_class_version,
            "entry_points_by_type": definition.entry_points_by_type,
        });
        serde_json::from_value::<ContractClass>(json)
    }

    pub(super) fn compile(definition: class_definition::Sierra<'_>) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = pathfinder_to_starknet_contract_class(definition)
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
        validate_compatible_sierra_version,
        ListSelector,
    };
    use casm_compiler_v1_1_1::casm_contract_class::CasmContractClass;
    use casm_compiler_v1_1_1::contract_class::ContractClass;
    use pathfinder_common::class_definition;

    pub(super) fn pathfinder_to_starknet_contract_class(
        definition: class_definition::Sierra<'_>,
    ) -> Result<ContractClass, serde_json::Error> {
        let json = serde_json::json!({
            "abi": [],
            "sierra_program": definition.sierra_program,
            "contract_class_version": definition.contract_class_version,
            "entry_points_by_type": definition.entry_points_by_type,
        });
        serde_json::from_value::<ContractClass>(json)
    }

    pub(super) fn compile(definition: class_definition::Sierra<'_>) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = pathfinder_to_starknet_contract_class(definition)
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
    use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
    use cairo_lang_starknet_classes::contract_class::ContractClass;

    use super::CasmHash;

    pub(super) fn pathfinder_to_starknet_contract_class(
        definition: crate::class_definition::Sierra<'_>,
    ) -> Result<ContractClass, serde_json::Error> {
        let json = serde_json::json!({
            "abi": [],
            "sierra_program": definition.sierra_program,
            "contract_class_version": definition.contract_class_version,
            "entry_points_by_type": definition.entry_points_by_type,
        });
        serde_json::from_value::<ContractClass>(json)
    }

    pub(super) fn compile(
        definition: crate::class_definition::Sierra<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let sierra_class: ContractClass = pathfinder_to_starknet_contract_class(definition)
            .context("Converting to Sierra class")?;

        sierra_class
            .validate_version_compatible(
                cairo_lang_starknet_classes::allowed_libfuncs::ListSelector::ListName(
                    cairo_lang_starknet_classes::allowed_libfuncs::BUILTIN_ALL_LIBFUNCS_LIST
                        .to_string(),
                ),
            )
            .context("Validating Sierra class")?;

        // TODO: determine `max_bytecode_size`
        let casm_class = CasmContractClass::from_contract_class(sierra_class, true, usize::MAX)
            .context("Compiling to CASM")?;
        let casm_definition = serde_json::to_vec(&casm_class)?;

        Ok(casm_definition)
    }

    pub(super) fn casm_class_hash_v2(casm_definition: &[u8]) -> anyhow::Result<CasmHash> {
        let ccc: CasmContractClass =
            serde_json::from_slice(casm_definition).context("Deserializing CASM class")?;

        use starknet_api::contract_class::compiled_class_hash::{
            HashVersion,
            HashableCompiledClass,
        };

        let casm_hash_v2 = ccc.hash(&HashVersion::V2);

        let casm_hash_v2 = CasmHash(pathfinder_crypto::Felt::from_be_bytes(
            casm_hash_v2.0.to_bytes_be(),
        )?);

        Ok(casm_hash_v2)
    }
}

#[cfg(test)]
mod tests {
    use super::compile_to_casm_ser;

    mod parse_version {
        use pathfinder_common::class_definition;
        use rstest::rstest;
        use starknet_gateway_test_fixtures::class_definitions::{
            CAIRO_1_0_0_ALPHA5_SIERRA,
            CAIRO_1_0_0_RC0_SIERRA,
            CAIRO_1_1_0_RC0_SIERRA,
            CAIRO_2_0_0_STACK_OVERFLOW,
        };

        use super::super::{parse_sierra_version, SierraVersion};

        #[rstest]
        #[case(CAIRO_1_0_0_ALPHA5_SIERRA, SierraVersion(0, 1, 0))]
        #[case(CAIRO_1_0_0_RC0_SIERRA, SierraVersion(1, 0, 0))]
        #[case(CAIRO_1_1_0_RC0_SIERRA, SierraVersion(1, 1, 0))]
        #[case(CAIRO_2_0_0_STACK_OVERFLOW, SierraVersion(1, 2, 0))]
        fn parse_version(#[case] sierra_json: &[u8], #[case] expected_version: SierraVersion) {
            let sierra =
                serde_json::from_slice::<class_definition::Sierra<'_>>(sierra_json).unwrap();
            let sierra_version = parse_sierra_version(&sierra.sierra_program).unwrap();
            assert_eq!(sierra_version, expected_version);
        }
    }

    mod starknet_v0_11_0 {
        use pathfinder_common::class_definition;
        use starknet_gateway_test_fixtures::class_definitions::CAIRO_1_0_0_ALPHA5_SIERRA;

        use super::*;
        use crate::v1_0_0_rc0::pathfinder_to_starknet_contract_class;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<class_definition::Sierra<'_>>(CAIRO_1_0_0_ALPHA5_SIERRA)
                    .unwrap();

            let _: casm_compiler_v1_0_0_rc0::contract_class::ContractClass =
                pathfinder_to_starknet_contract_class(class).unwrap();
        }

        #[test]
        fn test_compile_ser() {
            compile_to_casm_ser(CAIRO_1_0_0_ALPHA5_SIERRA).unwrap();
        }
    }

    mod starknet_v0_11_1 {
        use pathfinder_common::class_definition;
        use starknet_gateway_test_fixtures::class_definitions::CAIRO_1_0_0_RC0_SIERRA;

        use super::*;
        use crate::v1_0_0_rc0::pathfinder_to_starknet_contract_class;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<class_definition::Sierra<'_>>(CAIRO_1_0_0_RC0_SIERRA)
                    .unwrap();

            let _: casm_compiler_v1_0_0_rc0::contract_class::ContractClass =
                pathfinder_to_starknet_contract_class(class).unwrap();
        }

        #[test]
        fn test_compile_ser() {
            compile_to_casm_ser(CAIRO_1_0_0_RC0_SIERRA).unwrap();
        }
    }

    mod starknet_v0_11_2_onwards {
        use pathfinder_common::class_definition;
        use starknet_gateway_test_fixtures::class_definitions::{
            CAIRO_1_1_0_RC0_SIERRA,
            CAIRO_2_0_0_STACK_OVERFLOW,
        };

        use super::*;
        use crate::v2::pathfinder_to_starknet_contract_class;

        #[test]
        fn test_feeder_gateway_contract_conversion() {
            let class =
                serde_json::from_slice::<class_definition::Sierra<'_>>(CAIRO_1_1_0_RC0_SIERRA)
                    .unwrap();

            let _: cairo_lang_starknet_classes::contract_class::ContractClass =
                pathfinder_to_starknet_contract_class(class).unwrap();
        }

        #[test]
        fn test_compile_ser() {
            compile_to_casm_ser(CAIRO_1_1_0_RC0_SIERRA).unwrap();
        }

        #[test]
        fn regression_stack_overflow() {
            // This class caused a stack-overflow in v2 compilers <= v2.0.1
            compile_to_casm_ser(CAIRO_2_0_0_STACK_OVERFLOW).unwrap();
        }
    }
}
