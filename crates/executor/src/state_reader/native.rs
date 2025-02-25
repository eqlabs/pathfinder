use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::execution::native::contract_class::NativeCompiledClassV1;
use blockifier::state::errors::StateError;
use cairo_native::executor::AotContractExecutor;
use cairo_vm::types::errors::program_errors::ProgramError;
use pathfinder_common::ClassHash;
use starknet_api::contract_class::SierraVersion;

pub fn sierra_class_as_native(
    class_hash: ClassHash,
    sierra_version: SierraVersion,
    class_definition: Vec<u8>,
    casm_definition: Vec<u8>,
) -> Result<RunnableCompiledClass, StateError> {
    let mut class_path = std::env::temp_dir();
    class_path.push(format!("native_class_{}", class_hash));

    let contract_executor = if class_path.is_file() {
        AotContractExecutor::from_path(&class_path)
            .map_err(|e| StateError::StateReadError(format!("Error loading native class: {e}")))?
            .expect("No locking issues with a single process")
    } else {
        let mut sierra_definition: serde_json::Value = serde_json::from_slice(&class_definition)
            .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;
        let sierra_abi_str = sierra_definition
            .get("abi")
            .ok_or_else(|| StateError::StateReadError("Sierra ABI is missing".to_owned()))?
            .as_str()
            .ok_or_else(|| StateError::StateReadError("Sierra ABI is not a string".to_owned()))?;
        sierra_definition["abi"] = serde_json::from_str(sierra_abi_str)
            .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;

        let sierra_class: cairo_lang_starknet_classes::contract_class::ContractClass =
            serde_json::from_value(sierra_definition)
                .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;

        let sierra_program = sierra_class.extract_sierra_program().map_err(|e| {
            StateError::StateReadError(format!(
                "Error parsing Sierra
                program: {}",
                e
            ))
        })?;

        let mut class_path = std::env::temp_dir();
        class_path.push(format!("native_class_{}", class_hash));
        let version_id = cairo_lang_starknet_classes::compiler_version::VersionId {
            major: sierra_version.major as usize,
            minor: sierra_version.minor as usize,
            patch: sierra_version.patch as usize,
        };
        AotContractExecutor::new_into(
            &sierra_program,
            &sierra_class.entry_points_by_type,
            version_id,
            class_path,
            cairo_native::OptLevel::Default,
        )
        .map_err(|e| StateError::StateReadError(format!("Error compiling native class: {e}")))?
        .expect("No locking issues with a single process")
    };

    let casm_definition = String::from_utf8(casm_definition).map_err(|error| {
        StateError::StateReadError(format!("Class definition is not valid UTF-8: {}", error))
    })?;

    let casm_class = blockifier::execution::contract_class::CompiledClassV1::try_from_json_string(
        &casm_definition,
        sierra_version,
    )
    .map_err(StateError::ProgramError)?;

    let runnable_class =
        RunnableCompiledClass::V1Native(NativeCompiledClassV1::new(contract_executor, casm_class));

    Ok(runnable_class)
}
