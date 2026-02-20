use pathfinder_class_hash::compute_sierra_class_hash;
use pathfinder_class_hash::json::SierraContractDefinition;
use pathfinder_common::class_definition::Sierra;
use pathfinder_common::{state_update, CasmHash, SierraHash};
use pathfinder_compiler::{casm_class_hash_v2, compile_to_casm_deser};
use pathfinder_storage::Transaction;

/// Predeclare a Cairo1 class:
/// - compile sierra bytecode into casm,
/// - compute casm hash v2,
/// - compute sierra class hash if `class_hash` is `None`,
/// - insert sierra and casm into the DB and update the state update, which
///   should be inserted into the DB when all predeclarations and predeployments
///   are done.
pub fn predeclare(
    transaction: &Transaction<'_>,
    state_update: &mut state_update::StateUpdateData,
    sierra_class_ser: &[u8],
    class_hash: Option<SierraHash>,
) -> anyhow::Result<()> {
    let PrepocessedSierra {
        sierra_class_hash,

        sierra_class_ser,
        casm_hash_v2,
        casm,
        ..
    } = preprocess_sierra(sierra_class_ser, class_hash)?;

    let overwritten = state_update
        .declared_sierra_classes
        .insert(sierra_class_hash, casm_hash_v2)
        .is_some();
    anyhow::ensure!(
        !overwritten,
        "Predeclaring class with hash {sierra_class_hash} would overwrite an existing class \
         declaration"
    );

    transaction.insert_sierra_class_definition(
        &sierra_class_hash,
        &sierra_class_ser,
        &casm,
        &casm_hash_v2,
    )?;
    Ok(())
}

#[derive(Debug)]
pub struct PrepocessedSierra {
    // Class hash
    pub sierra_class_hash: SierraHash,
    // Deserialized into a format compatible with p2p, and hence the validator (for execution)
    pub cairo1_class_p2p: p2p_proto::class::Cairo1Class,
    // Re-serialized into a storage-compatible format
    pub sierra_class_ser: Vec<u8>,
    // Casm hash v2
    pub casm_hash_v2: CasmHash,
    // Casm - compiled from sierra
    pub casm: Vec<u8>,
}

/// Preprocess a Sierra class definition. Class hash is computed if not
/// provided.
pub fn preprocess_sierra<'a>(
    sierra_class_ser: &'a [u8],
    sierra_class_hash: Option<SierraHash>,
) -> anyhow::Result<PrepocessedSierra> {
    let sierra_class_hash = sierra_class_hash.unwrap_or({
        let compat::SierraContractDefinition {
            abi,
            sierra_program,
            contract_class_version,
            entry_points_by_type,
        } = serde_json::from_slice(sierra_class_ser).unwrap();
        let sierra_class_def = SierraContractDefinition {
            abi: serde_json::to_string(&abi).unwrap().into(),
            sierra_program,
            contract_class_version,
            entry_points_by_type,
        };

        SierraHash(compute_sierra_class_hash(sierra_class_def)?.0)
    });

    let compat::Sierra {
        abi,
        sierra_program,
        contract_class_version,
        entry_points_by_type,
    } = serde_json::from_slice(sierra_class_ser).unwrap();
    let sierra_class_def = Sierra {
        abi: serde_json::to_string(&abi).unwrap().into(),
        sierra_program,
        contract_class_version,
        entry_points_by_type,
    };

    // Re-serialize into a storage-compatible format
    let sierra_class_ser = serde_json::to_vec(&sierra_class_def).unwrap();
    let sierra_class_p2p = sierra_def_to_p2p_cairo1(&sierra_class_def);
    let casm = compile_to_casm_deser(sierra_class_def).unwrap();

    let casm_hash_v2 = casm_class_hash_v2(&casm).unwrap();

    Ok(PrepocessedSierra {
        sierra_class_hash,
        cairo1_class_p2p: sierra_class_p2p,
        sierra_class_ser,
        casm_hash_v2,
        casm,
    })
}

fn sierra_def_to_p2p_cairo1(sierra: &Sierra<'_>) -> p2p_proto::class::Cairo1Class {
    let Sierra {
        abi,
        sierra_program,
        contract_class_version,
        entry_points_by_type,
    } = sierra;
    p2p_proto::class::Cairo1Class {
        abi: abi.clone().into_owned(),
        entry_points: p2p_proto::class::Cairo1EntryPoints {
            externals: entry_points_by_type
                .external
                .iter()
                .map(|x| p2p_proto::class::SierraEntryPoint {
                    index: x.function_idx,
                    selector: x.selector.0,
                })
                .collect(),
            l1_handlers: entry_points_by_type
                .l1_handler
                .iter()
                .map(|x| p2p_proto::class::SierraEntryPoint {
                    index: x.function_idx,
                    selector: x.selector.0,
                })
                .collect(),
            constructors: entry_points_by_type
                .constructor
                .iter()
                .map(|x| p2p_proto::class::SierraEntryPoint {
                    index: x.function_idx,
                    selector: x.selector.0,
                })
                .collect(),
        },
        program: sierra_program.clone(),
        contract_class_version: contract_class_version.clone().into_owned(),
    }
}

mod compat {
    use std::borrow::Cow;
    use std::collections::HashMap;

    use pathfinder_common::class_definition::{
        EntryPointType,
        SelectorAndFunctionIndex,
        SierraEntryPoints,
    };
    use pathfinder_crypto::Felt;
    use serde::Deserialize;

    /// Necessary for class hash computation, as the
    /// [`compute_sierra_class_hash`] function expects a different struct
    /// than the one used for deserialization of the class definition.
    #[derive(Debug, Deserialize)]
    pub struct SierraContractDefinition<'a> {
        #[serde(borrow)]
        pub abi: Cow<'a, serde_json::value::RawValue>,
        pub sierra_program: Vec<Felt>,
        #[serde(borrow)]
        pub contract_class_version: Cow<'a, str>,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndFunctionIndex>>,
    }

    /// Necessary for compilation into casm, as the [`compile_to_casm_deser`]
    /// function expects a different struct than the one used for
    /// deserialization of the class definition.
    #[derive(Debug, Deserialize)]
    pub struct Sierra<'a> {
        #[serde(borrow)]
        pub abi: Cow<'a, serde_json::value::RawValue>,
        pub sierra_program: Vec<Felt>,
        #[serde(borrow)]
        pub contract_class_version: Cow<'a, str>,
        pub entry_points_by_type: SierraEntryPoints,
    }
}
