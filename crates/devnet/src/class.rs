use pathfinder_class_hash::json::{CairoContractDefinition, SierraContractDefinition};
use pathfinder_class_hash::{
    compute_cairo_class_hash,
    compute_sierra_class_hash,
    RawCairoContractDefinition,
};
use pathfinder_common::class_definition::Sierra;
use pathfinder_common::{state_update, ClassHash, SierraHash};
use pathfinder_compiler::{casm_class_hash_v2, compile_to_casm_deser};
use pathfinder_storage::Transaction;

use crate::fixtures::Class;

/// Predeclare Cairo0 or Cairo1 class, ie. insert class definition into the DB
/// and update the state update, which should be inserted into the DB when all
/// predeclarations and predeployments are done. If `class_hash` is `None`, it
/// will be computed from the class definition.
///
/// Note: Cairo1 class will also be compiled into casm and the casm class hash
/// will be computed and stored in the state update.
pub fn predeclare(
    transaction: &Transaction<'_>,
    state_update: &mut state_update::StateUpdateData,
    class_ser: Class,
    class_hash: Option<ClassHash>,
) -> anyhow::Result<()> {
    match class_ser {
        Class::Cairo0(cairo_class_ser) => {
            cairo(transaction, state_update, cairo_class_ser, class_hash)
        }
        Class::Cairo1(sierra_class_ser) => {
            sierra(transaction, state_update, sierra_class_ser, class_hash)
        }
    }
}

/// Predeclare Cairo0 class, ie. insert class definition into the DB and update
/// the state update, which should be inserted into the DB when all
/// predeclarations and predeployments are done. If `class_hash` is `None`, it
/// will be computed from the class definition.
fn cairo(
    transaction: &Transaction<'_>,
    state_update: &mut state_update::StateUpdateData,
    cairo_class_ser: &[u8],
    class_hash: Option<ClassHash>,
) -> anyhow::Result<()> {
    let cairo_class_def = serde_json::from_slice::<CairoContractDefinition<'_>>(cairo_class_ser)?;
    let cairo_class_hash = class_hash.unwrap_or(compute_cairo_class_hash(
        RawCairoContractDefinition::from(cairo_class_def),
    )?);

    let insert_ok = state_update.declared_cairo_classes.insert(cairo_class_hash);
    anyhow::ensure!(
        insert_ok,
        "Predeclaring class with hash {cairo_class_hash} would overwrite an existing class \
         declaration"
    );

    transaction.insert_cairo_class_definition(cairo_class_hash, cairo_class_ser)?;
    Ok(())
}

/// Predeclare a Cairo1 (Sierra) class, ie. insert class definition into the DB
/// and update the state update, which should be inserted into the DB when all
/// predeclarations and predeployments are done. If `class_hash` is `None`, it
/// will be computed from the class definition.
fn sierra(
    transaction: &Transaction<'_>,
    state_update: &mut state_update::StateUpdateData,
    sierra_class_ser: &[u8],
    class_hash: Option<ClassHash>,
) -> anyhow::Result<()> {
    let sierra_class_hash = class_hash.unwrap_or({
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

        compute_sierra_class_hash(sierra_class_def)?
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

    let casm = compile_to_casm_deser(sierra_class_def).unwrap();
    let casm_hash = casm_class_hash_v2(&casm).unwrap();
    let sierra_class_hash = SierraHash(sierra_class_hash.0);

    let overwritten = state_update
        .declared_sierra_classes
        .insert(sierra_class_hash, casm_hash)
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
        &casm_hash,
    )?;
    Ok(())
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
