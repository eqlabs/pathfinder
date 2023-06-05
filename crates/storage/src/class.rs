use anyhow::Context;
use pathfinder_common::{CasmHash, ClassCommitmentLeafHash, ClassHash, SierraHash};

use crate::prelude::*;

pub(crate) fn insert_sierra_class(
    transaction: &Transaction<'_>,
    sierra_hash: &SierraHash,
    sierra_definition: &[u8],
    casm_hash: &CasmHash,
    casm_definition: &[u8],
    compiler_version: &str,
) -> anyhow::Result<()> {
    let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
    let sierra_definition = compressor
        .compress(&sierra_definition)
        .context("Compressing sierra definition")?;
    let casm_definition = compressor
        .compress(&casm_definition)
        .context("Compressing casm definition")?;

    let version_id = intern_compiler_version(transaction, compiler_version)
        .context("Interning compiler version")?;

    transaction
        .execute(
            r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
            params![sierra_hash, &sierra_definition],
        )
        .context("Inserting sierra definition")?;

    transaction
        .execute(
            r"INSERT OR REPLACE INTO casm_definitions
                (hash, definition, compiled_class_hash, compiler_version_id)
            VALUES
                (:hash, :definition, :compiled_class_hash, :compiler_version_id)",
            named_params! {
                ":hash": sierra_hash,
                ":definition": &casm_definition,
                ":compiled_class_hash": casm_hash,
                ":compiler_version_id": &version_id,
            },
        )
        .context("Inserting casm definition")?;

    Ok(())
}

pub(crate) fn insert_cairo_class(
    transaction: &Transaction<'_>,
    cairo_hash: ClassHash,
    definition: &[u8],
) -> anyhow::Result<()> {
    let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
    let definition = compressor
        .compress(&definition)
        .context("Compressing cairo definition")?;

    transaction
        .execute(
            r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
            params![&cairo_hash, &definition],
        )
        .context("Inserting cairo definition")?;

    Ok(())
}

fn intern_compiler_version(
    transaction: &Transaction<'_>,
    compiler_version: &str,
) -> anyhow::Result<i64> {
    let id: Option<i64> = transaction
        .query_row(
            "SELECT id FROM casm_compiler_versions WHERE version = ?",
            [compiler_version],
            |r| Ok(r.get_unwrap(0)),
        )
        .optional()
        .context("Querying for an existing casm compiler version")?;

    let id = if let Some(id) = id {
        id
    } else {
        // sqlite "autoincrement" for integer primary keys works like this: we leave it out of
        // the insert, even though it's not null, it will get max(id)+1 assigned, which we can
        // read back with last_insert_rowid
        let id = transaction
            .query_row(
                "INSERT INTO casm_compiler_versions(version) VALUES (?) RETURNING id",
                [compiler_version],
                |row| row.get(0),
            )
            .context("Inserting unique casm_compiler_version")?;

        id
    };

    Ok(id)
}

/// Returns whether or not the given class definitions exist.
pub(crate) fn classes_exist(
    transaction: &Transaction<'_>,
    classes: &[ClassHash],
) -> anyhow::Result<Vec<bool>> {
    let mut stmt = transaction.prepare("SELECT 1 FROM class_definitions WHERE hash = ?")?;

    Ok(classes
        .iter()
        .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
        .collect::<Result<Vec<_>, _>>()?)
}

pub(crate) fn insert_class_commitment_leaf(
    transaction: &Transaction<'_>,
    leaf: &ClassCommitmentLeafHash,
    casm_hash: &CasmHash,
) -> anyhow::Result<()> {
    transaction.execute(
        "INSERT OR IGNORE INTO class_commitment_leaves (hash, compiled_class_hash) VALUES (?, ?)",
        params![leaf, casm_hash],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;
    use pathfinder_common::felt;

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = ClassHash(felt!("0x123"));

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        transaction.insert_cairo_class(hash, definition).unwrap();

        (
            hash,
            br#"{"huge":"hash"}"#,
            serde_json::json!({"this might be a":"hash"}),
        )
    }

    #[test]
    fn class_existence() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let (hash, _, _) = setup_class(&transaction);
        let non_existent = ClassHash(felt!("0x456"));

        let result = super::classes_exist(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];
        assert_eq!(result, expected);
    }

    #[test]
    fn compiler_version_interning() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let alpha = intern_compiler_version(&transaction, "alpha").unwrap();
        let alpha_again = intern_compiler_version(&transaction, "alpha").unwrap();
        assert_eq!(alpha, alpha_again);

        let beta = intern_compiler_version(&transaction, "beta").unwrap();
        assert_ne!(alpha, beta);

        let beta_again = intern_compiler_version(&transaction, "beta").unwrap();
        assert_eq!(beta, beta_again);

        for i in 0..10 {
            intern_compiler_version(&transaction, i.to_string().as_str()).unwrap();
        }

        let alpha_again2 = intern_compiler_version(&transaction, "alpha").unwrap();
        assert_eq!(alpha, alpha_again2);
    }
}
