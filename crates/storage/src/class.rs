use anyhow::Context;
use pathfinder_common::{CasmHash, ClassCommitmentLeafHash, ClassHash};

use crate::prelude::*;

/// Stores Starknet contract information, specifically a contract's
///
/// - [hash](ClassHash)
/// - definition
pub struct ClassDefinitionsTable {}

impl ClassDefinitionsTable {
    /// Insert a class into the table.
    ///
    /// Does nothing if the class [hash](ClassHash) is already populated.
    pub fn insert(
        transaction: &Transaction<'_>,
        hash: ClassHash,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10)
            .context("Couldn't create zstd compressor for ClassDefinitionsTable")?;
        let definition = compressor
            .compress(definition)
            .context("Failed to compress definition")?;
        transaction.execute(
            r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
            params![&hash, &definition],
        )?;

        Ok(())
    }

    /// Returns true for each [ClassHash] if the class definition already exists in the table.
    pub fn exists(
        transaction: &Transaction<'_>,
        classes: &[ClassHash],
    ) -> anyhow::Result<Vec<bool>> {
        let mut stmt = transaction.prepare("SELECT 1 FROM class_definitions WHERE hash = ?")?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Stores Sierra to CASM compiler version values
///
/// When compiling a Sierra class to CASM we should store the version of the compiler
/// used so that we can later selectively re-compile CASM based on the compiler version.
/// Because the version we have is not a properly structured semantic version we're
/// storing the `id` from the Cargo package metadata here. That is a not-so-short string,
/// that's why we're interning values.
struct CasmCompilerVersions;

impl CasmCompilerVersions {
    /// Interns, or makes sure there's a unique row for each version.
    ///
    /// These are not deleted automatically nor is a need expected because new versions
    /// are introduced _only_ when we're upgrading the CASM compiler in pathdfinder.
    pub fn intern(transaction: &Transaction<'_>, version: &str) -> anyhow::Result<i64> {
        let id: Option<i64> = transaction
            .query_row(
                "SELECT id FROM casm_compiler_versions WHERE version = ?",
                [version],
                |r| Ok(r.get_unwrap(0)),
            )
            .optional()
            .context("Querying for an existing casm_compiler_versions")?;

        let id = if let Some(id) = id {
            id
        } else {
            // sqlite "autoincrement" for integer primary keys works like this: we leave it out of
            // the insert, even though it's not null, it will get max(id)+1 assigned, which we can
            // read back with last_insert_rowid
            let rows = transaction
                .execute(
                    "INSERT INTO casm_compiler_versions(version) VALUES (?)",
                    [version],
                )
                .context("Inserting unique casm_compiler_version")?;

            anyhow::ensure!(rows == 1, "Unexpected number of rows inserted: {rows}");

            transaction.last_insert_rowid()
        };

        Ok(id)
    }
}

/// Stores compiled CASM for Sierra classes
///
/// Sierra classes need to be compiled to Cairo assembly so that we can execute them.
pub struct CasmClassTable {}

impl CasmClassTable {
    /// Insert a CASM class into the table.
    ///
    /// Note that the class hash must reference a class stored in [ClassDefinitionsTable].
    pub fn insert(
        transaction: &Transaction<'_>,
        definition: &[u8],
        class_hash: ClassHash,
        compiled_class_hash: ClassHash,
        casm_compiler_version: &str,
    ) -> anyhow::Result<()> {
        let version_id = CasmCompilerVersions::intern(transaction, casm_compiler_version)
            .context("Fetching CASM compiler version id")?;

        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let definition = compressor
            .compress(definition)
            .context("Compressing class definition")?;

        transaction.execute(
            r"INSERT OR REPLACE INTO casm_definitions
                (hash, definition, compiled_class_hash, compiler_version_id)
            VALUES
                (:hash, :definition, :compiled_class_hash, :compiler_version_id)",
            named_params! {
                ":hash": &class_hash,
                ":definition": &definition,
                ":compiled_class_hash": &compiled_class_hash,
                ":compiler_version_id": &version_id,
            },
        )?;
        Ok(())
    }

    /// Returns true for each [ClassHash] if the class definition already exists in the table.
    pub fn exists(
        transaction: &Transaction<'_>,
        classes: &[ClassHash],
    ) -> anyhow::Result<Vec<bool>> {
        let mut stmt = transaction.prepare("SELECT 1 FROM casm_definitions WHERE hash = ?")?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([hash]))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Stores class commitment table leaf hash to data mapping.
///
/// We have to be able to map the leaf hash value in the class commitment tree
/// to the compiled class hash.
pub struct ClassCommitmentLeavesTable;

impl ClassCommitmentLeavesTable {
    /// Upsert a class commitment leaf.
    pub fn upsert(
        transaction: &Transaction<'_>,
        hash: &ClassCommitmentLeafHash,
        compiled_class_hash: &CasmHash,
    ) -> anyhow::Result<()> {
        let mut stmt = transaction.prepare_cached(
            r"INSERT INTO class_commitment_leaves
                (hash, compiled_class_hash)
            VALUES
                (:hash, :compiled_class_hash)
            ON CONFLICT DO NOTHING
            ",
        )?;

        stmt.execute(named_params! {
            ":hash": hash,
            ":compiled_class_hash": compiled_class_hash,
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;
    use pathfinder_common::felt;

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = ClassHash(felt!("0x123"));

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;
        ClassDefinitionsTable::insert(transaction, hash, &definition[..]).unwrap();

        (
            hash,
            br#"{"huge":"hash"}"#,
            serde_json::json!({"this might be a":"hash"}),
        )
    }

    #[test]
    fn contracts_exist() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let (hash, _, _) = setup_class(&transaction);
        let non_existent = ClassHash(felt!("0x456"));

        let result = ClassDefinitionsTable::exists(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];

        assert_eq!(result, expected);
    }
}
