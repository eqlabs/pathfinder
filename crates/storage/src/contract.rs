use crate::types::{CompressedCasmClass, CompressedContract};
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use pathfinder_common::{
    CasmHash, ClassCommitmentLeafHash, ClassHash, ContractClass, StarknetBlockHash,
};
use pathfinder_serde::extract_program_and_entry_points_by_type;
use rusqlite::{named_params, Connection, OptionalExtension, Transaction};

/// Stores StarkNet contract information, specifically a contract's
///
/// - [hash](ClassHash)
/// - definition
pub struct ContractCodeTable {}

impl ContractCodeTable {
    /// Insert a class into the table.
    ///
    /// Does nothing if the class [hash](ClassHash) is already populated.
    pub fn insert(
        transaction: &Transaction<'_>,
        hash: ClassHash,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10)
            .context("Couldn't create zstd compressor for ContractCodeTable")?;
        let definition = compressor
            .compress(definition)
            .context("Failed to compress definition")?;

        let contract = CompressedContract { definition, hash };

        Self::insert_compressed(transaction, &contract)
    }

    pub fn insert_compressed(
        connection: &Connection,
        contract: &CompressedContract,
    ) -> anyhow::Result<()> {
        // check magics to verify these are zstd compressed files
        let magic = &[0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(&contract.definition[..4], magic);

        connection.execute(
            r"INSERT INTO class_definitions (hash, definition)
                             VALUES (:hash, :definition)",
            named_params! {
                ":hash": &contract.hash.0.to_be_bytes()[..],
                ":definition": &contract.definition[..],
            },
        )?;
        Ok(())
    }

    pub fn update_declared_on_if_null(
        transaction: &Transaction<'_>,
        class: ClassHash,
        block: StarknetBlockHash,
    ) -> anyhow::Result<bool> {
        let rows_changed = transaction.execute(
            "UPDATE class_definitions SET declared_on=? WHERE hash=? AND declared_on IS NULL",
            rusqlite::params![block, class],
        )?;

        match rows_changed {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("Should modify at most one row"),
        }
    }

    pub fn get_class(
        transaction: &Transaction<'_>,
        hash: ClassHash,
    ) -> anyhow::Result<Option<ContractClass>> {
        let row = transaction
            .query_row(
                "SELECT definition
                FROM class_definitions
                WHERE hash = :hash",
                named_params! {
                    ":hash": &hash.0.to_be_bytes()
                },
                |row| {
                    let definition: Vec<u8> = row.get("definition")?;

                    Ok(definition)
                },
            )
            .optional()?;

        let definition = match row {
            None => return Ok(None),
            Some(definition) => definition,
        };

        let definition = zstd::decode_all(&*definition)
            .context("Corruption: invalid compressed column (definition)")?;

        let (program, entry_points_by_type) = extract_program_and_entry_points_by_type(&definition)
            .context("Extract program and entry points from contract definition")?;

        // Program is expected to be a gzip-compressed then base64 encoded representation of the JSON.
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::fast());
        serde_json::to_writer(&mut gzip_encoder, &program).context("Compressing program JSON")?;
        let program = gzip_encoder
            .finish()
            .context("Finishing program compression")?;

        let program = base64::encode(program);

        Ok(Some(ContractClass {
            program,
            entry_points_by_type,
        }))
    }

    /// Returns true for each [ClassHash] if the class definition already exists in the table.
    pub fn exists(connection: &Connection, classes: &[ClassHash]) -> anyhow::Result<Vec<bool>> {
        let mut stmt = connection.prepare("SELECT 1 FROM class_definitions WHERE hash = ?")?;

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
    pub fn intern(connection: &Connection, version: &str) -> anyhow::Result<i64> {
        let id: Option<i64> = connection
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
            let rows = connection
                .execute(
                    "INSERT INTO casm_compiler_versions(version) VALUES (?)",
                    [version],
                )
                .context("Inserting unique casm_compiler_version")?;

            anyhow::ensure!(rows == 1, "Unexpected number of rows inserted: {rows}");

            connection.last_insert_rowid()
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
    /// Note that the class hash must reference a class stored in [ContractCodeTable].
    pub fn upsert_compressed(
        connection: &Connection,
        class: &CompressedCasmClass,
        compiled_class_hash: &CasmHash,
        casm_compiler_version: &str,
    ) -> anyhow::Result<()> {
        let version_id = CasmCompilerVersions::intern(connection, casm_compiler_version)
            .context("Fetching CASM compiler version id")?;

        connection.execute(
            r"INSERT OR REPLACE INTO casm_definitions
                (hash, definition, compiled_class_hash, compiler_version_id)
            VALUES
                (:hash, :definition, :compiled_class_hash, :compiler_version_id)",
            named_params! {
                ":hash": class.hash,
                ":definition": &class.definition[..],
                ":compiled_class_hash": compiled_class_hash,
                ":compiler_version_id": version_id,
            },
        )?;
        Ok(())
    }

    /// Returns true for each [ClassHash] if the class definition already exists in the table.
    pub fn exists(connection: &Connection, classes: &[ClassHash]) -> anyhow::Result<Vec<bool>> {
        let mut stmt = connection.prepare("SELECT 1 FROM casm_definitions WHERE hash = ?")?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
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

    #[test]
    fn get_class() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let (hash, program, entry_points_by_type) = setup_class(&transaction);

        let result = ContractCodeTable::get_class(&transaction, hash).unwrap();

        assert_matches::assert_matches!(
            result,
            Some(result) => {
                use std::io::{Cursor, Read};

                assert_eq!(result.entry_points_by_type, entry_points_by_type);

                let mut decompressor = flate2::read::GzDecoder::new(Cursor::new(base64::decode(result.program).unwrap()));
                let mut result_program = Vec::new();
                decompressor.read_to_end(&mut result_program).unwrap();
                assert_eq!(&result_program, program);
            }
        );
    }

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = ClassHash(felt!("0x123"));

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;
        ContractCodeTable::insert(transaction, hash, &definition[..]).unwrap();

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

        let result = ContractCodeTable::exists(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];

        assert_eq!(result, expected);
    }
}
