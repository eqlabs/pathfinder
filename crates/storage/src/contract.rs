use crate::types::CompressedContract;
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use pathfinder_common::{ClassHash, ContractClass, StarknetBlockHash};
use pathfinder_serde::extract_program_and_entry_points_by_type;
use rusqlite::{named_params, Connection, OptionalExtension, Transaction};

/// Stores StarkNet contract information, specifically a contract's
///
/// - [hash](ClassHash)
/// - byte code
/// - ABI
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
            r"INSERT INTO contract_code (hash, definition)
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
            "UPDATE contract_code SET declared_on=? WHERE hash=? AND declared_on IS NULL",
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
                FROM contract_code
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
        let mut stmt = connection.prepare("select 1 from contract_code where hash = ?")?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
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
