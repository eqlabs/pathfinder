use crate::{
    core::{ClassHash, ContractAddress, ContractClass},
    state::{class_hash::extract_program_and_entry_points_by_type, CompressedContract},
};

use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
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
        abi: &[u8],
        bytecode: &[u8],
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10)
            .context("Couldn't create zstd compressor for ContractCodeTable")?;
        let abi = compressor.compress(abi).context("Failed to compress ABI")?;
        let bytecode = compressor
            .compress(bytecode)
            .context("Failed to compress bytecode")?;
        let definition = compressor
            .compress(definition)
            .context("Failed to compress definition")?;

        let contract = CompressedContract {
            abi,
            bytecode,
            definition,
            hash,
        };

        Self::insert_compressed(transaction, &contract)
    }

    pub fn insert_compressed(
        connection: &Connection,
        contract: &CompressedContract,
    ) -> anyhow::Result<()> {
        // check magics to verify these are zstd compressed files
        let magic = &[0x28, 0xb5, 0x2f, 0xfd];
        assert_eq!(&contract.abi[..4], magic);
        assert_eq!(&contract.bytecode[..4], magic);
        assert_eq!(&contract.definition[..4], magic);

        connection.execute(
            r"INSERT INTO contract_code ( hash,  bytecode,  abi,  definition)
                             VALUES (:hash, :bytecode, :abi, :definition)",
            named_params! {
                ":hash": &contract.hash.0.to_be_bytes()[..],
                ":bytecode": &contract.bytecode[..],
                ":abi": &contract.abi[..],
                ":definition": &contract.definition[..],
            },
        )?;
        Ok(())
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
            .map(|hash| stmt.exists(&[&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Stores the mapping from StarkNet contract [address](ContractAddress) to [hash](ClassHash).
pub struct ContractsTable {}

impl ContractsTable {
    /// Insert a contract into the table, overwrites the data if it already exists.
    ///
    /// Note that [hash](ClassHash) must reference a class stored in [ContractCodeTable].
    pub fn upsert(
        transaction: &Transaction<'_>,
        address: ContractAddress,
        hash: ClassHash,
    ) -> anyhow::Result<()> {
        // A contract may be deployed multiple times due to L2 reorgs, so we ignore all after the first.
        transaction.execute(
            r"INSERT OR REPLACE INTO contracts (address, hash) VALUES (:address, :hash)",
            named_params! {
                ":address": address,
                ":hash": hash,
            },
        )?;
        Ok(())
    }

    /// Returns true if the given contract exists in this table.
    pub fn exists(transaction: &Transaction<'_>, address: ContractAddress) -> anyhow::Result<bool> {
        let exists = transaction
            .prepare("SELECT 1 FROM contracts WHERE address = ?")?
            .exists([address])?;
        Ok(exists)
    }

    /// Gets the specified contract's class hash.
    pub fn get_hash(
        transaction: &Transaction<'_>,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ClassHash>> {
        transaction
            .query_row(
                "SELECT hash FROM contracts WHERE address = ?",
                [address],
                |row| row.get("hash"),
            )
            .optional()
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::starkhash;
    use crate::storage::Storage;

    use super::*;

    #[test]
    fn fails_if_class_hash_missing() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let address = ContractAddress::new_or_panic(starkhash!("0abc"));
        let hash = ClassHash(starkhash!("0123"));

        ContractsTable::upsert(&transaction, address, hash).unwrap_err();
    }

    #[test]
    fn get_hash() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let address = ContractAddress::new_or_panic(starkhash!("0abc"));
        let hash = ClassHash(starkhash!("0123"));
        let definition = vec![9, 13, 25];

        ContractCodeTable::insert(&transaction, hash, &[][..], &[][..], &definition[..]).unwrap();
        ContractsTable::upsert(&transaction, address, hash).unwrap();

        let result = ContractsTable::get_hash(&transaction, address).unwrap();

        assert_eq!(result, Some(hash));
    }

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
        let hash = ClassHash(starkhash!("0123"));

        // list of objects
        let abi = br#"[{"this":"looks"},{"like": "this"}]"#;
        // this is list of hex
        let code = br#"["0x40780017fff7fff","0x1","0x208b7fff7fff7ffe"]"#;
        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;
        ContractCodeTable::insert(transaction, hash, &abi[..], &code[..], &definition[..]).unwrap();

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
        let non_existent = ClassHash(starkhash!("0456"));

        let result = ContractCodeTable::exists(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];

        assert_eq!(result, expected);
    }
}
