use crate::{
    core::{ContractAddress, ContractCode, ContractHash},
    storage::{DB_VERSION_CURRENT, DB_VERSION_EMPTY},
};

use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{named_params, OptionalExtension, Transaction};

/// Migrates the [ContractsTable] to the [current version](DB_VERSION_CURRENT).
pub fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
    ContractsTable::migrate(transaction, from_version)
}

/// Stores StarkNet contract information, specifically a contract's
///
/// - [address](ContractAddress)
/// - [hash](ContractHash)
/// - byte code
/// - ABI
/// - definition
pub struct ContractsTable {}

impl ContractsTable {
    /// Migrates the [ContractsTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {} // Fresh database, continue to create table.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        transaction.execute(
            r"CREATE TABLE contracts (
                    address    BLOB PRIMARY KEY,
                    hash       BLOB NOT NULL,
                    bytecode   BLOB,
                    abi        BLOB,
                    definition BLOB
                )",
            [],
        )?;

        Ok(())
    }

    /// Insert a contract into the table. Will fail if the contract address is already populated.
    pub fn insert(
        transaction: &Transaction,
        address: ContractAddress,
        hash: ContractHash,
        code: ContractCode,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let bytecode = code
            .bytecode
            .into_iter()
            .flat_map(|word| word.to_be_bytes())
            .collect::<Vec<_>>();

        transaction.execute(
            r"INSERT INTO contracts ( address,  hash, bytecode,   abi,  definition)
                             VALUES (:address, :hash, :bytecode, :abi, :definition)",
            named_params! {
                ":address": &address.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
                ":bytecode": &bytecode[..],
                ":abi": code.abi.as_bytes(),
                ":definition": definition,
            },
        )?;
        Ok(())
    }

    /// Gets the specificed contract's [code](ContractCode).
    pub fn get_code(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractCode>> {
        let row = transaction
            .query_row(
                "SELECT bytecode, abi FROM contracts where address = :address",
                named_params! {
                    ":address": &address.0.to_be_bytes()[..]
                },
                |row| {
                    let bytecode: Vec<u8> = row.get("bytecode")?;
                    let abi: Vec<u8> = row.get("abi")?;

                    Ok((bytecode, abi))
                },
            )
            .optional()?;

        let (bytecode, abi) = match row {
            None => return Ok(None),
            Some((bytecode, abi)) => (bytecode, abi),
        };

        anyhow::ensure!(
            (bytecode.len() % 32) == 0,
            "Bytecode length must be a multiple of 32, but got {}",
            bytecode.len()
        );

        let bytecode = bytecode
            .chunks(32)
            // unwrap is safe because word is guaranteed to be 32 bytes
            .map(|word| StarkHash::from_be_slice(word).unwrap())
            .collect();

        let abi = String::from_utf8(abi).context("Parsing ABI bytes")?;

        Ok(Some(ContractCode { bytecode, abi }))
    }

    /// Gets the specificed contract's hash.
    pub fn get_hash(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractHash>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT hash FROM contracts WHERE address = :address",
                named_params! {
                    ":address": &address.0.to_be_bytes()[..]
                },
                |row| row.get("hash"),
            )
            .optional()?;

        let bytes = match bytes {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let bytes: [u8; 32] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => anyhow::bail!("Bad contract hash length: {}", bytes.len()),
        };

        let hash = StarkHash::from_be_bytes(bytes)?;
        let hash = ContractHash(hash);

        Ok(Some(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
        let code = ContractCode {
            bytecode: Vec::new(),
            abi: String::new(),
        };
        let definition = vec![9, 13, 25];

        ContractsTable::insert(&transaction, address, hash, code, &definition[..]).unwrap();

        let result = ContractsTable::get_hash(&transaction, address).unwrap();

        assert_eq!(result, Some(hash));
    }

    #[test]
    fn get_code() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
        let code = ContractCode {
            bytecode: vec![
                StarkHash::from_hex_str("abc").unwrap(),
                StarkHash::from_hex_str("def").unwrap(),
                StarkHash::from_hex_str("123").unwrap(),
                StarkHash::from_hex_str("4567890").unwrap(),
            ],
            abi: "This is the ABI".to_string(),
        };
        let definition = vec![9, 13, 25];

        ContractsTable::insert(&transaction, address, hash, code.clone(), &definition[..]).unwrap();

        let result = ContractsTable::get_code(&transaction, address).unwrap();

        assert_eq!(result, Some(code));
    }
}
