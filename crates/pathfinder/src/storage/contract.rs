use crate::{
    core::{ContractAddress, ContractHash},
    storage::{DB_VERSION_CURRENT, DB_VERSION_EMPTY},
};

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
    const TABLE: &'static str = "contracts";

    /// Migrates the [ContractsTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {} // Fresh database, continue to create table.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        transaction.execute(
            &format!(
                r"CREATE TABLE {}(
                    address    BLOB PRIMARY KEY,
                    hash       BLOB NOT NULL,
                    code       BLOB,
                    abi        BLOB,
                    definition BLOB
                )",
                Self::TABLE
            ),
            [],
        )?;

        Ok(())
    }

    /// Insert a contract into the table. Will fail if the contract address is already populated.
    pub fn insert(
        transaction: &Transaction,
        address: ContractAddress,
        hash: ContractHash,
        code: &[u8],
        abi: &[u8],
        definition: &[u8],
    ) -> anyhow::Result<()> {
        transaction.execute(
            &format!(
                r"INSERT INTO {} ( address,  hash, code,   abi,  definition)
                          VALUES (:address, :hash, :code, :abi, :definition)",
                Self::TABLE
            ),
            named_params! {
                ":address": &address.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
                ":code": code,
                ":abi": abi,
                ":definition": definition,
            },
        )?;
        Ok(())
    }

    /// Gets the specificed contract's hash.
    pub fn get_hash(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractHash>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                &format!("SELECT hash FROM {} WHERE address = :address", Self::TABLE),
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
        let code = vec![0, 1, 2, 3, 4];
        let abi = vec![54, 62, 71];
        let definition = vec![9, 13, 25];

        ContractsTable::insert(
            &transaction,
            address,
            hash,
            &code[..],
            &abi[..],
            &definition[..],
        )
        .unwrap();

        let result = ContractsTable::get_hash(&transaction, address).unwrap();

        assert_eq!(result, Some(hash));
    }
}
