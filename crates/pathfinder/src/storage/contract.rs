use crate::{
    core::{ByteCodeWord, ContractAddress, ContractCode, ContractHash},
    storage::{DB_VERSION_1, DB_VERSION_CURRENT, DB_VERSION_EMPTY},
};

use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{named_params, OptionalExtension, Transaction};

/// Migrates the [ContractsTable] to the [current version](DB_VERSION_CURRENT).
pub fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
    ContractsTable::migrate(transaction, from_version)?;
    ContractAddressesTable::migrate(transaction, from_version)
}

/// Stores StarkNet contract information, specifically a contract's
///
/// - [hash](ContractHash)
/// - byte code
/// - ABI
/// - definition
pub struct ContractsTable {}

impl ContractsTable {
    /// Migrates the [ContractsTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        const CREATE_CONTRACTS_TABLE: &str = r"
        CREATE TABLE contracts (
            hash       BLOB PRIMARY KEY,
            bytecode   BLOB,
            abi        BLOB,
            definition BLOB
        )";

        match from_version {
            DB_VERSION_EMPTY => {
                // Fresh database, just create the table.
                transaction.execute(CREATE_CONTRACTS_TABLE, [])?;
            }
            DB_VERSION_1 => {
                // Rename the old contracts table
                transaction.execute(r"ALTER TABLE contracts RENAME TO contracts_v1", [])?;
                // Create the new contracts table
                transaction.execute(CREATE_CONTRACTS_TABLE, [])?;
                // Populate the new contracts table with data
                transaction.execute(
                    r"INSERT INTO contracts (hash, bytecode, abi, definition)
                    SELECT DISTINCT hash, bytecode, abi, definition FROM contracts_v1",
                    [],
                )?;
                // Create the contract addresses table
                transaction.execute(ContractAddressesTable::CREATE_CONTRACT_ADDRESSES_TABLE, [])?;
                // Populate it with address to hash mapping taken from the old contracts table
                transaction.execute(
                    r"INSERT INTO contract_addresses (address, hash)
                    SELECT address, hash FROM contracts_v1",
                    [],
                )?;
                // Drop the old contracts table
                transaction.execute(r"DROP TABLE contracts_v1", [])?;
            }
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        Ok(())
    }

    /// Insert a contract into the table.
    ///
    /// Does nothing if the contract [hash](ContractHash) is already populated.
    pub fn insert(
        transaction: &Transaction,
        hash: ContractHash,
        abi: &[u8],
        bytecode: &[u8],
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10)
            .context("Couldn't create zstd compressor for ContractsTable")?;
        let abi = compressor.compress(abi).context("Failed to compress ABI")?;
        let bytecode = compressor
            .compress(bytecode)
            .context("Failed to compress bytecode")?;
        let definition = compressor
            .compress(definition)
            .context("Failed to compress definition")?;

        transaction.execute(
            r"INSERT INTO contracts ( hash,  bytecode,  abi,  definition)
                             VALUES (:hash, :bytecode, :abi, :definition)
                             ON CONFLICT DO NOTHING",
            named_params! {
                ":hash": &hash.0.to_be_bytes()[..],
                ":bytecode": bytecode,
                ":abi": abi,
                ":definition": definition,
            },
        )?;
        Ok(())
    }

    /// Gets the specified contract's [code](ContractCode).
    pub fn get_code(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractCode>> {
        let row = transaction
            .query_row(
                "SELECT contracts.bytecode, contracts.abi
                FROM contract_addresses
                JOIN contracts ON contract_addresses.hash = contracts.hash
                WHERE contract_addresses.address = :address
                LIMIT 1",
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

        // It might be dangerious to not have some upper bound on the compressed size.
        // someone could put a very tight bomb to our database, and then have it OOM during
        // runtime, but if you can already modify our database at will, maybe there's more useful
        // things to do.

        let bytecode = zstd::decode_all(&*bytecode)
            .context("Corruption: invalid compressed column (bytecode)")?;

        let abi = zstd::decode_all(&*abi).context("Corruption: invalid compressed column (abi)")?;

        let abi =
            String::from_utf8(abi).context("Corruption: invalid uncompressed column (abi)")?;

        let bytecode = serde_json::from_slice::<Vec<ByteCodeWord>>(&bytecode)
            .context("Corruption: invalid uncompressed column (bytecode)")?;

        Ok(Some(ContractCode { bytecode, abi }))
    }
}

/// Stores the mapping from StarkNet contract [address](ContractAddress) to [hash](ContractHash).
pub struct ContractAddressesTable {}

impl ContractAddressesTable {
    /// This statement is reused by [`ContractsTable::migrate`]
    pub const CREATE_CONTRACT_ADDRESSES_TABLE: &'static str = r"
    CREATE TABLE contract_addresses (
        address    BLOB PRIMARY KEY,
        hash       BLOB NOT NULL,

        FOREIGN KEY(hash) REFERENCES contracts(hash)
    )";

    /// Migrates the [ContractAddressesTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {
                // Fresh database, just create the table.
                transaction.execute(Self::CREATE_CONTRACT_ADDRESSES_TABLE, [])?;
            }
            DB_VERSION_1 => {} // Handled in ContractsTable::migrate due to foreign key constraints.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        Ok(())
    }

    /// Insert a contract into the table.
    ///
    /// Fails if the contract address is already populated.
    ///
    /// Note that [hash](ContractHash) must reference a contract stored in [ContractsTable].
    pub fn insert(
        transaction: &Transaction,
        address: ContractAddress,
        hash: ContractHash,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO contract_addresses (address, hash) VALUES (:address, :hash)",
            named_params! {
                ":address": &address.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
            },
        )?;
        Ok(())
    }

    /// Gets the specified contract's hash.
    pub fn get_hash(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractHash>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT hash FROM contract_addresses WHERE address = :address",
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
    fn fails_if_contract_hash_missing() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();
        ContractAddressesTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());

        ContractAddressesTable::insert(&transaction, address, hash).unwrap_err();
    }

    #[test]
    fn get_hash() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();
        ContractAddressesTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
        let definition = vec![9, 13, 25];

        ContractsTable::insert(&transaction, hash, &[][..], &[][..], &definition[..]).unwrap();
        ContractAddressesTable::insert(&transaction, address, hash).unwrap();

        let result = ContractAddressesTable::get_hash(&transaction, address).unwrap();

        assert_eq!(result, Some(hash));
    }

    #[test]
    fn get_code() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();
        ContractAddressesTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());

        // list of objects
        let abi = br#"[{"this":"looks"},{"like": "this"}]"#;

        // this is list of hex
        let code = br#"["0x40780017fff7fff","0x1","0x208b7fff7fff7ffe"]"#;

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        ContractsTable::insert(&transaction, hash, &abi[..], &code[..], &definition[..]).unwrap();
        ContractAddressesTable::insert(&transaction, address, hash).unwrap();

        let result = ContractsTable::get_code(&transaction, address).unwrap();

        assert_eq!(
            result,
            Some(ContractCode {
                abi: String::from_utf8(abi.to_vec()).unwrap(),
                bytecode: serde_json::from_slice::<Vec<ByteCodeWord>>(code).unwrap(),
            })
        );
    }
}
