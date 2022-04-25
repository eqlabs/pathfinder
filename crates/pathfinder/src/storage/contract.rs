use crate::{
    core::{ByteCodeWord, ContractAddress, ContractCode, ContractHash},
    state::CompressedContract,
};

use anyhow::Context;
use pedersen_hash::StarkHash;
use rusqlite::{named_params, Connection, OptionalExtension, Transaction};

/// Stores StarkNet contract information, specifically a contract's
///
/// - [hash](ContractHash)
/// - byte code
/// - ABI
/// - definition
pub struct ContractCodeTable {}

impl ContractCodeTable {
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

    /// Gets the specified contract's [code](ContractCode).
    pub fn get_code(
        transaction: &Transaction,
        address: ContractAddress,
    ) -> anyhow::Result<Option<ContractCode>> {
        let row = transaction
            .query_row(
                "SELECT contract_code.bytecode, contract_code.abi
                FROM contracts
                JOIN contract_code ON contracts.hash = contract_code.hash
                WHERE contracts.address = :address
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

    /// Returns true for each [ContractHash] if the contract definition already exists in the table.
    pub fn exists(
        connection: &Connection,
        contracts: &[ContractHash],
    ) -> anyhow::Result<Vec<bool>> {
        let mut stmt = connection.prepare("select 1 from contract_code where hash = ?")?;

        Ok(contracts
            .iter()
            .map(|hash| stmt.exists(&[&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Stores the mapping from StarkNet contract [address](ContractAddress) to [hash](ContractHash).
pub struct ContractsTable {}

impl ContractsTable {
    /// Insert a contract into the table, overwrites the data if it already exists.
    ///
    /// Note that [hash](ContractHash) must reference a contract stored in [ContractCodeTable].
    pub fn upsert(
        transaction: &Transaction,
        address: ContractAddress,
        hash: ContractHash,
    ) -> anyhow::Result<()> {
        // A contract may be deployed multiple times due to L2 reorgs, so we ignore all after the first.
        transaction.execute(
            r"INSERT OR REPLACE INTO contracts (address, hash) VALUES (:address, :hash)",
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
    use crate::storage::Storage;

    use super::*;

    #[test]
    fn fails_if_contract_hash_missing() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());

        ContractsTable::upsert(&transaction, address, hash).unwrap_err();
    }

    #[test]
    fn get_hash() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
        let definition = vec![9, 13, 25];

        ContractCodeTable::insert(&transaction, hash, &[][..], &[][..], &definition[..]).unwrap();
        ContractsTable::upsert(&transaction, address, hash).unwrap();

        let result = ContractsTable::get_hash(&transaction, address).unwrap();

        assert_eq!(result, Some(hash));
    }

    #[test]
    fn get_code() {
        let storage = Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let address = ContractAddress(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());

        // list of objects
        let abi = br#"[{"this":"looks"},{"like": "this"}]"#;

        // this is list of hex
        let code = br#"["0x40780017fff7fff","0x1","0x208b7fff7fff7ffe"]"#;

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        ContractCodeTable::insert(&transaction, hash, &abi[..], &code[..], &definition[..])
            .unwrap();
        ContractsTable::upsert(&transaction, address, hash).unwrap();

        let result = ContractCodeTable::get_code(&transaction, address).unwrap();

        assert_eq!(
            result,
            Some(ContractCode {
                abi: String::from_utf8(abi.to_vec()).unwrap(),
                bytecode: serde_json::from_slice::<Vec<ByteCodeWord>>(code).unwrap(),
            })
        );
    }

    #[test]
    fn contracts_exist() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());

        // list of objects
        let abi = br#"[{"this":"looks"},{"like": "this"}]"#;
        // this is list of hex
        let code = br#"["0x40780017fff7fff","0x1","0x208b7fff7fff7ffe"]"#;
        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;
        ContractCodeTable::insert(&transaction, hash, &abi[..], &code[..], &definition[..])
            .unwrap();

        let non_existent = ContractHash(StarkHash::from_hex_str("456").unwrap());

        let result = ContractCodeTable::exists(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];

        assert_eq!(result, expected);
    }
}
