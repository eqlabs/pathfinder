use pedersen::StarkHash;
use rusqlite::{named_params, OptionalExtension, Transaction};

use crate::{
    core::{ContractHash, ContractRoot, ContractStateHash},
    storage::{DB_VERSION_CURRENT, DB_VERSION_EMPTY},
};

/// Migrates the [ContractsStateTable] to the [current version](DB_VERSION_CURRENT).
pub fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
    ContractsStateTable::migrate(transaction, from_version)
}

/// Stores the contract state hash along with its preimage. This is useful to
/// map between the global state tree and the contracts tree.
///
/// Specifically it stores
///
/// - [contract state hash](ContractStateHash)
/// - [contract hash](ContractHash)
/// - [contract root](ContractRoot)
pub struct ContractsStateTable {}

impl ContractsStateTable {
    /// Migrates the [ContractsStateTable] from the given version to [DB_VERSION_CURRENT].
    fn migrate(transaction: &Transaction, from_version: u32) -> anyhow::Result<()> {
        match from_version {
            DB_VERSION_EMPTY => {} // Fresh database, continue to create table.
            DB_VERSION_CURRENT => return Ok(()), // Table is already correct.
            other => anyhow::bail!("Unknown database version: {}", other),
        }

        transaction.execute(
            r"CREATE TABLE contract_states (
                    state_hash BLOB PRIMARY KEY,
                    hash       BLOB NOT NULL,
                    root       BLOB NOT NULL
                )",
            [],
        )?;

        Ok(())
    }

    /// Insert a state hash into the table. Does nothing if the state hash already exists.
    pub fn insert(
        transaction: &Transaction,
        state_hash: ContractStateHash,
        hash: ContractHash,
        root: ContractRoot,
    ) -> anyhow::Result<()> {
        transaction.execute(
            r"INSERT INTO contract_states ( state_hash,  hash,  root)
                                       VALUES (:state_hash, :hash, :root)",
            named_params! {
                ":state_hash": &state_hash.0.to_be_bytes()[..],
                ":hash": &hash.0.to_be_bytes()[..],
                ":root": &root.0.to_be_bytes()[..],
            },
        )?;
        Ok(())
    }

    /// Gets the root associated with the given state hash, or [None]
    /// if it does not exist.
    pub fn get_root(
        transaction: &Transaction,
        state_hash: ContractStateHash,
    ) -> anyhow::Result<Option<ContractRoot>> {
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT root FROM contract_states WHERE state_hash = :state_hash",
                named_params! {
                    ":state_hash": &state_hash.0.to_be_bytes()[..]
                },
                |row| row.get("root"),
            )
            .optional()?;

        let bytes = match bytes {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let bytes: [u8; 32] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => anyhow::bail!("Bad contract root length: {}", bytes.len()),
        };

        let root = StarkHash::from_be_bytes(bytes)?;
        let root = ContractRoot(root);

        Ok(Some(root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_root() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        ContractsStateTable::migrate(&transaction, DB_VERSION_EMPTY).unwrap();

        let state_hash = ContractStateHash(StarkHash::from_hex_str("abc").unwrap());
        let hash = ContractHash(StarkHash::from_hex_str("123").unwrap());
        let root = ContractRoot(StarkHash::from_hex_str("def").unwrap());

        ContractsStateTable::insert(&transaction, state_hash, hash, root).unwrap();

        let result = ContractsStateTable::get_root(&transaction, state_hash).unwrap();

        assert_eq!(result, Some(root));
    }
}
