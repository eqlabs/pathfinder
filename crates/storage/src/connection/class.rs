use anyhow::Context;
use pathfinder_common::{
    BlockId,
    BlockNumber,
    CasmHash,
    ClassCommitmentLeafHash,
    ClassHash,
    SierraHash,
};

use crate::prelude::*;

impl Transaction<'_> {
    pub fn insert_sierra_class_definition(
        &self,
        sierra_hash: &SierraHash,
        sierra_definition: &[u8],
        casm_definition: &[u8],
        // Blake2 hash of the compiled class definition
        casm_hash_v2: &CasmHash,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let sierra_definition = compressor
            .compress(sierra_definition)
            .context("Compressing sierra definition")?;
        let casm_definition = compressor
            .compress(casm_definition)
            .context("Compressing casm definition")?;

        self.inner()
            .execute(
                "INSERT OR IGNORE INTO class_definitions (hash, definition) VALUES (?, ?)",
                params![sierra_hash, &sierra_definition],
            )
            .context("Inserting sierra definition")?;

        self.inner()
            .execute(
                r"
                INSERT OR REPLACE INTO casm_definitions
                (hash, definition)
                VALUES (:hash, :definition)
                ",
                named_params! {
                    ":hash": sierra_hash,
                    ":definition": &casm_definition,
                },
            )
            .context("Inserting CASM definition")?;

        self.inner()
            .execute(
                r"
                INSERT OR REPLACE INTO casm_class_hashes_v2
                (hash, compiled_class_hash)
                VALUES (:hash, :compiled_class_hash)
                ",
                named_params! {
                    ":hash": sierra_hash,
                    ":compiled_class_hash": casm_hash_v2,
                },
            )
            .context("Inserting CASM Blake2 hash")?;

        Ok(())
    }

    pub fn update_sierra_class_definition(
        &self,
        sierra_hash: &SierraHash,
        sierra_definition: &[u8],
        casm_definition: &[u8],
        casm_hash_v2: &CasmHash,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let sierra_definition = compressor
            .compress(sierra_definition)
            .context("Compressing sierra definition")?;
        let casm_definition = compressor
            .compress(casm_definition)
            .context("Compressing casm definition")?;

        self.inner()
            .execute(
                r"UPDATE class_definitions SET definition=:definition WHERE hash=:hash",
                named_params! {
                    ":definition": &sierra_definition,
                    ":hash": sierra_hash
                },
            )
            .context("Updating sierra definition")?;

        self.inner()
            .execute(
                r"INSERT OR REPLACE INTO casm_definitions(hash, definition) VALUES(:hash, :definition)",
                named_params! {
                    ":definition": &casm_definition,
                    ":hash": sierra_hash,
                },
            )
            .context("Updating casm definition")?;

        self.inner()
            .execute(
                r"INSERT OR REPLACE INTO casm_class_hashes_v2(hash, compiled_class_hash) VALUES(:hash, :compiled_class_hash)",
                named_params! {
                    ":compiled_class_hash": casm_hash_v2,
                    ":hash": sierra_hash,
                },
            )
            .context("Inserting CASM Blake2 hash")?;

        Ok(())
    }

    pub fn insert_cairo_class_definition(
        &self,
        cairo_hash: ClassHash,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let definition = compressor
            .compress(definition)
            .context("Compressing cairo definition")?;

        self.inner()
            .execute(
                r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
                params![&cairo_hash, &definition],
            )
            .context("Inserting cairo definition")?;

        Ok(())
    }

    pub fn update_cairo_class_definition(
        &self,
        cairo_hash: ClassHash,
        definition: &[u8],
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let definition = compressor
            .compress(definition)
            .context("Compressing cairo definition")?;

        self.inner()
            .execute(
                r"UPDATE class_definitions SET definition=? WHERE hash=?",
                params![&definition, &cairo_hash],
            )
            .context("Updating cairo definition")?;

        Ok(())
    }

    /// Returns whether the Sierra or Cairo class definition exists in the
    /// database.
    ///
    /// Note that this does not indicate that the class is actually declared --
    /// only that we stored it.
    pub fn class_definitions_exist(&self, classes: &[ClassHash]) -> anyhow::Result<Vec<bool>> {
        let mut stmt = self
            .inner()
            .prepare_cached("SELECT 1 FROM class_definitions WHERE hash = ?")?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Returns the uncompressed class definition.
    pub fn class_definition(&self, class_hash: ClassHash) -> anyhow::Result<Option<Vec<u8>>> {
        self.class_definition_with_block_number(class_hash)
            .map(|option| option.map(|(_block_number, definition)| definition))
    }

    /// Returns the uncompressed class definition as well as the block number at
    /// which it was declared.
    pub fn class_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        let from_row = |row: &rusqlite::Row<'_>| {
            let definition = row.get_blob(0).map(|x| x.to_vec())?;
            let block_number = row.get_optional_block_number(1)?;
            Ok((block_number, definition))
        };

        let mut stmt = self.inner().prepare_cached(
            "SELECT definition, block_number FROM class_definitions WHERE hash = ?",
        )?;

        let result = stmt
            .query_row(params![&class_hash], from_row)
            .optional()
            .context("Querying for class definition")?;

        let Some((block_number, definition)) = result else {
            return Ok(None);
        };
        let definition =
            zstd::decode_all(definition.as_slice()).context("Decompressing class definition")?;

        Ok(Some((block_number, definition)))
    }

    /// Returns the compressed class definition if it has been declared at
    /// `block_id`.
    pub fn compressed_class_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.compressed_class_definition_at_with_block_number(block_id, class_hash)
            .map(|option| option.map(|(_block_number, definition)| definition))
    }

    pub fn compressed_class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(BlockNumber, Vec<u8>)>> {
        let from_row = |row: &rusqlite::Row<'_>| {
            let definition = row.get_blob(0).map(|x| x.to_vec())?;
            let block_number = row.get_block_number(1)?;
            Ok((block_number, definition))
        };

        match block_id {
        BlockId::Latest => {
            let mut stmt = self.inner().prepare_cached(
                "SELECT definition, block_number FROM class_definitions WHERE hash=? AND block_number IS NOT NULL",
            )?;
            stmt.query_row(
                params![&class_hash],
                from_row,
            )
        }
        BlockId::Number(number) => {
            let mut stmt = self.inner().prepare_cached(
                "SELECT definition, block_number FROM class_definitions WHERE hash=? AND block_number <= ?",
            )?;
            stmt.query_row(
                params![&class_hash, &number],
                from_row,
            )
        }
        BlockId::Hash(hash) => {
            let mut stmt = self.inner().prepare_cached(
                r"SELECT definition, block_number FROM class_definitions
                WHERE hash = ? AND block_number <= (SELECT number from block_headers WHERE hash = ?)",
            )?;
            stmt.query_row(
                params![&class_hash, &hash],
                from_row,
            )
        }
    }
    .optional()
    .context("Querying for class definition")
    }

    /// Returns the uncompressed class definition if it has been declared at
    /// `block_id`.
    pub fn class_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.class_definition_at_with_block_number(block_id, class_hash)
            .map(|option| option.map(|(_block_number, definition)| definition))
    }

    /// Returns the uncompressed class definition if it has been declared at
    /// `block_id`, as well as the block number at which it was declared.
    pub fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(BlockNumber, Vec<u8>)>> {
        let definition =
            self.compressed_class_definition_at_with_block_number(block_id, class_hash)?;
        let Some((block_number, definition)) = definition else {
            return Ok(None);
        };
        let definition =
            zstd::decode_all(definition.as_slice()).context("Decompressing class definition")?;

        Ok(Some((block_number, definition)))
    }

    /// Returns the uncompressed compiled class definition.
    pub fn casm_definition(&self, class_hash: ClassHash) -> anyhow::Result<Option<Vec<u8>>> {
        // Don't reuse the "_with_block_number" impl here since the suffixed one
        // requires a join that this one doesn't.
        let mut stmt = self
            .inner()
            .prepare_cached("SELECT definition FROM casm_definitions WHERE hash = ?")?;
        let definition = stmt
            .query_row(params![&class_hash], |row| {
                row.get_blob(0).map(|x| x.to_vec())
            })
            .optional()
            .context("Querying for compiled class definition")?;

        let Some(definition) = definition else {
            return Ok(None);
        };
        let definition = zstd::decode_all(definition.as_slice())
            .context("Decompressing compiled class definition")?;

        Ok(Some(definition))
    }

    /// Returns the uncompressed compiled class definition, as well as the block
    /// number at which it  was declared.
    pub fn casm_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        let from_row = |row: &rusqlite::Row<'_>| {
            let definition = row.get_blob(0).map(|x| x.to_vec())?;
            let block_number = row.get_optional_block_number(1)?;
            Ok((block_number, definition))
        };

        let mut stmt = self.inner().prepare_cached(
            r"
            SELECT
                casm_definitions.definition,
                class_definitions.block_number
            FROM
                casm_definitions
                LEFT JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?",
        )?;
        let result = stmt
            .query_row(params![&class_hash], from_row)
            .optional()
            .context("Querying for compiled class definition")?;

        let Some((block_number, definition)) = result else {
            return Ok(None);
        };
        let definition = zstd::decode_all(definition.as_slice())
            .context("Decompressing compiled class definition")?;

        Ok(Some((block_number, definition)))
    }

    /// Returns the uncompressed compiled class definition if it has been
    /// declared at `block_id`.
    pub fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.casm_definition_at_with_block_number(block_id, class_hash)
            .map(|option| option.map(|(_block_number, definition)| definition))
    }

    /// Returns the uncompressed compiled class definition if it has been
    /// declared at `block_id`, as well as the block number at which it was
    /// declared.
    pub fn casm_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
        let from_row = |row: &rusqlite::Row<'_>| {
            let definition = row.get_blob(0).map(|x| x.to_vec())?;
            let block_number = row.get_optional_block_number(1)?;
            Ok((block_number, definition))
        };

        let definition = match block_id {
        BlockId::Latest => {
            let mut stmt = self.inner().prepare_cached(
                r"SELECT
                casm_definitions.definition,
                class_definitions.block_number
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number IS NOT NULL"
            )?;
            stmt.query_row(params![&class_hash],from_row)
        }
        BlockId::Number(number) => {
            let mut stmt = self.inner().prepare_cached(
                r"SELECT
                casm_definitions.definition,
                class_definitions.block_number
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number <= ?")?;
            stmt.query_row(params![&class_hash, &number], from_row,)
        },
        BlockId::Hash(hash) => {
            let mut stmt = self.inner().prepare_cached(
            r"SELECT
                casm_definitions.definition,
                class_definitions.block_number
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number <= (SELECT number FROM block_headers WHERE hash = ?)")?;
            stmt.query_row(params![&class_hash, &hash], from_row)
        },
    }
    .optional()
    .context("Querying for compiled class definition")?;

        let Some((block_number, definition)) = definition else {
            return Ok(None);
        };
        let definition = zstd::decode_all(definition.as_slice())
            .context("Decompressing compiled class definition")?;

        Ok(Some((block_number, definition)))
    }

    /// Returns the compiled class hash for a class.
    pub fn casm_hash(&self, class_hash: ClassHash) -> anyhow::Result<Option<CasmHash>> {
        let mut stmt = self.inner().prepare_cached(
            "SELECT compiled_class_hash FROM casm_class_hashes WHERE hash = ? ORDER BY \
             block_number DESC LIMIT 1",
        )?;
        let compiled_class_hash = stmt
            .query_row(params![&class_hash], |row| row.get_casm_hash(0))
            .optional()
            .context("Querying for compiled class definition")?;

        Ok(compiled_class_hash)
    }

    /// Returns the compiled class hash for a class if it has been declared at
    /// `block_id`.
    pub fn casm_hash_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<CasmHash>> {
        let compiled_class_hash = match block_id {
            BlockId::Latest => {
                let mut stmt = self.inner().prepare_cached(
                    r"SELECT
                        compiled_class_hash 
                    FROM
                        casm_class_hashes
                    WHERE
                        hash = ?
                        AND block_number IS NOT NULL
                    ORDER BY
                        block_number DESC
                    LIMIT 1
                    ",
                )?;
                stmt.query_row(params![&class_hash], |row| row.get_casm_hash(0))
            }
            BlockId::Number(number) => {
                let mut stmt = self.inner().prepare_cached(
                    r"SELECT
                        compiled_class_hash 
                    FROM
                        casm_class_hashes
                    WHERE
                        hash = ?
                        AND block_number <= ?
                    ORDER BY
                        block_number DESC
                    LIMIT 1",
                )?;
                stmt.query_row(params![&class_hash, &number], |row| row.get_casm_hash(0))
            }
            BlockId::Hash(hash) => {
                let mut stmt = self.inner().prepare_cached(
                    r"SELECT
                        compiled_class_hash 
                    FROM
                        casm_class_hashes
                    WHERE
                        hash = ?
                        AND block_number <= (SELECT number FROM block_headers WHERE hash = ?)
                    ORDER BY
                        block_number DESC
                    LIMIT 1",
                )?;
                stmt.query_row(params![&class_hash, &hash], |row| row.get_casm_hash(0))
            }
        }
        .optional()
        .context("Querying for class definition")?;

        Ok(compiled_class_hash)
    }

    /// Returns the Blake2 compiled class hash for a class.
    pub fn casm_hash_v2(&self, class_hash: ClassHash) -> anyhow::Result<Option<CasmHash>> {
        let mut stmt = self.inner().prepare_cached(
            "SELECT compiled_class_hash FROM casm_class_hashes_v2 WHERE hash = ?",
        )?;
        let compiled_class_hash = stmt
            .query_row(params![&class_hash], |row| row.get_casm_hash(0))
            .optional()
            .context("Querying for compiled class definition")?;

        Ok(compiled_class_hash)
    }

    pub fn is_sierra(&self, class_hash: ClassHash) -> anyhow::Result<Option<bool>> {
        let mut stmt = self.inner().prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM casm_definitions WHERE casm_definitions.hash = ?)",
        )?;

        let is_sierra = stmt
            .query_row(params![&class_hash], |row| row.get(0))
            .optional()
            .context("Querying if class is sierra")?;

        Ok(is_sierra)
    }

    pub fn insert_class_commitment_leaf(
        &self,
        block: BlockNumber,
        leaf: &ClassCommitmentLeafHash,
        casm_hash: &CasmHash,
    ) -> anyhow::Result<()> {
        self.inner().execute(
            "INSERT INTO class_commitment_leaves (block_number, leaf, casm) VALUES (?, ?, ?)",
            params![&block, leaf, casm_hash],
        )?;

        Ok(())
    }

    pub fn class_commitment_leaf(
        &self,
        block: BlockNumber,
        casm_hash: &CasmHash,
    ) -> anyhow::Result<Option<ClassCommitmentLeafHash>> {
        let mut stmt = self.inner().prepare_cached(
            "SELECT leaf FROM class_commitment_leaves WHERE casm = ? AND block_number <= ?",
        )?;
        stmt.query_row(params![casm_hash, &block], |row| {
            row.get_class_commitment_leaf(0)
        })
        .optional()
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;

    use super::*;

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = class_hash!("0x123");

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        transaction
            .insert_cairo_class_definition(hash, definition)
            .unwrap();

        (
            hash,
            br#"{"huge":"hash"}"#,
            serde_json::json!({"this might be a":"hash"}),
        )
    }

    #[test]
    fn class_existence() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let transaction = connection.transaction().unwrap();

        let (hash, _, _) = setup_class(&transaction);
        let non_existent = class_hash!("0x456");

        let result = transaction
            .class_definitions_exist(&[hash, non_existent])
            .unwrap();
        let expected = vec![true, false];
        assert_eq!(result, expected);
    }

    #[test]
    fn insert_cairo() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let cairo_hash = class_hash_bytes!(b"cairo hash");
        let cairo_definition = b"example cairo program";

        tx.insert_cairo_class_definition(cairo_hash, cairo_definition)
            .unwrap();

        let definition = tx.class_definition(cairo_hash).unwrap().unwrap();

        assert_eq!(definition, cairo_definition);
    }

    #[test]
    fn insert_sierra() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let sierra_hash = sierra_hash_bytes!(b"sierra hash");
        let sierra_definition = b"example sierra program";
        let casm_definition = b"compiled sierra program";
        let casm_hash_v2 = casm_hash_bytes!(b"casm hash blake");

        tx.insert_sierra_class_definition(
            &sierra_hash,
            sierra_definition,
            casm_definition,
            &casm_hash_v2,
        )
        .unwrap();

        let definition = tx
            .casm_definition(ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(definition, casm_definition);

        let definition = tx
            .class_definition(ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(definition, sierra_definition);

        let retrieved_casm_hash_v2 = tx.casm_hash_v2(ClassHash(sierra_hash.0)).unwrap().unwrap();
        assert_eq!(retrieved_casm_hash_v2, casm_hash_v2);
    }

    #[test]
    fn compiled_class_leaves() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let leaf0 = class_commitment_leaf_hash_bytes!(b"genesis leaf");
        let casm0 = casm_hash_bytes!(b"genesis casm");

        let leaf1 = class_commitment_leaf_hash_bytes!(b"leaf one");
        let casm1 = casm_hash_bytes!(b"casm one");

        tx.insert_class_commitment_leaf(BlockNumber::GENESIS, &leaf0, &casm0)
            .unwrap();
        tx.insert_class_commitment_leaf(BlockNumber::GENESIS + 5, &leaf1, &casm0)
            .unwrap();
        tx.insert_class_commitment_leaf(BlockNumber::GENESIS + 5, &leaf1, &casm1)
            .unwrap();

        let result = tx
            .class_commitment_leaf(BlockNumber::GENESIS, &casm_hash_bytes!(b"missing"))
            .unwrap();
        assert!(result.is_none());

        let result = tx
            .class_commitment_leaf(BlockNumber::GENESIS, &casm0)
            .unwrap();
        assert_eq!(result, Some(leaf0));

        let result = tx
            .class_commitment_leaf(BlockNumber::GENESIS, &casm1)
            .unwrap();
        assert!(result.is_none());
    }
}
