use anyhow::Context;
use pathfinder_common::class_definition::{
    SerializedCairoDefinition,
    SerializedCasmDefinition,
    SerializedClassDefinition,
    SerializedSierraDefinition,
};
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
        sierra_definition: &SerializedSierraDefinition,
        casm_definition: &SerializedCasmDefinition,
        // Blake2 hash of the compiled class definition
        casm_hash_v2: &CasmHash,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let compressed_sierra_definition = compressor
            .compress(sierra_definition.as_bytes())
            .context("Compressing sierra definition")?;
        let compressed_casm_definition = compressor
            .compress(casm_definition.as_bytes())
            .context("Compressing casm definition")?;

        self.inner()
            .execute(
                "INSERT INTO class_definitions (hash, definition) VALUES (?, ?)
                ON CONFLICT(hash) DO UPDATE SET definition = excluded.definition
                WHERE class_definitions.definition IS NULL",
                params![sierra_hash, &compressed_sierra_definition],
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
                    ":definition": &compressed_casm_definition,
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
        sierra_definition: &SerializedSierraDefinition,
        casm_definition: &SerializedCasmDefinition,
        casm_hash_v2: &CasmHash,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let compressed_sierra_definition = compressor
            .compress(sierra_definition.as_bytes())
            .context("Compressing sierra definition")?;
        let compressed_casm_definition = compressor
            .compress(casm_definition.as_bytes())
            .context("Compressing casm definition")?;

        self.inner()
            .execute(
                r"UPDATE class_definitions SET definition=:definition WHERE hash=:hash",
                named_params! {
                    ":definition": &compressed_sierra_definition,
                    ":hash": sierra_hash
                },
            )
            .context("Updating sierra definition")?;

        self.inner()
            .execute(
                r"INSERT OR REPLACE INTO casm_definitions(hash, definition) VALUES(:hash, :definition)",
                named_params! {
                    ":definition": &compressed_casm_definition,
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
        definition: &SerializedCairoDefinition,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let compressed_definition = compressor
            .compress(definition.as_bytes())
            .context("Compressing cairo definition")?;

        self.inner()
            .execute(
                r"INSERT INTO class_definitions (hash, definition) VALUES (?, ?)
                ON CONFLICT(hash) DO UPDATE SET definition = excluded.definition
                WHERE class_definitions.definition IS NULL",
                params![&cairo_hash, &compressed_definition],
            )
            .context("Inserting cairo definition")?;

        Ok(())
    }

    pub fn update_cairo_class_definition(
        &self,
        cairo_hash: ClassHash,
        definition: &SerializedCairoDefinition,
    ) -> anyhow::Result<()> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
        let compressed_definition = compressor
            .compress(definition.as_bytes())
            .context("Compressing cairo definition")?;

        self.inner()
            .execute(
                r"UPDATE class_definitions SET definition=? WHERE hash=?",
                params![&compressed_definition, &cairo_hash],
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
        let mut stmt = self.inner().prepare_cached(
            "SELECT 1 FROM class_definitions WHERE hash = ? AND definition IS NOT NULL",
        )?;

        Ok(classes
            .iter()
            .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Returns the uncompressed class definition.
    pub fn class_definition(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<SerializedClassDefinition>> {
        self.class_definition_with_block_number(class_hash)
            .map(|option| option.map(|(_block_number, definition)| definition))
    }

    /// Returns the uncompressed class definition as well as the block number at
    /// which it was declared.
    pub fn class_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, SerializedClassDefinition)>> {
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

        Ok(Some((
            block_number,
            SerializedClassDefinition::from_bytes(definition),
        )))
    }

    fn compressed_class_definition_at_with_block_number(
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
    ) -> anyhow::Result<Option<SerializedClassDefinition>> {
        self.class_definition_at_with_block_number(block_id, class_hash)
            .map(|option| option.map(|(_, definition)| definition))
    }

    /// Returns the uncompressed class definition if it has been declared at
    /// `block_id`, as well as the block number at which it was declared.
    pub fn class_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(BlockNumber, SerializedClassDefinition)>> {
        let definition =
            self.compressed_class_definition_at_with_block_number(block_id, class_hash)?;
        let Some((block_number, definition)) = definition else {
            return Ok(None);
        };
        let definition =
            zstd::decode_all(definition.as_slice()).context("Decompressing class definition")?;
        let definition = SerializedClassDefinition::from_bytes(definition);

        Ok(Some((block_number, definition)))
    }

    /// Returns the uncompressed compiled class definition.
    pub fn casm_definition(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<SerializedCasmDefinition>> {
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

        Ok(Some(SerializedCasmDefinition::from_bytes(definition)))
    }

    /// Returns the uncompressed compiled class definition, as well as the block
    /// number at which it  was declared.
    pub fn casm_definition_with_block_number(
        &self,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, SerializedCasmDefinition)>> {
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

        Ok(Some((
            block_number,
            SerializedCasmDefinition::from_bytes(definition),
        )))
    }

    /// Returns the uncompressed compiled class definition if it has been
    /// declared at `block_id`.
    pub fn casm_definition_at(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<SerializedCasmDefinition>> {
        self.casm_definition_at_with_block_number(block_id, class_hash)
            .map(|option| option.map(|(_, definition)| definition))
    }

    /// Returns the uncompressed compiled class definition if it has been
    /// declared at `block_id`, as well as the block number at which it was
    /// declared.
    pub fn casm_definition_at_with_block_number(
        &self,
        block_id: BlockId,
        class_hash: ClassHash,
    ) -> anyhow::Result<Option<(Option<BlockNumber>, SerializedCasmDefinition)>> {
        let from_row = |row: &rusqlite::Row<'_>| {
            let compressed_definition = row.get_blob(0).map(|x| x.to_vec())?;
            let block_number = row.get_optional_block_number(1)?;
            Ok((block_number, compressed_definition))
        };

        let compressed_definition = match block_id {
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

        let Some((block_number, compressed_definition)) = compressed_definition else {
            return Ok(None);
        };
        let definition = zstd::decode_all(compressed_definition.as_slice())
            .context("Decompressing compiled class definition")?;

        Ok(Some((
            block_number,
            SerializedCasmDefinition::from_bytes(definition),
        )))
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

    pub fn class_hashes_with_missing_definitions(&self) -> anyhow::Result<Vec<ClassHash>> {
        let mut stmt = self
            .inner()
            .prepare_cached("SELECT hash FROM class_definitions WHERE definition IS NULL")?;

        let hashes = stmt
            .query_map([], |row| row.get_class_hash(0))
            .context("Querying class hashes with missing definitions")?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(hashes)
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

    fn insert_placeholder(transaction: &Transaction<'_>, hash: ClassHash) {
        transaction
            .inner()
            .execute(
                "INSERT INTO class_definitions (hash, block_number) VALUES (?, 0)",
                rusqlite::params![&hash.0.to_be_bytes()[..]],
            )
            .unwrap();
    }

    #[test]
    fn class_definitions_exist_ignores_placeholder() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let hash = class_hash!("0xabc");
        insert_placeholder(&tx, hash);

        let result = tx.class_definitions_exist(&[hash]).unwrap();
        assert_eq!(result, vec![false]);
    }

    #[test]
    fn insert_cairo_fills_placeholder() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let hash = class_hash!("0xabc");
        insert_placeholder(&tx, hash);

        let definition = b"example cairo program";
        tx.insert_cairo_class_definition(hash, &SerializedCairoDefinition::from_slice(definition))
            .unwrap();

        let result = tx.class_definition(hash).unwrap();
        assert_eq!(
            result,
            Some(SerializedClassDefinition::from_slice(definition))
        );
    }

    #[test]
    fn insert_sierra_fills_placeholder() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let sierra_hash = sierra_hash_bytes!(b"sierra hash abc");
        let class_hash = ClassHash(sierra_hash.0);
        insert_placeholder(&tx, class_hash);

        let sierra_definition = b"example sierra program";
        let casm_definition = b"compiled sierra program";
        let casm_hash_v2 = casm_hash_bytes!(b"casm hash blake abc");

        tx.insert_sierra_class_definition(
            &sierra_hash,
            &SerializedSierraDefinition::from_slice(sierra_definition),
            &SerializedCasmDefinition::from_slice(casm_definition),
            &casm_hash_v2,
        )
        .unwrap();

        let result = tx.class_definition(class_hash).unwrap();
        assert_eq!(
            result,
            Some(SerializedClassDefinition::from_slice(sierra_definition))
        );

        let result = tx.casm_definition(class_hash).unwrap();
        assert_eq!(
            result,
            Some(SerializedCasmDefinition::from_slice(casm_definition))
        );
    }

    #[test]
    fn insert_cairo_does_not_overwrite_existing() {
        let mut connection = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = connection.transaction().unwrap();

        let hash = class_hash!("0xabc");
        let definition_a = b"definition A";
        let definition_b = b"definition B";

        tx.insert_cairo_class_definition(
            hash,
            &SerializedCairoDefinition::from_slice(definition_a),
        )
        .unwrap();
        tx.insert_cairo_class_definition(
            hash,
            &SerializedCairoDefinition::from_slice(definition_b),
        )
        .unwrap();

        let result = tx.class_definition(hash).unwrap();
        assert_eq!(
            result,
            Some(SerializedClassDefinition::from_slice(definition_a))
        );
    }

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = class_hash!("0x123");

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        transaction
            .insert_cairo_class_definition(hash, &SerializedCairoDefinition::from_slice(definition))
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

        tx.insert_cairo_class_definition(
            cairo_hash,
            &SerializedCairoDefinition::from_slice(cairo_definition),
        )
        .unwrap();

        let definition = tx.class_definition(cairo_hash).unwrap().unwrap();

        assert_eq!(
            definition,
            SerializedClassDefinition::from_slice(cairo_definition)
        );
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
            &SerializedSierraDefinition::from_slice(sierra_definition),
            &SerializedCasmDefinition::from_slice(casm_definition),
            &casm_hash_v2,
        )
        .unwrap();

        let definition = tx
            .casm_definition(ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(
            definition,
            SerializedCasmDefinition::from_slice(casm_definition)
        );

        let definition = tx
            .class_definition(ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(
            definition,
            SerializedClassDefinition::from_slice(sierra_definition)
        );

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
