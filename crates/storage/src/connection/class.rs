use anyhow::Context;
use pathfinder_common::{BlockNumber, CasmHash, ClassCommitmentLeafHash, ClassHash, SierraHash};

use crate::{prelude::*, BlockId};

pub(super) fn insert_sierra_class(
    transaction: &Transaction<'_>,
    sierra_hash: &SierraHash,
    sierra_definition: &[u8],
    casm_hash: &CasmHash,
    casm_definition: &[u8],
    compiler_version: &str,
) -> anyhow::Result<()> {
    let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
    let sierra_definition = compressor
        .compress(sierra_definition)
        .context("Compressing sierra definition")?;
    let casm_definition = compressor
        .compress(casm_definition)
        .context("Compressing casm definition")?;

    let version_id = intern_compiler_version(transaction, compiler_version)
        .context("Interning compiler version")?;

    transaction
        .inner()
        .execute(
            r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
            params![sierra_hash, &sierra_definition],
        )
        .context("Inserting sierra definition")?;

    transaction
        .inner()
        .execute(
            r"INSERT OR REPLACE INTO casm_definitions
                (hash, definition, compiled_class_hash, compiler_version_id)
            VALUES
                (:hash, :definition, :compiled_class_hash, :compiler_version_id)",
            named_params! {
                ":hash": sierra_hash,
                ":definition": &casm_definition,
                ":compiled_class_hash": casm_hash,
                ":compiler_version_id": &version_id,
            },
        )
        .context("Inserting casm definition")?;

    Ok(())
}

pub(super) fn insert_cairo_class(
    transaction: &Transaction<'_>,
    cairo_hash: ClassHash,
    definition: &[u8],
) -> anyhow::Result<()> {
    let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;
    let definition = compressor
        .compress(definition)
        .context("Compressing cairo definition")?;

    transaction
        .inner()
        .execute(
            r"INSERT OR IGNORE INTO class_definitions (hash,  definition) VALUES (?, ?)",
            params![&cairo_hash, &definition],
        )
        .context("Inserting cairo definition")?;

    Ok(())
}

fn intern_compiler_version(
    transaction: &Transaction<'_>,
    compiler_version: &str,
) -> anyhow::Result<i64> {
    let id: Option<i64> = transaction
        .inner()
        .query_row(
            "SELECT id FROM casm_compiler_versions WHERE version = ?",
            [compiler_version],
            |r| Ok(r.get_unwrap(0)),
        )
        .optional()
        .context("Querying for an existing casm compiler version")?;

    let id = if let Some(id) = id {
        id
    } else {
        // sqlite "autoincrement" for integer primary keys works like this: we leave it out of
        // the insert, even though it's not null, it will get max(id)+1 assigned, which we can
        // read back with last_insert_rowid

        transaction
            .inner()
            .query_row(
                "INSERT INTO casm_compiler_versions(version) VALUES (?) RETURNING id",
                [compiler_version],
                |row| row.get(0),
            )
            .context("Inserting unique casm_compiler_version")?
    };

    Ok(id)
}

/// Returns whether or not the given class definitions exist.
pub(super) fn classes_exist(
    transaction: &Transaction<'_>,
    classes: &[ClassHash],
) -> anyhow::Result<Vec<bool>> {
    let mut stmt = transaction
        .inner()
        .prepare("SELECT 1 FROM class_definitions WHERE hash = ?")?;

    Ok(classes
        .iter()
        .map(|hash| stmt.exists([&hash.0.to_be_bytes()[..]]))
        .collect::<Result<Vec<_>, _>>()?)
}

pub(super) fn class_definition(
    transaction: &Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    self::class_definition_with_block_number(transaction, class_hash)
        .map(|option| option.map(|(_block_number, definition)| definition))
}

pub(super) fn class_definition_with_block_number(
    transaction: &Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
    let from_row = |row: &rusqlite::Row<'_>| {
        let definition = row.get_blob(0).map(|x| x.to_vec())?;
        let block_number = row.get_optional_block_number(1)?;
        Ok((block_number, definition))
    };

    let result = transaction
        .inner()
        .query_row(
            "SELECT definition, block_number FROM class_definitions WHERE hash = ?",
            params![&class_hash],
            from_row,
        )
        .optional()
        .context("Querying for class definition")?;

    let Some((block_number, definition)) = result else {
        return Ok(None);
    };
    let definition =
        zstd::decode_all(definition.as_slice()).context("Decompressing class definition")?;

    Ok(Some((block_number, definition)))
}

pub(super) fn compressed_class_definition_at(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    self::compressed_class_definition_at_with_block_number(tx, block_id, class_hash)
        .map(|option| option.map(|(_block_number, definition)| definition))
}

pub(super) fn compressed_class_definition_at_with_block_number(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<(BlockNumber, Vec<u8>)>> {
    let from_row = |row: &rusqlite::Row<'_>| {
        let definition = row.get_blob(0).map(|x| x.to_vec())?;
        let block_number = row.get_block_number(1)?;
        Ok((block_number, definition))
    };

    match block_id {
        BlockId::Latest => tx.inner().query_row(
            "SELECT definition, block_number FROM class_definitions WHERE hash=? AND block_number IS NOT NULL",
            params![&class_hash],
            from_row,
        ),
        BlockId::Number(number) => tx.inner().query_row(
            "SELECT definition, block_number FROM class_definitions WHERE hash=? AND block_number <= ?",
            params![&class_hash, &number],
            from_row,
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r"SELECT definition, block_number FROM class_definitions
                WHERE hash = ? AND block_number <= (SELECT number from canonical_blocks WHERE hash = ?)",
            params![&class_hash, &hash],
            from_row,
        ),
    }
    .optional()
    .context("Querying for class definition")
}

pub(super) fn class_definition_at(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    self::class_definition_at_with_block_number(tx, block_id, class_hash)
        .map(|option| option.map(|(_block_number, definition)| definition))
}

pub(super) fn class_definition_at_with_block_number(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<(BlockNumber, Vec<u8>)>> {
    let definition = compressed_class_definition_at_with_block_number(tx, block_id, class_hash)?;
    let Some((block_number, definition)) = definition else {
        return Ok(None);
    };
    let definition =
        zstd::decode_all(definition.as_slice()).context("Decompressing class definition")?;

    Ok(Some((block_number, definition)))
}

pub(super) fn casm_definition(
    transaction: &Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    // Don't reuse the "_with_block_number" impl here since the suffixed one requires a join that this one doesn't.
    let definition = transaction
        .inner()
        .query_row(
            "SELECT definition FROM casm_definitions WHERE hash = ?",
            params![&class_hash],
            |row| row.get_blob(0).map(|x| x.to_vec()),
        )
        .optional()
        .context("Querying for compiled class definition")?;

    let Some(definition) = definition else {
        return Ok(None);
    };
    let definition = zstd::decode_all(definition.as_slice())
        .context("Decompressing compiled class definition")?;

    Ok(Some(definition))
}

pub(super) fn casm_definition_with_block_number(
    transaction: &Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
    let from_row = |row: &rusqlite::Row<'_>| {
        let definition = row.get_blob(0).map(|x| x.to_vec())?;
        let block_number = row.get_optional_block_number(1)?;
        Ok((block_number, definition))
    };

    let result = transaction
        .inner()
        .query_row(
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
            params![&class_hash],
            from_row,
        )
        .optional()
        .context("Querying for compiled class definition")?;

    let Some((block_number, definition)) = result else {
        return Ok(None);
    };
    let definition = zstd::decode_all(definition.as_slice())
        .context("Decompressing compiled class definition")?;

    Ok(Some((block_number, definition)))
}

pub(super) fn casm_definition_at(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    self::casm_definition_at_with_block_number(tx, block_id, class_hash)
        .map(|option| option.map(|(_block_number, definition)| definition))
}

pub(super) fn casm_definition_at_with_block_number(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<(Option<BlockNumber>, Vec<u8>)>> {
    let from_row = |row: &rusqlite::Row<'_>| {
        let definition = row.get_blob(0).map(|x| x.to_vec())?;
        let block_number = row.get_optional_block_number(1)?;
        Ok((block_number, definition))
    };

    let definition = match block_id {
        BlockId::Latest => tx.inner().query_row(
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
                AND class_definitions.block_number IS NOT NULL",
            params![&class_hash],
            from_row,
        ),
        BlockId::Number(number) => tx.inner().query_row(
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
                AND class_definitions.block_number <= ?",
            params![&class_hash, &number],
            from_row,
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
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
                AND class_definitions.block_number <= (SELECT number FROM canonical_blocks WHERE hash = ?)",
            params![&class_hash, &hash],
            from_row,
        ),
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

pub(super) fn casm_hash(
    tx: &Transaction<'_>,
    class_hash: ClassHash,
) -> anyhow::Result<Option<CasmHash>> {
    let compiled_class_hash = tx
        .inner()
        .query_row(
            r#"SELECT
                casm_definitions.compiled_class_hash
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?"#,
            params![&class_hash],
            |row| row.get_casm_hash(0),
        )
        .optional()
        .context("Querying for compiled class definition")?;

    Ok(compiled_class_hash)
}

pub(super) fn casm_hash_at(
    tx: &Transaction<'_>,
    block_id: BlockId,
    class_hash: ClassHash,
) -> anyhow::Result<Option<CasmHash>> {
    let compiled_class_hash = match block_id {
        BlockId::Latest => tx.inner().query_row(
            r#"SELECT
                casm_definitions.compiled_class_hash 
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number IS NOT NULL"#,
            params![&class_hash],
            |row| row.get_casm_hash(0),
        ),
        BlockId::Number(number) => tx.inner().query_row(
            r#"SELECT
                casm_definitions.compiled_class_hash 
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number <= ?"#,
            params![&class_hash, &number],
            |row| row.get_casm_hash(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r#"SELECT
                casm_definitions.compiled_class_hash 
            FROM
                casm_definitions
                INNER JOIN class_definitions ON (
                    class_definitions.hash = casm_definitions.hash
                )
            WHERE
                casm_definitions.hash = ?
                AND class_definitions.block_number <= (SELECT number FROM canonical_blocks WHERE hash = ?)"#,
            params![&class_hash, &hash],
            |row| row.get_casm_hash(0),
        ),
    }
    .optional()
    .context("Querying for class definition")?;

    Ok(compiled_class_hash)
}

pub(super) fn insert_class_commitment_leaf(
    transaction: &Transaction<'_>,
    block: BlockNumber,
    leaf: &ClassCommitmentLeafHash,
    casm_hash: &CasmHash,
) -> anyhow::Result<()> {
    transaction.inner().execute(
        "INSERT INTO class_commitment_leaves (block_number, leaf, casm) VALUES (?, ?, ?)",
        params![&block, leaf, casm_hash],
    )?;

    Ok(())
}

pub(super) fn class_commitment_leaf(
    transaction: &Transaction<'_>,
    block: BlockNumber,
    casm_hash: &CasmHash,
) -> anyhow::Result<Option<ClassCommitmentLeafHash>> {
    transaction
        .inner()
        .query_row(
            "SELECT leaf FROM class_commitment_leaves WHERE casm = ? AND block_number <= ?",
            params![casm_hash, &block],
            |row| row.get_class_commitment_leaf(0),
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_crypto::Felt;

    fn setup_class(transaction: &Transaction<'_>) -> (ClassHash, &'static [u8], serde_json::Value) {
        let hash = class_hash!("0x123");

        let definition = br#"{"abi":{"see":"above"},"program":{"huge":"hash"},"entry_points_by_type":{"this might be a":"hash"}}"#;

        transaction.insert_cairo_class(hash, definition).unwrap();

        (
            hash,
            br#"{"huge":"hash"}"#,
            serde_json::json!({"this might be a":"hash"}),
        )
    }

    #[test]
    fn class_existence() {
        let mut connection = Storage::in_memory().unwrap().connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let (hash, _, _) = setup_class(&transaction);
        let non_existent = class_hash!("0x456");

        let result = super::classes_exist(&transaction, &[hash, non_existent]).unwrap();
        let expected = vec![true, false];
        assert_eq!(result, expected);
    }

    #[test]
    fn compiler_version_interning() {
        let mut connection = Storage::in_memory().unwrap().connection().unwrap();
        let transaction = connection.transaction().unwrap();

        let alpha = intern_compiler_version(&transaction, "alpha").unwrap();
        let alpha_again = intern_compiler_version(&transaction, "alpha").unwrap();
        assert_eq!(alpha, alpha_again);

        let beta = intern_compiler_version(&transaction, "beta").unwrap();
        assert_ne!(alpha, beta);

        let beta_again = intern_compiler_version(&transaction, "beta").unwrap();
        assert_eq!(beta, beta_again);

        for i in 0..10 {
            intern_compiler_version(&transaction, i.to_string().as_str()).unwrap();
        }

        let alpha_again2 = intern_compiler_version(&transaction, "alpha").unwrap();
        assert_eq!(alpha, alpha_again2);
    }

    #[test]
    fn insert_cairo() {
        let mut connection = Storage::in_memory().unwrap().connection().unwrap();
        let tx = connection.transaction().unwrap();

        let cairo_hash = class_hash_bytes!(b"cairo hash");
        let cairo_definition = b"example cairo program";

        insert_cairo_class(&tx, cairo_hash, cairo_definition).unwrap();

        let definition = class_definition(&tx, cairo_hash).unwrap().unwrap();

        assert_eq!(definition, cairo_definition);
    }

    #[test]
    fn insert_sierra() {
        let mut connection = Storage::in_memory().unwrap().connection().unwrap();
        let tx = connection.transaction().unwrap();

        let sierra_hash = sierra_hash_bytes!(b"sierra hash");
        let casm_hash = casm_hash_bytes!(b"casm hash");
        let sierra_definition = b"example sierra program";
        let casm_definition = b"compiled sierra program";
        let version = "compiler version";

        insert_sierra_class(
            &tx,
            &sierra_hash,
            sierra_definition,
            &casm_hash,
            casm_definition,
            version,
        )
        .unwrap();

        let casm_result = tx
            .inner().query_row(
                r"SELECT * FROM casm_definitions 
                    JOIN casm_compiler_versions ON casm_definitions.compiler_version_id = casm_compiler_versions.id 
                    WHERE hash = ?",
                params![&sierra_hash],
                |row| {
                    let casm_hash = row.get_blob("compiled_class_hash").unwrap();
                    let casm_hash = CasmHash(Felt::from_be_slice(casm_hash).unwrap());

                    let casm_definition = row.get_blob("definition").unwrap().to_vec();
                    let casm_definition = zstd::decode_all(casm_definition.as_slice()).unwrap();

                    let version: String = row.get("version").unwrap();

                    Ok((casm_hash, casm_definition, version))
                },
            )
            .unwrap();

        assert_eq!(casm_result.0, casm_hash);
        assert_eq!(casm_result.1, casm_definition);
        assert_eq!(casm_result.2, version);

        let definition = class_definition(&tx, ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(definition, sierra_definition);
    }

    #[test]
    fn compiled_class_leaves() {
        let mut connection = Storage::in_memory().unwrap().connection().unwrap();
        let tx = connection.transaction().unwrap();

        let leaf0 = class_commitment_leaf_hash_bytes!(b"genesis leaf");
        let casm0 = casm_hash_bytes!(b"genesis casm");

        let leaf1 = class_commitment_leaf_hash_bytes!(b"leaf one");
        let casm1 = casm_hash_bytes!(b"casm one");

        insert_class_commitment_leaf(&tx, BlockNumber::GENESIS, &leaf0, &casm0).unwrap();
        insert_class_commitment_leaf(&tx, BlockNumber::GENESIS + 5, &leaf1, &casm0).unwrap();
        insert_class_commitment_leaf(&tx, BlockNumber::GENESIS + 5, &leaf1, &casm1).unwrap();

        let result =
            class_commitment_leaf(&tx, BlockNumber::GENESIS, &casm_hash_bytes!(b"missing"))
                .unwrap();
        assert!(result.is_none());

        let result = class_commitment_leaf(&tx, BlockNumber::GENESIS, &casm0).unwrap();
        assert_eq!(result, Some(leaf0));

        let result = class_commitment_leaf(&tx, BlockNumber::GENESIS, &casm1).unwrap();
        assert!(result.is_none());
    }
}
