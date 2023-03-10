use anyhow::Context;
use rusqlite::named_params;

/// This migration adds class commitment tree leaf hashes to the casm_definitions table.
///
/// We need the leaf hash value to be able to look up the compiled class hash based on the
/// leaf hash value in the class commitment tree.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
        -- Stores class commitment leaf hash to compiled class hash mappings.
        CREATE TABLE class_commitment_leaves (
            hash                BLOB    PRIMARY KEY NOT NULL,
            compiled_class_hash BLOB    NOT NULL
        );
        ",
    )
    .context("Adding class_commitment_leaves table")?;

    let mut query_statement = tx
        .prepare(r"SELECT compiled_class_hash FROM casm_definitions")
        .context("Preparing statement for reading casm_definitions table")?;
    let mut insert_statement = tx
        .prepare(
            r"INSERT INTO class_commitment_leaves
                (hash, compiled_class_hash)
            VALUES
                (:leaf_hash, :compiled_class_hash)
            ON CONFLICT DO NOTHING",
        )
        .context("Preparing statement for adding a leaf hash")?;

    let mut rows = query_statement.query([]).context("Executing query")?;
    while let Some(row) = rows.next()? {
        let compiled_class_hash = row.get_unwrap("compiled_class_hash");

        let class_commitment_leaf_hash =
            pathfinder_common::calculate_class_commitment_leaf_hash(compiled_class_hash);

        insert_statement
            .execute(named_params![
                ":leaf_hash": &class_commitment_leaf_hash,
                ":compiled_class_hash": compiled_class_hash
            ])
            .context("Inserting class commitment leaf")?;
    }

    Ok(())
}
