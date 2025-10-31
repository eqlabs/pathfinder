use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Migrating CASM definitions");

    tx.execute_batch(
        r"
        CREATE TABLE casm_definitions_new(
            hash                BLOB    NOT NULL,
            block_number        INTEGER NOT NULL,
            compiled_class_hash BLOB    NOT NULL,
            definition          BLOB,
            FOREIGN KEY(hash) REFERENCES class_definitions(hash) ON DELETE CASCADE
        );
        CREATE UNIQUE INDEX casm_definitions_hash_block_number
            ON casm_definitions_new(hash, block_number);
        ",
    )
    .context("Creating new casm_definitions table")?;

    tx.execute_batch(
        r"
        INSERT INTO
            casm_definitions_new(hash, block_number, compiled_class_hash, definition)
        SELECT
            cd.hash AS hash,
            cd.block_number AS block_number,
            cdm.compiled_class_hash AS compiled_class_hash,
            cdm.definition AS definition
        FROM
            class_definitions cd
        INNER JOIN
            casm_definitions cdm ON cd.hash = cdm.hash;
        ",
    )
    .context("Transferring data to new casm_definitions table")?;

    tx.execute_batch(
        r"
        DROP TABLE casm_definitions;
        ALTER TABLE casm_definitions_new RENAME TO casm_definitions;
        ",
    )
    .context("Finalizing casm_definitions table migration")?;

    Ok(())
}
