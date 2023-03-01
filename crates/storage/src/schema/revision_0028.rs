/// This migration adds a new table storing compiled CASM classes.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute_batch(
        r"
        ALTER TABLE contract_code RENAME TO class_definitions;

        -- Stores compiled CASM for Sierra classes.
        CREATE TABLE casm_definitions (
            hash                BLOB    PRIMARY KEY NOT NULL,
            compiled_class_hash BLOB    NOT NULL,
            definition          BLOB    NOT NULL,
            FOREIGN KEY(hash) REFERENCES class_definitions(hash) ON DELETE CASCADE
        );

        CREATE INDEX casm_definitions_compiled_class_hash ON casm_definitions(compiled_class_hash);
        ",
    )
    .context("Creating casm_definitions table and indexes")?;
    Ok(())
}
