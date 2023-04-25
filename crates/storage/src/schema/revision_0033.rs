use anyhow::Context;
use rusqlite::Transaction;

/// This migration replaces block hash with block number for class_definitions.
///
/// This enables range querying when the class was declared.
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        "ALTER TABLE class_definitions ADD COLUMN block_number INTEGER REFERENCES canonical_blocks(number) DEFAULT NULL",
        [],
    )
    .context("Adding block_number column to class_definitions table")?;

    tx.execute(
        r"UPDATE class_definitions SET block_number = (
            SELECT canonical_blocks.number FROM class_definitions JOIN canonical_blocks ON (class_definitions.declared_on = canonical_blocks.hash)
        )", 
        []
    )
    .context("Copying block numbers into class_definitions table")?;

    tx.execute("ALTER TABLE class_definitions DROP COLUMN declared_on", [])
        .context("Dropping declared_on column from class_definitions table")?;

    Ok(())
}

// 191|016B00CD0ED871BCCDFED41FAC05EF64C025F6DF61A8369D62DB777BC0872F62|071B7F73B5E2B4F81F7CF01D4D1569CCBA2921B3FA3170CF11CFF3720DFE918E
