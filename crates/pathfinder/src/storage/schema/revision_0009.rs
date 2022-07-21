use anyhow::Context;
use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // Add new columns to the blocks table
    transaction
        .execute_batch(
            r"ALTER TABLE starknet_blocks ADD COLUMN gas_price BLOB NOT NULL
            DEFAULT X'00000000000000000000000000000000';
            ALTER TABLE starknet_blocks ADD COLUMN sequencer_address BLOB NOT NULL
            DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000';",
        )
        .context("Add columns gas_price and starknet_address to starknet_blocks table")?;

    Ok(())
}
