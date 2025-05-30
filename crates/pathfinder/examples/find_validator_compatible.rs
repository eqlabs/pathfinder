//! Find blocks that are compatible with the proposal validator, ie blocks that
//! only contain DeclareV3, DeployAccountV3, InvokeV3 and L1Handler
//! transactions.
use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::BlockNumber;
use pathfinder_storage::{BlockId, StorageBuilder};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_path = std::env::args()
        .nth(1)
        .context("Please provide the database path as the first argument")?;

    let storage = StorageBuilder::file(database_path.into())
        .migrate()
        .context("Migrating database")?
        .create_read_only_pool(NonZeroU32::new(1).expect("1>0"))
        .context("Creating connection pool")?;

    let mut db_conn = storage.connection().context("Create database connection")?;

    let db_txn = db_conn
        .transaction()
        .context("Create database transaction")?;

    find_compatible_blocks(&db_txn)?;

    Ok(())
}

/// Create a valid sequence of proposal parts for the given block.
fn find_compatible_blocks(db_txn: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<()> {
    let latest = db_txn
        .block_number(BlockId::Latest)
        .context("Getting latest block number")?
        .context("No blocks found")?
        .get();

    (0..=latest).try_for_each(|block_number| {
        let txns = db_txn
            .transactions_for_block(BlockNumber::new(block_number).expect("is valid").into())?
            .context("Block not found")?;
        if !txns.into_iter().any(|t| {
            !matches!(
                t.variant,
                TransactionVariant::DeclareV3(_)
                    | TransactionVariant::DeployAccountV3(_)
                    | TransactionVariant::InvokeV3(_)
                    | TransactionVariant::L1Handler(_)
            )
        }) {
            println!("{block_number}");
        }
        anyhow::Ok(())
    })?;

    Ok(())
}
