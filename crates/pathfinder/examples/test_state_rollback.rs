use std::{num::NonZeroU32, time::Instant};

use anyhow::Context;
use pathfinder_common::BlockNumber;
use pathfinder_storage::{BlockId, JournalMode, Storage};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let database_path = std::env::args().nth(1).unwrap();
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL, 1)?
        .create_pool(NonZeroU32::new(10).unwrap())?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest_block = {
        let tx = db.transaction().unwrap();
        let (latest_block, _) = tx.block_id(BlockId::Latest)?.unwrap();
        latest_block.get()
    };
    let from: u64 = std::env::args()
        .nth(2)
        .map(|s| str::parse(&s).unwrap())
        .unwrap();
    let to: u64 = std::env::args()
        .nth(3)
        .map(|s| str::parse(&s).unwrap())
        .unwrap();
    assert!(from <= latest_block);
    assert!(from > to);
    let from = BlockNumber::new_or_panic(from);
    let to = BlockNumber::new_or_panic(to);

    tracing::info!(%from, %to, "Testing state rollback");

    let started = Instant::now();

    let tx = db.transaction()?;

    let to_header = tx.block_header(to.into()).unwrap().unwrap();

    pathfinder_merkle_tree::revert_class_updates(&tx, from, to, to_header.class_commitment, true)?;

    pathfinder_merkle_tree::contract_state::revert_contract_updates(
        &tx,
        from,
        to,
        to_header.storage_commitment,
        true,
    )?;

    tracing::info!(
        from=%from,
        to=%to,
        total = ?started.elapsed(),
        "Finished state rollback"
    );

    // Explicitly do _not_ commit transaction
    drop(tx);

    Ok(())
}
