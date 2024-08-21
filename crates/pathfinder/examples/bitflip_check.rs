use std::num::NonZeroU32;

use anyhow::Context;

// 138069308

fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let index: u64 = std::env::args()
        .nth(2)
        .context("Index missing")?
        .parse()
        .context("Index should be u64")?;
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let db = db.transaction().context("Creating transaction")?;

    // Sanity check
    let contract = db
        .contract_trie_node_hash(index)
        .context("Getting contract trie node hash")?;
    if contract.is_some() {
        eprintln!("Whoa! Index {index} should be missing dude!");
    }

    for shift in 0..63 {
        let mask = 1u64 << shift;
        let new_idx = index ^ mask;

        let contract = db
            .contract_trie_node_hash(new_idx)
            .context("Getting contract trie node hash")?;

        if contract.is_some() {
            eprintln!("Flipped bit: {}, index: {}", shift, new_idx)
        }
    }

    Ok(())
}
