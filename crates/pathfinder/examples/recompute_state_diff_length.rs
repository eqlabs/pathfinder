use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::BlockNumber;

/// Verify that state diff length in block_headers matches actual length.
fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        tx.block_id(pathfinder_common::FinalizedBlockId::Latest)
            .context("Fetching latest block number")?
            .context("No latest block number")?
            .0
    };

    let tx = db.transaction().unwrap();

    for block_number in 0..latest_block_number.get() {
        let block_number = BlockNumber::new_or_panic(block_number);
        let block_id = pathfinder_common::FinalizedBlockId::Number(block_number);
        let state_update = tx
            .state_update(block_id)?
            .context("Fetching state update")?;
        let header = tx
            .block_header(block_id)?
            .context("Fetching block header")?;

        let state_diff_length = state_update.state_diff_length();
        let state_diff_commitment = state_update.compute_state_diff_commitment();

        if state_diff_length != header.state_diff_length
            || state_diff_commitment != header.state_diff_commitment
        {
            println!(
                "State diff length mismatch at {block_number}: header length \
                 {state_diff_length_in_header}, actual length {state_diff_length}, header \
                 commitment {state_diff_commitment_in_header}, actual commitment \
                 {state_diff_commitment}",
                state_diff_length_in_header = header.state_diff_length,
                state_diff_commitment_in_header = header.state_diff_commitment,
            );
        }
    }

    tx.commit()
        .context("Committing state diff length changes")?;

    Ok(())
}
