//! Common utilities shared among [`v02`](super) methods.
use crate::v02::types::reply::BlockStatus;
use anyhow::Context;
use pathfinder_common::StarknetBlockNumber;
use pathfinder_storage::RefsTable;

/// Determines block status based on the current L1-L2 stored in the DB.
pub fn get_block_status(
    db_tx: &rusqlite::Transaction<'_>,
    block_number: StarknetBlockNumber,
) -> anyhow::Result<BlockStatus> {
    // All our data is L2 accepted, check our L1-L2 head to see if this block has been accepted on L1.
    let l1_l2_head =
        RefsTable::get_l1_l2_head(db_tx).context("Read latest L1 head from database")?;
    let block_status = match l1_l2_head {
        Some(number) if number >= block_number => BlockStatus::AcceptedOnL1,
        _ => BlockStatus::AcceptedOnL2,
    };

    Ok(block_status)
}
