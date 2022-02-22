use crate::{
    core::StarknetBlockNumber,
    ethereum::log::StateUpdateLog,
    sequencer::reply::{state_update::StateDiff, Block},
    storage::{L1StateTable, RefsTable, StarknetBlocksTable, Storage},
};

use anyhow::Context;
use rusqlite::Connection;
use tokio::sync::mpsc;

/// The sync events which are emitted by the L1 and L2 sync processes.
enum SyncEvent {
    L1Update(Vec<StateUpdateLog>),
    L2Update(Block, StateDiff),
    L1Reorg(StarknetBlockNumber),
    L2Reorg(StarknetBlockNumber),
    // TODO: queries required by L1 and L2 sync processes.
}

pub fn sync(storage: Storage) -> anyhow::Result<()> {
    // TODO: should this be owning a Storage, or just take in a Connection?
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_events, mut rx_events) = mpsc::channel(1);

    let l1_process = tokio::spawn(l1_sync(tx_events.clone()));
    let l2_process = tokio::spawn(l1_sync(tx_events));

    while let Some(event) = rx_events.blocking_recv() {
        match event {
            SyncEvent::L1Update(updates) => {
                l1_update(&mut db_conn, updates).context("Update L1 state")?
            }
            SyncEvent::L2Update(_, _) => todo!(),
            SyncEvent::L1Reorg(_) => todo!(),
            SyncEvent::L2Reorg(_) => todo!(),
        }
    }

    Ok(())
}

async fn l1_sync(tx_events: mpsc::Sender<SyncEvent>) -> anyhow::Result<()> {
    todo!();
}
async fn l2_sync(tx_events: mpsc::Sender<SyncEvent>) -> anyhow::Result<()> {
    todo!();
}

fn l1_update(connection: &mut Connection, updates: Vec<StateUpdateLog>) -> anyhow::Result<()> {
    let transaction = connection
        .transaction()
        .context("Create database transaction")?;

    for update in &updates {
        L1StateTable::insert(&transaction, update).context("Insert into database")?;
    }

    // Track combined L1 and L2 state. This can also be tracked externally to save on database reads.
    let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
    let expected_next = l1_l2_head
        .map(|head| head + 1)
        .unwrap_or(StarknetBlockNumber::GENESIS);

    match updates.first() {
        Some(update) if update.block_number == expected_next => {
            let mut next_head = None;
            for update in updates {
                let l2_root = StarknetBlocksTable::get_root(&transaction, update.block_number)
                    .context("Query L2 root")?;

                match l2_root {
                    Some(l2_root) if l2_root == update.global_root => {
                        next_head = Some(update.block_number);
                    }
                    _ => break,
                }
            }

            if let Some(next_head) = next_head {
                RefsTable::set_l1_l2_head(&transaction, Some(next_head))
                    .context("Update L1-L2 head")?;
            }
        }
        _ => {}
    }

    transaction.commit().context("Commit database transaction")
}

