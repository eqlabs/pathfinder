use crate::{
    core::StarknetBlockNumber,
    ethereum::log::StateUpdateLog,
    sequencer::reply::{state_update::StateDiff, Block},
};

use tokio::sync::mpsc;

/// The sync events which are emitted by the L1 and L2 sync processes.
enum SyncEvent {
    L1Update(Vec<StateUpdateLog>),
    L2Update(Block, StateDiff),
    L1Reorg(StarknetBlockNumber),
    L2Reorg(StarknetBlockNumber),
    // TODO: queries required by L1 and L2 sync processes.
}

pub fn sync() -> anyhow::Result<()> {
    let (tx_events, mut rx_events) = mpsc::channel(1);

    let l1_process = tokio::spawn(l1_sync(tx_events.clone()));
    let l2_process = tokio::spawn(l1_sync(tx_events));

    while let Some(event) = rx_events.blocking_recv() {
        match event {
            SyncEvent::L1Update(_) => todo!(),
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
