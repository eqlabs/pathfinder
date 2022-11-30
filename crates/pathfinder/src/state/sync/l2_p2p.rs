use std::time::Duration;

use pathfinder_common::{Chain, GlobalRoot, StarknetBlockHash, StarknetBlockNumber};
use tokio::sync::mpsc;

use super::l2::Event;

pub async fn sync(
    tx_event: mpsc::Sender<Event>,
    sequencer: impl starknet_gateway_client::ClientApi,
    mut head: Option<(StarknetBlockNumber, StarknetBlockHash, GlobalRoot)>,
    chain: Chain,
    pending_poll_interval: Option<Duration>,
) -> anyhow::Result<()> {
    Ok(())
}
