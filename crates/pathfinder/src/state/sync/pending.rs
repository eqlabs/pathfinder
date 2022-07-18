/// Poll's the Sequencer's pending block and emits [Event::Pending]
/// until the pending block is no longer connected to our current head.
///
/// This disconnect is detected whenever
/// - `pending.block_hash != head`, or
/// - `pending` is a fully formed block and not [PendingBlock]
pub async fn poll_pending(
    tx_event: tokio::sync::mpsc::Sender<super::l2::Event>,
    sequencer: &impl crate::sequencer::ClientApi,
    head: crate::core::StarknetBlockHash,
    poll_interval: std::time::Duration,
) -> anyhow::Result<()> {
    use crate::core::BlockId;
    use anyhow::Context;

    loop {
        use crate::sequencer::reply::MaybePendingBlock;

        let block = match sequencer
            .block(BlockId::Pending)
            .await
            .context("Download block")?
        {
            MaybePendingBlock::Block(block) => {
                tracing::debug!(hash=%block.block_hash, "Found full block, exiting pending mode.");
                return Ok(());
            }
            MaybePendingBlock::Pending(pending) if pending.parent_hash != head => {
                tracing::debug!(
                    pending=%pending.parent_hash, head=%head,
                    "Pending block's parent hash does not match head, exiting pending mode"
                );
                return Ok(());
            }
            MaybePendingBlock::Pending(pending) => pending,
        };

        // Download the pending state diff.
        let state_update = sequencer
            .state_update(BlockId::Pending)
            .await
            .context("Download state update")?;
        if state_update.block_hash.is_some() {
            tracing::debug!("Found full state update, exiting pending mode.");
            return Ok(());
        }

        // Emit new pending data.
        use crate::state::l2::Event::Pending;
        tx_event
            .send(Pending(Box::new(block), Box::new(state_update)))
            .await
            .context("Event channel closed")?;

        tokio::time::sleep(poll_interval).await;
    }
}
