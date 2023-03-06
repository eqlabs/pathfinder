/// Poll's the Sequencer's pending block and emits [Event::Pending](super::l2::Event::Pending)
/// until the pending block is no longer connected to our current head.
///
/// This disconnect is detected whenever
/// - `pending.parent_hash != head`, or
/// - `pending` is a fully formed block and not [PendingBlock](starknet_gateway_types::reply::MaybePendingBlock::Pending), or
/// - the state update parent root does not match head.
pub async fn poll_pending(
    tx_event: tokio::sync::mpsc::Sender<super::l2::Event>,
    sequencer: &impl starknet_gateway_client::ClientApi,
    head: (
        pathfinder_common::StarknetBlockHash,
        pathfinder_common::StateCommitment,
    ),
    poll_interval: std::time::Duration,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use pathfinder_common::BlockId;
    use std::sync::Arc;

    loop {
        use starknet_gateway_types::reply::{MaybePendingBlock, MaybePendingStateUpdate};

        let pending_block = match sequencer
            .block(BlockId::Pending)
            .await
            .context("Download pending block")?
        {
            MaybePendingBlock::Block(block) if block.block_hash == head.0 => {
                // Sequencer `pending` may return the latest full block for quite some time, so ignore it.
                tracing::trace!(hash=%block.block_hash, "Found current head from pending mode");
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            MaybePendingBlock::Block(block) => {
                tracing::trace!(hash=%block.block_hash, "Found full block, exiting pending mode.");
                return Ok(());
            }
            MaybePendingBlock::Pending(pending) if pending.parent_hash != head.0 => {
                tracing::trace!(
                    pending=%pending.parent_hash, head=%head.0,
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
            .context("Download pending state update")?;

        match state_update {
            MaybePendingStateUpdate::StateUpdate(_) => {
                tracing::trace!("Found full state update, exiting pending mode.");
                return Ok(());
            }
            MaybePendingStateUpdate::Pending(pending_state_update) => {
                if pending_state_update.old_root != head.1 {
                    tracing::trace!(pending=%pending_state_update.old_root, head=%head.1, "Pending state update's old root does not match head, exiting pending mode.");
                    return Ok(());
                }

                // Emit new pending data.
                use crate::state::l2::Event::Pending;
                tx_event
                    .send(Pending(
                        Arc::new(pending_block),
                        Arc::new(pending_state_update),
                    ))
                    .await
                    .context("Event channel closed")?;

                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::poll_pending;
    use assert_matches::assert_matches;
    use pathfinder_common::{
        felt, felt_bytes, GasPrice, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp, StateCommitment,
    };
    use starknet_gateway_client::MockClientApi;
    use starknet_gateway_types::reply::{
        state_update::StateDiff, Block, MaybePendingBlock, MaybePendingStateUpdate, PendingBlock,
        PendingStateUpdate, StateUpdate, Status,
    };

    lazy_static::lazy_static!(
        pub static ref PARENT_HASH: StarknetBlockHash =  StarknetBlockHash(felt!("0x1234"));
        pub static ref PARENT_ROOT: StateCommitment = StateCommitment(felt_bytes!(b"parent root"));

        pub static ref NEXT_BLOCK: Block = Block{
            block_hash: StarknetBlockHash(felt!("0xabcd")),
            block_number: StarknetBlockNumber::new_or_panic(1),
            gas_price: None,
            parent_block_hash: *PARENT_HASH,
            sequencer_address: None,
            state_commitment: *PARENT_ROOT,
            status: Status::AcceptedOnL2,
            timestamp: StarknetBlockTimestamp::new_or_panic(10),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: None,
        };

        pub static ref PENDING_DIFF: PendingStateUpdate = PendingStateUpdate {
            old_root: *PARENT_ROOT,
            state_diff: StateDiff {
                storage_diffs: std::collections::HashMap::new(),
                deployed_contracts: Vec::new(),
                old_declared_contracts: Vec::new(),
                declared_classes: Vec::new(),
                nonces: std::collections::HashMap::new(),
                replaced_classes: Vec::new(),
            }
        };

        pub static ref PENDING_BLOCK: PendingBlock = PendingBlock {
            gas_price: GasPrice(11),
            parent_hash: NEXT_BLOCK.parent_block_hash,
            sequencer_address: SequencerAddress(felt_bytes!(b"seqeunecer address")),
            status: Status::Pending,
            timestamp: StarknetBlockTimestamp::new_or_panic(20),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: None,
        };
    );

    /// Arbitrary timeout for receiving emits on the tokio channel. Otherwise failing tests will
    /// need to timeout naturally which may be forever.
    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn exits_on_full_block() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockClientApi::new();

        // Give a pending state update and full block.
        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Block(NEXT_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(MaybePendingStateUpdate::Pending(PENDING_DIFF.clone())));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);
        jh.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exits_on_full_state_diff() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockClientApi::new();

        // Construct some full diff
        let pending_diff = PENDING_DIFF.clone();
        let full_diff = MaybePendingStateUpdate::StateUpdate(StateUpdate {
            block_hash: NEXT_BLOCK.block_hash,
            new_root: StateCommitment(felt!("0x12")),
            old_root: pending_diff.old_root,
            state_diff: pending_diff.state_diff,
        });

        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(full_diff.clone()));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);
        jh.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exits_on_block_discontinuity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockClientApi::new();

        let mut pending_block = PENDING_BLOCK.clone();
        pending_block.parent_hash = StarknetBlockHash(felt!("0xFFFFFF"));
        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(pending_block.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(MaybePendingStateUpdate::Pending(PENDING_DIFF.clone())));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);
        jh.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exits_on_state_diff_discontinuity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockClientApi::new();

        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));

        let mut disconnected_diff = PENDING_DIFF.clone();
        disconnected_diff.old_root = StateCommitment(felt_bytes!(b"different old root"));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(MaybePendingStateUpdate::Pending(disconnected_diff.clone())));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);
        jh.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn success() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockClientApi::new();

        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(MaybePendingStateUpdate::Pending(PENDING_DIFF.clone())));

        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        use crate::state::l2::Event::Pending;
        assert_matches!(result, Pending(block, diff) if *block == *PENDING_BLOCK && *diff == *PENDING_DIFF);
    }
}
