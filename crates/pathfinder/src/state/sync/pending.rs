use anyhow::Context;
use pathfinder_common::BlockId;
use pathfinder_common::StateUpdate;
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::MaybePendingBlock;
use starknet_gateway_types::reply::{Block, PendingBlock};
use std::sync::Arc;
use tokio::time::Instant;

use crate::state::sync::SyncEvent;

/// Poll's the Sequencer's pending block and emits [pending events](SyncEvent::Pending)
/// until the pending block is no longer connected to our current head.
///
/// This disconnect is detected whenever
/// - `pending.parent_hash != head`, or
/// - `pending` is a fully formed block and not [PendingBlock](starknet_gateway_types::reply::MaybePendingBlock::Pending), or
/// - the state update parent root does not match head.
///
/// A full block or full state update can be returned from this function if it is encountered during polling.
pub async fn poll_pending<S: GatewayApi + Clone + Send + 'static>(
    tx_event: tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: &S,
    head: (
        pathfinder_common::BlockHash,
        pathfinder_common::StateCommitment,
    ),
    poll_interval: std::time::Duration,
    storage: Storage,
) -> anyhow::Result<(Option<Block>, Option<StateUpdate>)> {
    let mut prev_block: Option<Arc<PendingBlock>> = None;

    loop {
        let t_fetch = Instant::now();

        // Fetches the pending block _and_ state update in a single request.
        // Starknet 0.12.2 introduced a feeder gateway API for fetching both the block and the state update, so
        // that we get _consistent_ data.
        let (block, state_update) = sequencer
            .state_update_with_block(BlockId::Pending)
            .await
            .context("Downloading pending block and state update")?;

        match block {
            MaybePendingBlock::Block(block) if block.block_hash == head.0 => {
                // Sequencer `pending` may return the latest full block for quite some time, so ignore it.
                tracing::trace!(hash=%block.block_hash, "Found current head from pending mode");
            }
            MaybePendingBlock::Block(block) => {
                tracing::trace!(hash=%block.block_hash, "Found full block, exiting pending mode.");
                return Ok((Some(block), Some(state_update)));
            }
            MaybePendingBlock::Pending(pending) if pending.parent_hash != head.0 => {
                tracing::trace!(
                    pending=%pending.parent_hash, head=%head.0,
                    "Pending block's parent hash does not match head, exiting pending mode"
                );
                return Ok((None, None));
            }
            MaybePendingBlock::Pending(pending)
                if state_update.parent_state_commitment != head.1 =>
            {
                tracing::trace!(
                    pending=%pending.parent_hash, head=%head.0,
                    "Pending state update's parent state commitment does not match head, exiting pending mode"
                );
                return Ok((None, None));
            }
            MaybePendingBlock::Pending(pending) => {
                let replace = prev_block
                    .as_ref()
                    .map(|prev| pending.transactions.len() > prev.transactions.len())
                    .unwrap_or(true);

                if replace {
                    let block = Arc::new(pending);
                    prev_block = Some(block.clone());
                    tracing::trace!("Pending block data changed");

                    download_classes_and_emit_event(
                        &tx_event,
                        sequencer,
                        &storage,
                        block,
                        Arc::new(state_update),
                    )
                    .await?;
                } else {
                    tracing::trace!("No change in pending block data");
                }
            }
        }

        tokio::time::sleep_until(t_fetch + poll_interval).await;
    }
}

async fn download_classes_and_emit_event<S: GatewayApi + Clone + Send + 'static>(
    tx_event: &tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: &S,
    storage: &Storage,
    block: Arc<PendingBlock>,
    state_update: Arc<StateUpdate>,
) -> anyhow::Result<()> {
    tracing::trace!("Downloading classes for pending state update");

    // Download, process and emit all missing classes.
    super::l2::download_new_classes(
        &state_update,
        sequencer,
        tx_event,
        &block.starknet_version,
        storage.clone(),
    )
    .await
    .context("Handling newly declared classes for pending block")?;

    tracing::trace!("Emitting a pending update");
    tx_event
        .send(SyncEvent::Pending(block, state_update))
        .await
        .context("Event channel closed")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::state::sync::SyncEvent;

    use super::poll_pending;
    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        BlockHash, BlockNumber, BlockTimestamp, GasPrice, StarknetVersion, StateCommitment,
        StateUpdate, TransactionVersion,
    };
    use pathfinder_storage::Storage;
    use starknet_gateway_client::MockGatewayApi;
    use starknet_gateway_types::reply::transaction::L1HandlerTransaction;
    use starknet_gateway_types::reply::{Block, MaybePendingBlock, PendingBlock, Status};

    const PARENT_HASH: BlockHash = block_hash!("0x1234");
    const PARENT_ROOT: StateCommitment = state_commitment_bytes!(b"parent root");

    lazy_static::lazy_static!(
        pub static ref NEXT_BLOCK: Block = Block{
            block_hash: block_hash!("0xabcd"),
            block_number: BlockNumber::new_or_panic(1),
            gas_price: None,
            parent_block_hash: PARENT_HASH,
            sequencer_address: None,
            state_commitment: PARENT_ROOT,
            status: Status::AcceptedOnL2,
            timestamp: BlockTimestamp::new_or_panic(10),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: StarknetVersion::default(),
        };

        pub static ref PENDING_UPDATE: StateUpdate = {
            StateUpdate::default().with_parent_state_commitment(PARENT_ROOT)
        };

        pub static ref PENDING_BLOCK: PendingBlock = PendingBlock {
            gas_price: GasPrice(11),
            parent_hash: NEXT_BLOCK.parent_block_hash,
            sequencer_address: sequencer_address_bytes!(b"seqeunecer address"),
            status: Status::Pending,
            timestamp: BlockTimestamp::new_or_panic(20),
            transaction_receipts: Vec::new(),
            transactions: vec![
                starknet_gateway_types::reply::transaction::Transaction::L1Handler(
                    L1HandlerTransaction {
                        contract_address: contract_address!("0x1"),
                        entry_point_selector: entry_point!("0x55"),
                        nonce: transaction_nonce!("0x2"),
                        calldata: Vec::new(),
                        transaction_hash: transaction_hash!("0x22"),
                        version: TransactionVersion::ONE,
                    },
                )
            ],
            starknet_version: StarknetVersion::default(),
        };
    );

    /// Arbitrary timeout for receiving emits on the tokio channel. Otherwise failing tests will
    /// need to timeout naturally which may be forever.
    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn exits_on_full_block() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        // Give a pending state update and full block.
        sequencer
            .expect_state_update_with_block()
            .returning(move |_| {
                Ok((
                    MaybePendingBlock::Block(NEXT_BLOCK.clone()),
                    PENDING_UPDATE.clone(),
                ))
            });

        let sequencer = Arc::new(sequencer);

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (PARENT_HASH, PARENT_ROOT),
                std::time::Duration::ZERO,
                Storage::in_memory().unwrap(),
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);

        let (full_block, _) = jh.await.unwrap().unwrap();
        assert_eq!(full_block.unwrap(), *NEXT_BLOCK);
    }

    #[tokio::test]
    async fn exits_on_block_discontinuity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        let mut pending_block = PENDING_BLOCK.clone();
        pending_block.parent_hash = block_hash!("0xFFFFFF");
        sequencer
            .expect_state_update_with_block()
            .returning(move |_| {
                Ok((
                    MaybePendingBlock::Pending(pending_block.clone()),
                    PENDING_UPDATE.clone(),
                ))
            });
        let sequencer = Arc::new(sequencer);

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (PARENT_HASH, PARENT_ROOT),
                std::time::Duration::ZERO,
                Storage::in_memory().unwrap(),
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
        let mut sequencer = MockGatewayApi::new();

        let disconnected_diff = PENDING_UPDATE
            .clone()
            .with_parent_state_commitment(state_commitment_bytes!(b"different old root"));
        sequencer
            .expect_state_update_with_block()
            .returning(move |_| {
                Ok((
                    MaybePendingBlock::Pending(PENDING_BLOCK.clone()),
                    disconnected_diff.clone(),
                ))
            });
        let sequencer = Arc::new(sequencer);

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (PARENT_HASH, PARENT_ROOT),
                std::time::Duration::ZERO,
                Storage::in_memory().unwrap(),
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
        let mut sequencer = MockGatewayApi::new();

        sequencer
            .expect_state_update_with_block()
            .returning(move |_| {
                Ok((
                    MaybePendingBlock::Pending(PENDING_BLOCK.clone()),
                    PENDING_UPDATE.clone(),
                ))
            });

        let sequencer = Arc::new(sequencer);
        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (PARENT_HASH, PARENT_ROOT),
                std::time::Duration::ZERO,
                Storage::in_memory().unwrap(),
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result, SyncEvent::Pending(block, diff) if *block == *PENDING_BLOCK && *diff == *PENDING_UPDATE);
    }

    #[tokio::test]
    async fn ignores_inconsistent_gateway_blocks() {
        // In this test the gateway mock sends inconsistent block data.
        //
        // It first sends a block with 1 tx, then 0 and then 2.
        // We expect the function to ignore the middle one since pending data
        // should be monotonically growing.
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        let mut b0 = PENDING_BLOCK.clone();
        b0.transactions.push(
            starknet_gateway_types::reply::transaction::Transaction::L1Handler(
                L1HandlerTransaction {
                    contract_address: contract_address!("0x1"),
                    entry_point_selector: entry_point!("0x55"),
                    nonce: transaction_nonce!("0x2"),
                    calldata: Vec::new(),
                    transaction_hash: transaction_hash!("0x22"),
                    version: TransactionVersion::ONE,
                },
            ),
        );
        let b0_copy = b0.clone();

        let mut b1 = b0.clone();
        b1.transactions.push(
            starknet_gateway_types::reply::transaction::Transaction::L1Handler(
                L1HandlerTransaction {
                    contract_address: contract_address!("0x1"),
                    entry_point_selector: entry_point!("0x55"),
                    nonce: transaction_nonce!("0x2"),
                    calldata: Vec::new(),
                    transaction_hash: transaction_hash!("0x22"),
                    version: TransactionVersion::ONE,
                },
            ),
        );
        let b1_copy = b1.clone();

        lazy_static::lazy_static!(
            static ref COUNT: std::sync::Mutex<usize>  = Default::default();
        );

        sequencer
            .expect_state_update_with_block()
            .returning(move |_| {
                let mut count = COUNT.lock().unwrap();
                *count += 1;

                let block = match *count {
                    1 => MaybePendingBlock::Pending(b0_copy.clone()),
                    2 => MaybePendingBlock::Pending(PENDING_BLOCK.clone()),
                    _ => MaybePendingBlock::Pending(b1_copy.clone()),
                };

                Ok((block, PENDING_UPDATE.clone()))
            });

        let sequencer = Arc::new(sequencer);
        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (PARENT_HASH, PARENT_ROOT),
                std::time::Duration::ZERO,
                Storage::in_memory().unwrap(),
            )
            .await
        });

        let result1 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result1, SyncEvent::Pending(block, diff) if *block == b0 && *diff == *PENDING_UPDATE);

        let result2 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result2, SyncEvent::Pending(block, diff) if *block == b1 && *diff == *PENDING_UPDATE);
    }
}
