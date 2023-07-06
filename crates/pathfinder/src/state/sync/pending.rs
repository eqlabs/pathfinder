use pathfinder_common::{Chain, StateUpdate};
use pathfinder_storage::Storage;
use starknet_gateway_types::reply::{Block, PendingBlock};

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
pub async fn poll_pending(
    tx_event: tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: &impl starknet_gateway_client::GatewayApi,
    head: (
        pathfinder_common::BlockHash,
        pathfinder_common::StateCommitment,
    ),
    poll_interval: std::time::Duration,
    chain: Chain,
    storage: Storage,
) -> anyhow::Result<(Option<Block>, Option<StateUpdate>)> {
    use anyhow::Context;
    use pathfinder_common::BlockId;
    use std::sync::Arc;

    let mut prev_block = Arc::new(PendingBlock {
        gas_price: Default::default(),
        parent_hash: Default::default(),
        sequencer_address: Default::default(),
        status: starknet_gateway_types::reply::Status::Pending,
        timestamp: Default::default(),
        transaction_receipts: Default::default(),
        transactions: Default::default(),
        starknet_version: Default::default(),
    });

    let mut prev_state_update = Arc::new(StateUpdate::default());

    loop {
        use starknet_gateway_types::reply::MaybePendingBlock;

        let block = loop {
            let block = match sequencer
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
                    return Ok((Some(block), None));
                }
                MaybePendingBlock::Pending(pending) if pending.parent_hash != head.0 => {
                    tracing::trace!(
                        pending=%pending.parent_hash, head=%head.0,
                        "Pending block's parent hash does not match head, exiting pending mode"
                    );
                    return Ok((None, None));
                }
                MaybePendingBlock::Pending(pending) => pending,
            };

            // The gateway can return inconsistent pending data, which means it will sometimes return
            // stale data. Since the pending block should be monotinically increasing in size, we check
            // to ensure that this block is actually more recent than the previous one.
            if block.transactions.len() >= prev_block.transactions.len() {
                break Arc::new(block);
            }
        };

        let state_update = loop {
            let state_update = sequencer
                .state_update(BlockId::Pending)
                .await
                .context("Downloading pending state update")?;

            if state_update.block_hash != pathfinder_common::BlockHash::ZERO {
                tracing::trace!("Found full state update, exiting pending mode.");
                return Ok((None, Some(state_update)));
            } else if state_update.parent_state_commitment != head.1 {
                tracing::trace!(pending=%state_update.parent_state_commitment, head=%head.1, "Pending state update's old root does not match head, exiting pending mode.");
                return Ok((None, None));
            }

            // The gateway can return inconsistent pending data, which means it will sometimes return
            // stale data. Since the pending block should be monotinically increasing in size, we check
            // to ensure that this block is actually more recent than the previous one.
            if state_update.change_count() >= prev_state_update.change_count() {
                break Arc::new(state_update);
            }
        };

        // Only emit if at least one of them has changed (currently still possible both are the same).
        if block.transactions.len() == prev_block.transactions.len()
            && state_update.change_count() == prev_state_update.change_count()
        {
            continue;
        }

        // Download, process and emit all missing classes.
        super::l2::download_new_classes(
            &state_update,
            sequencer,
            &tx_event,
            chain,
            &block.starknet_version,
            storage.clone(),
        )
        .await
        .context("Handling newly declared classes for pending block")?;

        prev_block = block.clone();
        prev_state_update = state_update.clone();

        // Emit new block.
        tx_event
            .send(SyncEvent::Pending(block, state_update))
            .await
            .context("Event channel closed")?;

        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use crate::state::sync::SyncEvent;

    use super::poll_pending;
    use assert_matches::assert_matches;
    use pathfinder_common::{
        felt, felt_bytes, BlockHash, BlockNumber, BlockTimestamp, Chain, ContractAddress,
        ContractNonce, EntryPoint, GasPrice, SequencerAddress, StarknetVersion, StateCommitment,
        StateUpdate, StorageAddress, StorageValue, TransactionHash, TransactionNonce,
        TransactionVersion,
    };
    use pathfinder_storage::Storage;
    use starknet_gateway_client::MockGatewayApi;
    use starknet_gateway_types::reply::transaction::L1HandlerTransaction;
    use starknet_gateway_types::reply::{Block, MaybePendingBlock, PendingBlock, Status};

    lazy_static::lazy_static!(
        pub static ref PARENT_HASH: BlockHash =  BlockHash(felt!("0x1234"));
        pub static ref PARENT_ROOT: StateCommitment = StateCommitment(felt_bytes!(b"parent root"));

        pub static ref NEXT_BLOCK: Block = Block{
            block_hash: BlockHash(felt!("0xabcd")),
            block_number: BlockNumber::new_or_panic(1),
            gas_price: None,
            parent_block_hash: *PARENT_HASH,
            sequencer_address: None,
            state_commitment: *PARENT_ROOT,
            status: Status::AcceptedOnL2,
            timestamp: BlockTimestamp::new_or_panic(10),
            transaction_receipts: Vec::new(),
            transactions: Vec::new(),
            starknet_version: StarknetVersion::default(),
        };

        pub static ref PENDING_UPDATE: StateUpdate = {
            StateUpdate::default().with_parent_state_commitment(*PARENT_ROOT)
        };

        pub static ref PENDING_BLOCK: PendingBlock = PendingBlock {
            gas_price: GasPrice(11),
            parent_hash: NEXT_BLOCK.parent_block_hash,
            sequencer_address: SequencerAddress(felt_bytes!(b"seqeunecer address")),
            status: Status::Pending,
            timestamp: BlockTimestamp::new_or_panic(20),
            transaction_receipts: Vec::new(),
            transactions: vec![
                starknet_gateway_types::reply::transaction::Transaction::L1Handler(
                    L1HandlerTransaction {
                        contract_address: ContractAddress::new_or_panic(felt!("0x1")),
                        entry_point_selector: EntryPoint(felt!("0x55")),
                        nonce: TransactionNonce(felt!("0x2")),
                        calldata: Vec::new(),
                        transaction_hash: TransactionHash(felt!("0x22")),
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
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Block(NEXT_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(PENDING_UPDATE.clone()));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
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
    async fn exits_on_full_state_diff() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        // Construct some full diff
        let full_diff = PENDING_UPDATE
            .clone()
            .with_block_hash(NEXT_BLOCK.block_hash)
            .with_state_commitment(StateCommitment(felt!("0x12")));
        let full_diff_copy = full_diff.clone();

        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(full_diff_copy.clone()));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
                Storage::in_memory().unwrap(),
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Channel should be dropped");
        assert_matches!(result, None);

        let (_, full_state_update) = jh.await.unwrap().unwrap();
        assert_eq!(full_state_update.unwrap(), full_diff);
    }

    #[tokio::test]
    async fn exits_on_block_discontinuity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        let mut pending_block = PENDING_BLOCK.clone();
        pending_block.parent_hash = BlockHash(felt!("0xFFFFFF"));
        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(pending_block.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(PENDING_UPDATE.clone()));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
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

        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));

        let disconnected_diff = PENDING_UPDATE
            .clone()
            .with_parent_state_commitment(StateCommitment(felt_bytes!(b"different old root")));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(disconnected_diff.clone()));

        let jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
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
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(PENDING_UPDATE.clone()));

        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
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
                    contract_address: ContractAddress::new_or_panic(felt!("0x1")),
                    entry_point_selector: EntryPoint(felt!("0x55")),
                    nonce: TransactionNonce(felt!("0x2")),
                    calldata: Vec::new(),
                    transaction_hash: TransactionHash(felt!("0x22")),
                    version: TransactionVersion::ONE,
                },
            ),
        );
        let b0_copy = b0.clone();

        let mut b1 = b0.clone();
        b1.transactions.push(
            starknet_gateway_types::reply::transaction::Transaction::L1Handler(
                L1HandlerTransaction {
                    contract_address: ContractAddress::new_or_panic(felt!("0x1")),
                    entry_point_selector: EntryPoint(felt!("0x55")),
                    nonce: TransactionNonce(felt!("0x2")),
                    calldata: Vec::new(),
                    transaction_hash: TransactionHash(felt!("0x22")),
                    version: TransactionVersion::ONE,
                },
            ),
        );
        let b1_copy = b1.clone();

        lazy_static::lazy_static!(
            static ref COUNT: std::sync::Mutex<usize>  = Default::default();
        );

        sequencer.expect_block().returning(move |_| {
            let mut count = COUNT.lock().unwrap();
            *count += 1;

            match *count {
                1 => Ok(MaybePendingBlock::Pending(b0_copy.clone())),
                2 => Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())),
                _ => Ok(MaybePendingBlock::Pending(b1_copy.clone())),
            }
        });
        sequencer
            .expect_state_update()
            .returning(move |_| Ok(PENDING_UPDATE.clone()));

        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
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

    #[tokio::test]
    async fn ignores_inconsistent_gateway_state_update() {
        // In this test the gateway mock sends inconsistent state update data.
        //
        // It first sends a state update with 1 more update, then 0 then 2.
        // We expect the middle one to be ignored.
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        let b0 = PENDING_UPDATE.clone().with_storage_update(
            ContractAddress::new_or_panic(felt!("0x1")),
            StorageAddress::new_or_panic(felt!("0x2")),
            StorageValue(felt!("0x123")),
        );
        let b0_copy = b0.clone();

        let b1 = b0.clone().with_contract_nonce(
            ContractAddress::new_or_panic(felt!("0x1")),
            ContractNonce(felt!("0x99")),
        );
        let b1_copy = b1.clone();

        lazy_static::lazy_static!(
            static ref COUNT: std::sync::Mutex<usize>  = Default::default();
        );

        sequencer.expect_state_update().returning(move |_| {
            let mut count = COUNT.lock().unwrap();
            *count += 1;

            match *count {
                1 => Ok(b0_copy.clone()),
                2 => Ok(PENDING_UPDATE.clone()),
                _ => Ok(b1_copy.clone()),
            }
        });
        sequencer
            .expect_block()
            .returning(move |_| Ok(MaybePendingBlock::Pending(PENDING_BLOCK.clone())));

        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                &sequencer,
                (*PARENT_HASH, *PARENT_ROOT),
                std::time::Duration::ZERO,
                Chain::Testnet,
                Storage::in_memory().unwrap(),
            )
            .await
        });

        let result1 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result1, SyncEvent::Pending(block, diff) if *block == *PENDING_BLOCK && *diff == b0);

        let result2 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result2, SyncEvent::Pending(block, diff) if *block == *PENDING_BLOCK && *diff == b1);
    }
}
