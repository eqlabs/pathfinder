use pathfinder_common::{BlockHash, BlockNumber, StarknetVersion};
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::state::sync::SyncEvent;

/// Emits new pending data events while the current block is close to the latest
/// block.
pub async fn poll_pending<S: GatewayApi + Clone + Send + 'static>(
    tx_event: tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: S,
    poll_interval: std::time::Duration,
    storage: Storage,
    latest: watch::Receiver<(BlockNumber, BlockHash)>,
    current: watch::Receiver<(BlockNumber, BlockHash)>,
    fetch_casm_from_fgw: bool,
) {
    poll_pre_starknet_0_14_0(
        &tx_event,
        &sequencer,
        poll_interval,
        &storage,
        &latest,
        &current,
        fetch_casm_from_fgw,
    )
    .await;

    poll_starknet_0_14_0(&tx_event, &sequencer, poll_interval, &latest, &current).await;
}

const STARKNET_VERSION_0_14_0: StarknetVersion = StarknetVersion::new(0, 14, 0, 0);

pub async fn poll_pre_starknet_0_14_0<S: GatewayApi + Clone + Send + 'static>(
    tx_event: &tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: &S,
    poll_interval: std::time::Duration,
    storage: &Storage,
    latest: &watch::Receiver<(BlockNumber, BlockHash)>,
    current: &watch::Receiver<(BlockNumber, BlockHash)>,
    fetch_casm_from_fgw: bool,
) {
    let mut prev_tx_count = 0;
    let mut prev_hash = BlockHash::default();

    loop {
        let t_fetch = Instant::now();

        let latest = latest.borrow().0.get();
        let current = current.borrow().0.get();

        if latest.abs_diff(current) > 6 {
            tracing::debug!(%latest, %current, "Not in sync yet; skipping pending block download");
            tokio::time::sleep_until(t_fetch + poll_interval).await;
            continue;
        }

        let (block, state_update) = match sequencer.pending_block().await {
            Ok(r) => r,
            Err(err) => {
                tracing::debug!(%err, "Failed to fetch pending block");
                tokio::time::sleep_until(t_fetch + poll_interval).await;
                continue;
            }
        };

        // If we've reached Starknet 0.14.0, stop polling for pending blocks as we need
        // to transition to polling the pre-confirmed block instead.
        if block.starknet_version >= STARKNET_VERSION_0_14_0 {
            tracing::debug!("Reached Starknet 0.14.0, stopping pending block polling");
            break;
        }

        // Use the transaction count as a proxy for freshness of the pending data.
        //
        // The sequencer has multiple feeder gateways which are not 100% in sync making
        // it possible for us to receive stale data, older than the previous data.
        if block.parent_hash == prev_hash && block.transactions.len() <= prev_tx_count {
            tracing::trace!("No change in pending block data");
            tokio::time::sleep_until(t_fetch + poll_interval).await;
            continue;
        }

        // Download, process and emit all missing classes. This can occasionally
        // fail when querying a desync'd feeder gateway which isn't aware of the
        // new pending classes. In this case, ignore the new pending data as it
        // is incomplete.
        match super::l2::download_new_classes(
            &state_update,
            sequencer,
            storage.clone(),
            fetch_casm_from_fgw,
        )
        .await
        {
            Err(e) => tracing::debug!(reason=?e, "Failed to download pending classes"),
            Ok(downloaded_classes) => {
                if let Err(e) = super::l2::emit_events_for_downloaded_classes(
                    tx_event,
                    downloaded_classes,
                    &state_update.declared_sierra_classes,
                )
                .await
                {
                    tracing::error!(error=%e, "Event channel closed unexpectedly. Ending pending stream.");
                    break;
                }

                prev_tx_count = block.transactions.len();
                prev_hash = block.parent_hash;
                tracing::trace!("Emitting a pending update");
                if let Err(e) = tx_event
                    .send(SyncEvent::Pending((block.into(), state_update.into())))
                    .await
                {
                    tracing::error!(error=%e, "Event channel closed unexpectedly. Ending pending stream.");
                    break;
                }
            }
        }

        tokio::time::sleep_until(t_fetch + poll_interval).await;
    }
}

pub async fn poll_starknet_0_14_0<S: GatewayApi + Clone + Send + 'static>(
    tx_event: &tokio::sync::mpsc::Sender<SyncEvent>,
    sequencer: &S,
    poll_interval: std::time::Duration,
    latest: &watch::Receiver<(BlockNumber, BlockHash)>,
    current: &watch::Receiver<(BlockNumber, BlockHash)>,
) {
    #[derive(Default)]
    struct State {
        block_number: BlockNumber,
        tx_count: usize,
    }

    impl State {
        /// Returns `true` if the state was updated, `false` otherwise.
        fn update(&mut self, block_number: BlockNumber, tx_count: usize) -> bool {
            if self.block_number == block_number && self.tx_count >= tx_count {
                return false;
            }
            self.block_number = block_number;
            self.tx_count = tx_count;
            true
        }
    }

    let mut state = State::default();

    loop {
        let t_fetch = Instant::now();

        let latest = latest.borrow().0.get();
        let current = current.borrow().0.get();

        if latest.abs_diff(current) > 6 {
            tracing::debug!(%latest, %current, "Not in sync yet; skipping pre-confirmed block download");
            tokio::time::sleep_until(t_fetch + poll_interval).await;
            continue;
        }

        let pre_confirmed_block_number = BlockNumber::new_or_panic(latest + 1);

        let pre_confirmed_block = match sequencer
            .preconfirmed_block(pre_confirmed_block_number.into())
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::debug!(%err, "Failed to fetch pre-confirmed block");
                tokio::time::sleep_until(t_fetch + poll_interval).await;
                continue;
            }
        };

        match state.update(
            pre_confirmed_block_number,
            pre_confirmed_block.transactions.len(),
        ) {
            false => {
                tracing::trace!("No change in pre-confirmed block data");
                tokio::time::sleep_until(t_fetch + poll_interval).await;
                continue;
            }
            true => {
                tracing::trace!("Emitting a pre-confirmed update");
                if let Err(e) = tx_event
                    .send(SyncEvent::PreConfirmed((
                        pre_confirmed_block_number,
                        pre_confirmed_block.into(),
                    )))
                    .await
                {
                    tracing::error!(error=%e, "Event channel closed unexpectedly. Ending pre-confirmed stream.");
                    break;
                }

                tokio::time::sleep_until(t_fetch + poll_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, LazyLock};

    use assert_matches::assert_matches;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::prelude::*;
    use pathfinder_common::transaction::{
        DataAvailabilityMode,
        InvokeTransactionV3,
        L1HandlerTransaction,
        Transaction,
        TransactionVariant,
    };
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_client::MockGatewayApi;
    use starknet_gateway_types::reply::state_update::{
        DeclaredSierraClass,
        DeployedContract,
        ReplacedClass,
        StateDiff,
        StorageDiff,
    };
    use starknet_gateway_types::reply::{
        Block,
        GasPrices,
        L1DataAvailabilityMode,
        PendingBlock,
        PreConfirmedBlock,
        Status,
    };
    use tokio::sync::watch;

    use super::poll_pending;
    use crate::state::sync::SyncEvent;

    const PARENT_HASH: BlockHash = block_hash!("0x1234");
    const PARENT_ROOT: StateCommitment = state_commitment_bytes!(b"parent root");

    pub static NEXT_BLOCK: LazyLock<Block> = LazyLock::new(|| Block {
        block_hash: block_hash!("0xabcd"),
        block_number: BlockNumber::new_or_panic(1),
        l1_gas_price: Default::default(),
        l1_data_gas_price: Default::default(),
        l2_gas_price: Default::default(),
        parent_block_hash: PARENT_HASH,
        sequencer_address: None,
        state_commitment: PARENT_ROOT,
        status: Status::AcceptedOnL2,
        timestamp: BlockTimestamp::new_or_panic(10),
        transaction_receipts: Vec::new(),
        transactions: Vec::new(),
        starknet_version: StarknetVersion::default(),
        l1_da_mode: Default::default(),
        transaction_commitment: Default::default(),
        event_commitment: Default::default(),
        receipt_commitment: Default::default(),
        state_diff_commitment: Default::default(),
        state_diff_length: Default::default(),
    });

    pub static PENDING_UPDATE: LazyLock<StateUpdate> =
        LazyLock::new(|| StateUpdate::default().with_parent_state_commitment(PARENT_ROOT));

    pub static PENDING_BLOCK: LazyLock<PendingBlock> = LazyLock::new(|| PendingBlock {
        l1_gas_price: GasPrices {
            price_in_wei: GasPrice(11),
            ..Default::default()
        },
        l1_data_gas_price: Default::default(),
        l2_gas_price: Default::default(),
        parent_hash: NEXT_BLOCK.parent_block_hash,
        sequencer_address: sequencer_address_bytes!(b"seqeunecer address"),
        status: Status::Pending,
        timestamp: BlockTimestamp::new_or_panic(20),
        transaction_receipts: Vec::new(),
        transactions: vec![pathfinder_common::transaction::Transaction {
            hash: transaction_hash!("0x22"),
            variant: pathfinder_common::transaction::TransactionVariant::L1Handler(
                L1HandlerTransaction {
                    contract_address: contract_address!("0x1"),
                    entry_point_selector: entry_point!("0x55"),
                    nonce: transaction_nonce!("0x2"),
                    calldata: Vec::new(),
                },
            ),
        }],
        starknet_version: StarknetVersion::default(),
        l1_da_mode: L1DataAvailabilityMode::Calldata,
    });

    pub static PRE_CONFIRMED_BLOCK: LazyLock<PreConfirmedBlock> =
        LazyLock::new(|| PreConfirmedBlock {
            l1_gas_price: Default::default(),
            l1_data_gas_price: Default::default(),
            l2_gas_price: Default::default(),
            sequencer_address: sequencer_address_bytes!(b"seqeunecer address"),
            status: Status::PreConfirmed,
            timestamp: BlockTimestamp::new_or_panic(30),
            starknet_version: StarknetVersion::new(0, 14, 0, 0),
            l1_da_mode: L1DataAvailabilityMode::Blob,
            transactions: vec![
                pathfinder_common::transaction::Transaction {
                    hash: transaction_hash!("0x22"),
                    variant: pathfinder_common::transaction::TransactionVariant::L1Handler(
                        L1HandlerTransaction {
                            contract_address: contract_address!("0x1"),
                            entry_point_selector: entry_point!("0x55"),
                            nonce: transaction_nonce!("0x2"),
                            calldata: Vec::new(),
                        },
                    ),
                },
                pathfinder_common::transaction::Transaction {
                    hash: transaction_hash!("0x33"),
                    variant: pathfinder_common::transaction::TransactionVariant::InvokeV3(
                        InvokeTransactionV3 {
                            signature: vec![],
                            nonce: transaction_nonce!("0x3"),
                            nonce_data_availability_mode: DataAvailabilityMode::L1,
                            fee_data_availability_mode: DataAvailabilityMode::L1,
                            resource_bounds: Default::default(),
                            tip: Default::default(),
                            paymaster_data: vec![],
                            account_deployment_data: vec![],
                            calldata: vec![],
                            sender_address: contract_address!("0x2"),
                        },
                    ),
                },
            ],
            transaction_receipts: vec![
                Some((
                    pathfinder_common::receipt::Receipt {
                        actual_fee: Default::default(),
                        execution_resources: Default::default(),
                        l2_to_l1_messages: vec![],
                        execution_status: pathfinder_common::receipt::ExecutionStatus::Succeeded,
                        transaction_hash: transaction_hash!("0x22"),
                        transaction_index: TransactionIndex::new_or_panic(0),
                    },
                    vec![],
                )),
                None,
            ],
            transaction_state_diffs: vec![
                Some(StateDiff {
                    storage_diffs: HashMap::from([(
                        contract_address_bytes!(b"contract 0"),
                        vec![StorageDiff {
                            key: storage_address_bytes!(b"storage key 0"),
                            value: storage_value_bytes!(b"storage val 0"),
                        }],
                    )]),
                    deployed_contracts: vec![DeployedContract {
                        address: contract_address_bytes!(b"deployed contract"),
                        class_hash: class_hash_bytes!(b"deployed class"),
                    }],
                    old_declared_contracts: HashSet::from([
                        class_hash_bytes!(b"cairo 0 0"),
                        class_hash_bytes!(b"cairo 0 1"),
                    ]),
                    declared_classes: vec![DeclaredSierraClass {
                        class_hash: sierra_hash_bytes!(b"sierra class"),
                        compiled_class_hash: casm_hash_bytes!(b"casm hash"),
                    }],
                    nonces: HashMap::from([
                        (
                            contract_address_bytes!(b"contract 0"),
                            contract_nonce_bytes!(b"nonce 0"),
                        ),
                        (
                            contract_address_bytes!(b"contract 10"),
                            contract_nonce_bytes!(b"nonce 10"),
                        ),
                    ]),
                    replaced_classes: vec![ReplacedClass {
                        address: contract_address_bytes!(b"contract 0"),
                        class_hash: class_hash_bytes!(b"replaced class"),
                    }],
                }),
                None,
            ],
        });

    /// Arbitrary timeout for receiving emits on the tokio channel. Otherwise
    /// failing tests will need to timeout naturally which may be forever.
    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn success() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        sequencer
            .expect_pending_block()
            .returning(|| Ok((PENDING_BLOCK.clone(), PENDING_UPDATE.clone())));

        let (_, latest) = watch::channel(Default::default());
        let (_, current) = watch::channel(Default::default());

        let sequencer = Arc::new(sequencer);
        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                sequencer,
                std::time::Duration::ZERO,
                StorageBuilder::in_memory().unwrap(),
                latest,
                current,
                false,
            )
            .await
        });

        let result = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result, SyncEvent::Pending(x) if *x.0 == *PENDING_BLOCK && *x.1 == *PENDING_UPDATE);
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
        b0.transactions.push(Transaction {
            hash: transaction_hash!("0x22"),
            variant: TransactionVariant::L1Handler(L1HandlerTransaction {
                contract_address: contract_address!("0x1"),
                entry_point_selector: entry_point!("0x55"),
                nonce: transaction_nonce!("0x2"),
                calldata: Vec::new(),
            }),
        });
        let b0_copy = b0.clone();

        let mut b1 = b0.clone();
        b1.transactions.push(Transaction {
            hash: transaction_hash!("0x22"),
            variant: TransactionVariant::L1Handler(L1HandlerTransaction {
                contract_address: contract_address!("0x1"),
                entry_point_selector: entry_point!("0x55"),
                nonce: transaction_nonce!("0x2"),
                calldata: Vec::new(),
            }),
        });
        let b1_copy = b1.clone();

        static COUNT: std::sync::Mutex<usize> = std::sync::Mutex::new(0);

        sequencer.expect_pending_block().returning(move || {
            let mut count = COUNT.lock().unwrap();
            *count += 1;

            let block = match *count {
                1 => b0_copy.clone(),
                2 => PENDING_BLOCK.clone(),
                _ => b1_copy.clone(),
            };

            Ok((block, PENDING_UPDATE.clone()))
        });

        let sequencer = Arc::new(sequencer);
        let (_, rx_latest) = watch::channel(Default::default());
        let (_, rx_current) = watch::channel(Default::default());
        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                sequencer,
                std::time::Duration::ZERO,
                StorageBuilder::in_memory().unwrap(),
                rx_latest,
                rx_current,
                false,
            )
            .await
        });

        let result1 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result1, SyncEvent::Pending(x) if *x.0 == b0 && *x.1 == *PENDING_UPDATE);

        let result2 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result2, SyncEvent::Pending(x) if *x.0 == b1 && *x.1 == *PENDING_UPDATE);
    }

    #[tokio::test]
    async fn transition_to_polling_pre_confirmed() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sequencer = MockGatewayApi::new();

        // A pending block with Starknet version 0.14.0 should trigger the transition
        // to polling the pre-confirmed block.
        let pending_block = PendingBlock {
            starknet_version: StarknetVersion::new(0, 14, 0, 0),
            ..PENDING_BLOCK.clone()
        };
        let pending_block_copy = pending_block.clone();

        sequencer
            .expect_pending_block()
            .returning(move || Ok((pending_block_copy.clone(), PENDING_UPDATE.clone())));
        sequencer
            .expect_preconfirmed_block()
            .returning(move |_| Ok(PRE_CONFIRMED_BLOCK.clone()));

        let sequencer = Arc::new(sequencer);
        let (_, rx_latest) = watch::channel(Default::default());
        let (_, rx_current) = watch::channel(Default::default());
        let _jh = tokio::spawn(async move {
            poll_pending(
                tx,
                sequencer,
                std::time::Duration::ZERO,
                StorageBuilder::in_memory().unwrap(),
                rx_latest,
                rx_current,
                false,
            )
            .await
        });

        let result1 = tokio::time::timeout(TEST_TIMEOUT, rx.recv())
            .await
            .expect("Event should be emitted")
            .unwrap();

        assert_matches!(result1, SyncEvent::PreConfirmed((block_number, pre_confirmed_block)) if block_number == BlockNumber::new_or_panic(1) && *pre_confirmed_block == *PRE_CONFIRMED_BLOCK);
    }
}
