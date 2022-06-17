pub mod l1;
pub mod l2;

use std::future::Future;
use std::sync::Arc;

use crate::{
    core::{
        ContractRoot, GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash,
        StarknetBlockNumber,
    },
    ethereum::{
        log::StateUpdateLog,
        state_update::{DeployedContract, StateUpdate},
        transport::EthereumTransport,
        Chain,
    },
    rpc::types::reply::{syncing, syncing::NumberedBlock, Syncing as SyncStatus},
    sequencer::{self, reply::Block},
    state::{calculate_contract_state_hash, state_tree::GlobalStateTree, update_contract_state},
    storage::{
        ContractCodeTable, ContractsStateTable, ContractsTable, L1StateTable, L1TableBlockId,
        RefsTable, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable,
        StarknetTransactionsTable, Storage,
    },
};

use anyhow::Context;
use rusqlite::{Connection, Transaction};
use stark_hash::StarkHash;
use tokio::sync::{mpsc, RwLock};

pub struct State {
    pub status: RwLock<SyncStatus>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            status: RwLock::new(SyncStatus::False(false)),
        }
    }
}

/// Implements the main sync loop, where L1 and L2 sync results are combined.
pub async fn sync<Transport, SequencerClient, F1, F2, L1Sync, L2Sync>(
    storage: Storage,
    transport: Transport,
    chain: Chain,
    sequencer: SequencerClient,
    state: Arc<State>,
    l1_sync: L1Sync,
    l2_sync: L2Sync,
) -> anyhow::Result<()>
where
    Transport: EthereumTransport + Clone,
    SequencerClient: sequencer::ClientApi + Clone + Send + Sync + 'static,
    F1: Future<Output = anyhow::Result<()>> + Send + 'static,
    F2: Future<Output = anyhow::Result<()>> + Send + 'static,
    L1Sync: FnOnce(mpsc::Sender<l1::Event>, Transport, Chain, Option<StateUpdateLog>) -> F1 + Copy,
    L2Sync: FnOnce(
            mpsc::Sender<l2::Event>,
            SequencerClient,
            Option<(StarknetBlockNumber, StarknetBlockHash)>,
            crate::ethereum::Chain,
        ) -> F2
        + Copy,
{
    // TODO: should this be owning a Storage, or just take in a Connection?
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_l1, mut rx_l1) = mpsc::channel(1);
    let (tx_l2, mut rx_l2) = mpsc::channel(1);

    let (l1_head, l2_head) = tokio::task::block_in_place(|| -> anyhow::Result<_> {
        let l1_head = L1StateTable::get(&db_conn, L1TableBlockId::Latest)
            .context("Query L1 head from database")?;
        let l2_head = StarknetBlocksTable::get(&db_conn, StarknetBlocksBlockId::Latest)
            .context("Query L2 head from database")?
            .map(|block| (block.number, block.hash));
        Ok((l1_head, l2_head))
    })?;

    // Start update sync-status process.
    let (starting_block_num, starting_block_hash) = l2_head.unwrap_or((
        // Seems a better choice for an invalid block number than 0
        StarknetBlockNumber(u64::MAX),
        StarknetBlockHash(StarkHash::ZERO),
    ));
    let _status_sync = tokio::spawn(update_sync_status_latest(
        Arc::clone(&state),
        sequencer.clone(),
        starting_block_hash,
        starting_block_num,
        chain,
    ));

    // Start L1 and L2 sync processes.
    let mut l1_handle = tokio::spawn(l1_sync(tx_l1, transport.clone(), chain, l1_head));
    let mut l2_handle = tokio::spawn(l2_sync(tx_l2, sequencer.clone(), l2_head, chain));

    let mut existed = (0, 0);

    let mut last_block_start = std::time::Instant::now();
    let mut block_time_avg = std::time::Duration::ZERO;
    const BLOCK_TIME_WEIGHT: f32 = 0.05;

    loop {
        tokio::select! {
            l1_event = rx_l1.recv() => match l1_event {
                Some(l1::Event::Update(updates)) => {
                    let first = updates.first().map(|u| u.block_number.0);
                    let last = updates.last().map(|u| u.block_number.0);

                    l1_update(&mut db_conn, &updates).await.with_context(|| {
                        format!("Update L1 state with blocks {:?}-{:?}", first, last)
                    })?;

                    match updates.as_slice() {
                        [single] => {
                            tracing::info!("L1 sync updated to block {}", single.block_number.0);
                        }
                        [first, .., last] => {
                            tracing::info!(
                                "L1 sync updated with blocks {} - {}",
                                first.block_number.0,
                                last.block_number.0
                            );
                        }
                        _ => {}
                    }
                }
                Some(l1::Event::Reorg(reorg_tail)) => {
                    l1_reorg(&mut db_conn, reorg_tail)
                        .await
                        .with_context(|| format!("Reorg L1 state to block {}", reorg_tail.0))?;

                    let new_head = match reorg_tail {
                        StarknetBlockNumber::GENESIS => None,
                        other => Some(other - 1),
                    };

                    match new_head {
                        Some(head) => {
                            tracing::info!("L1 reorg occurred, new L1 head is block {}", head.0)
                        }
                        None => tracing::info!("L1 reorg occurred, new L1 head is genesis"),
                    }
                }
                Some(l1::Event::QueryUpdate(block, tx)) => {
                    let update =
                        tokio::task::block_in_place(|| L1StateTable::get(&db_conn, block.into()))
                            .with_context(|| format!("Query L1 state table for block {:?}", block))?;

                    let _ = tx.send(update);

                    tracing::trace!("Query for L1 update for block {}", block.0);
                }
                None => {
                    // L1 sync process failed; restart it.
                    match l1_handle.await.context("Join L1 sync process handle")? {
                        Ok(()) => {
                            tracing::error!("L1 sync process terminated without an error.");
                        }
                        Err(e) => {
                            tracing::warn!("L1 sync process terminated with: {:?}", e);
                        }
                    }
                    let l1_head = tokio::task::block_in_place(|| {
                        L1StateTable::get(&db_conn, L1TableBlockId::Latest)
                    })
                    .context("Query L1 head from database")?;

                    let (new_tx, new_rx) = mpsc::channel(1);
                    rx_l1 = new_rx;

                    l1_handle = tokio::spawn(l1_sync(new_tx, transport.clone(), chain, l1_head));
                    tracing::info!("L1 sync process restarted.")
                },
            },
            l2_event = rx_l2.recv() => match l2_event {
                Some(l2::Event::Update(block, diff, timings)) => {
                    // unwrap is safe as only pending query blocks are None.
                    let block_num = block.block_number.unwrap().0;
                    let block_hash = block.block_hash.unwrap();
                    let storage_updates: usize = diff
                        .contract_updates
                        .iter()
                        .map(|u| u.storage_updates.len())
                        .sum();
                    let update_t = std::time::Instant::now();
                    l2_update(&mut db_conn, *block, diff)
                        .await
                        .with_context(|| format!("Update L2 state to {}", block_num))?;
                    let block_time = last_block_start.elapsed();
                    let update_t = update_t.elapsed();
                    last_block_start = std::time::Instant::now();

                    block_time_avg = block_time_avg.mul_f32(1.0 - BLOCK_TIME_WEIGHT)
                        + block_time.mul_f32(BLOCK_TIME_WEIGHT);

                    // Update sync status
                    match &mut *state.status.write().await {
                        SyncStatus::False(_) => {}
                        SyncStatus::Status(status) => {
                            status.current = NumberedBlock::from((block_hash, StarknetBlockNumber(block_num)));

                            if status.highest.number.0 <= block_num {
                                status.highest = status.current;
                            }
                        }
                    }

                    // Give a simple log under INFO level, and a more verbose log
                    // with timing information under DEBUG+ level.
                    //
                    // This should be removed if we have a configurable log level.
                    // See the docs for LevelFilter for more information.
                    match tracing::level_filters::LevelFilter::current().into_level() {
                        None => {}
                        Some(level) if level <= tracing::Level::INFO => {
                            tracing::info!("Updated StarkNet state with block {}", block_num)
                        }
                        Some(_) => {
                            tracing::debug!("Updated StarkNet state with block {} after {:2}s ({:2}s avg). {} ({} new) contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in {:2}s, state diff in {:2}s",
                                block_num,
                                block_time.as_secs_f32(),
                                block_time_avg.as_secs_f32(),
                                existed.0,
                                existed.0 - existed.1,
                                timings.contract_deployment.as_secs_f32(),
                                storage_updates,
                                update_t.as_secs_f32(),
                                timings.block_download.as_secs_f32(),
                                timings.state_diff_download.as_secs_f32(),
                            );
                        }
                    }
                }
                Some(l2::Event::Reorg(reorg_tail)) => {
                    l2_reorg(&mut db_conn, reorg_tail)
                        .await
                        .with_context(|| format!("Reorg L2 state to {:?}", reorg_tail))?;

                    let new_head = match reorg_tail {
                        StarknetBlockNumber::GENESIS => None,
                        other => Some(other - 1),
                    };
                    match new_head {
                        Some(head) => {
                            tracing::info!("L2 reorg occurred, new L2 head is block {}", head.0)
                        }
                        None => tracing::info!("L2 reorg occurred, new L2 head is genesis"),
                    }
                }
                Some(l2::Event::NewContract(contract)) => {
                    tokio::task::block_in_place(|| {
                        ContractCodeTable::insert_compressed(&db_conn, &contract)
                    })
                    .with_context(|| {
                        format!("Insert contract definition with hash: {:?}", contract.hash)
                    })?;

                    tracing::trace!("Inserted new contract {}", contract.hash.0.to_hex_str());
                }
                Some(l2::Event::QueryHash(block, tx)) => {
                    let hash = tokio::task::block_in_place(|| {
                        StarknetBlocksTable::get(&db_conn, block.into())
                    })
                    .with_context(|| format!("Query L2 block hash for block {:?}", block))?
                    .map(|block| block.hash);
                    let _ = tx.send(hash);

                    tracing::trace!("Query hash for L2 block {}", block.0);
                }
                Some(l2::Event::QueryContractExistance(contracts, tx)) => {
                    let exists =
                        tokio::task::block_in_place(|| ContractCodeTable::exists(&db_conn, &contracts))
                            .with_context(|| {
                                format!("Query storage for existance of contracts {:?}", contracts)
                            })?;
                    let count = exists.iter().filter(|b| **b).count();

                    existed = (contracts.len(), count);

                    let _ = tx.send(exists);

                    tracing::trace!("Query for existence of contracts: {:?}", contracts);
                }
                None => {
                    // L2 sync process failed; restart it.
                    match l2_handle.await.context("Join L2 sync process handle")? {
                        Ok(()) => {
                            tracing::error!("L2 sync process terminated without an error.");
                        }
                        Err(e) => {
                            tracing::warn!("L2 sync process terminated with: {:?}", e);
                        }
                    }

                    let l2_head = tokio::task::block_in_place(|| {
                        StarknetBlocksTable::get(&db_conn, StarknetBlocksBlockId::Latest)
                    })
                    .context("Query L2 head from database")?
                    .map(|block| (block.number, block.hash));

                    let (new_tx, new_rx) = mpsc::channel(1);
                    rx_l2 = new_rx;

                    l2_handle = tokio::spawn(l2_sync(new_tx, sequencer.clone(), l2_head, chain));
                    tracing::info!("L2 sync process restarted.");
                }
            }
        }
    }
}

/// Periodically updates sync state with the latest block height.
async fn update_sync_status_latest(
    state: Arc<State>,
    sequencer: impl sequencer::ClientApi,
    starting_block_hash: StarknetBlockHash,
    starting_block_num: StarknetBlockNumber,
    chain: Chain,
) -> anyhow::Result<()> {
    use crate::core::BlockId;

    let poll_interval = head_poll_interval(chain);

    let starting = NumberedBlock::from((starting_block_hash, starting_block_num));

    loop {
        match sequencer.block(BlockId::Latest).await {
            Ok(block) => {
                let latest = {
                    let latest_hash = block.block_hash.unwrap();
                    let latest_num = block.block_number.unwrap();
                    NumberedBlock::from((latest_hash, latest_num))
                };
                // Update the sync status.
                match &mut *state.status.write().await {
                    sync_status @ SyncStatus::False(_) => {
                        *sync_status = SyncStatus::Status(syncing::Status {
                            starting,
                            current: starting,
                            highest: latest,
                        });

                        tracing::debug!(
                            status=%sync_status,
                            "Updated sync status",
                        );
                    }
                    SyncStatus::Status(status) => {
                        if status.highest.hash != latest.hash {
                            status.highest = latest;

                            tracing::debug!(
                                %status,
                                "Updated sync status",
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(error=%e, "Failed to fetch latest block");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn l1_update(connection: &mut Connection, updates: &[StateUpdateLog]) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;

        for update in updates {
            L1StateTable::insert(&transaction, update).context("Insert update")?;
        }

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(StarknetBlockNumber::GENESIS);

        match updates.first() {
            Some(update) if update.block_number == expected_next => {
                let mut next_head = None;
                for update in updates {
                    let l2_root =
                        StarknetBlocksTable::get(&transaction, update.block_number.into())
                            .context("Query L2 root")?
                            .map(|block| block.root);

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
    })
}

async fn l1_reorg(
    connection: &mut Connection,
    reorg_tail: StarknetBlockNumber,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;

        L1StateTable::reorg(&transaction, reorg_tail).context("Delete L1 state from database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        match l1_l2_head {
            Some(head) if head >= reorg_tail => {
                let new_head = match reorg_tail {
                    StarknetBlockNumber::GENESIS => None,
                    other => Some(other - 1),
                };
                RefsTable::set_l1_l2_head(&transaction, new_head).context("Update L1-L2 head")?;
            }
            _ => {}
        }

        transaction.commit().context("Commit database transaction")
    })
}

async fn l2_update(
    connection: &mut Connection,
    block: Block,
    state_diff: StateUpdate,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;

        let new_root =
            update_starknet_state(&transaction, state_diff).context("Updating Starknet state")?;

        // Ensure that roots match.. what should we do if it doesn't? For now the whole sync process ends..
        anyhow::ensure!(new_root == block.state_root.unwrap(), "State root mismatch");

        // Update L2 database. These types shouldn't be options at this level,
        // but for now the unwraps are "safe" in that these should only ever be
        // None for pending queries to the sequencer, but we aren't using those here.
        let starknet_block = StarknetBlock {
            number: block.block_number.unwrap(),
            hash: block.block_hash.unwrap(),
            root: block.state_root.unwrap(),
            timestamp: block.timestamp,
            // Default value for cairo <0.8.2 is 0
            gas_price: block.gas_price.unwrap_or(GasPrice::ZERO),
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(StarkHash::ZERO)),
        };
        StarknetBlocksTable::insert(&transaction, &starknet_block)
            .context("Insert block into database")?;

        // Insert the transactions.
        anyhow::ensure!(
            block.transactions.len() == block.transaction_receipts.len(),
            "Transactions and receipts mismatch. There were {} transactions and {} receipts.",
            block.transactions.len(),
            block.transaction_receipts.len()
        );
        let transaction_data = block
            .transactions
            .into_iter()
            .zip(block.transaction_receipts.into_iter())
            .collect::<Vec<_>>();
        StarknetTransactionsTable::upsert(
            &transaction,
            starknet_block.hash,
            starknet_block.number,
            &transaction_data,
        )
        .context("Insert transaction data into database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(StarknetBlockNumber::GENESIS);

        if expected_next == starknet_block.number {
            let l1_root = L1StateTable::get_root(&transaction, starknet_block.number.into())
                .context("Query L1 root")?;
            if l1_root == Some(starknet_block.root) {
                RefsTable::set_l1_l2_head(&transaction, Some(starknet_block.number))
                    .context("Update L1-L2 head")?;
            }
        }

        transaction.commit().context("Commit database transaction")
    })
}

async fn l2_reorg(
    connection: &mut Connection,
    reorg_tail: StarknetBlockNumber,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;

        // TODO: clean up state tree's as well...

        StarknetBlocksTable::reorg(&transaction, reorg_tail)
            .context("Delete L2 state from database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        match l1_l2_head {
            Some(head) if head >= reorg_tail => {
                let new_head = match reorg_tail {
                    StarknetBlockNumber::GENESIS => None,
                    other => Some(other - 1),
                };
                RefsTable::set_l1_l2_head(&transaction, new_head).context("Update L1-L2 head")?;
            }
            _ => {}
        }

        transaction.commit().context("Commit database transaction")
    })
}

fn update_starknet_state(
    transaction: &Transaction<'_>,
    diff: StateUpdate,
) -> anyhow::Result<GlobalRoot> {
    let global_root = StarknetBlocksTable::get(transaction, StarknetBlocksBlockId::Latest)
        .context("Query latest state root")?
        .map(|block| block.root)
        .unwrap_or(GlobalRoot(StarkHash::ZERO));
    let mut global_tree =
        GlobalStateTree::load(transaction, global_root).context("Loading global state tree")?;

    for contract in diff.deployed_contracts {
        deploy_contract(transaction, &mut global_tree, contract).context("Deploying contract")?;
    }

    for update in diff.contract_updates {
        let contract_state_hash = update_contract_state(&update, &global_tree, transaction)
            .context("Update contract state")?;

        // Update the global state tree.
        global_tree
            .set(update.address, contract_state_hash)
            .context("Updating global state tree")?;
    }

    // Apply all global tree changes.
    global_tree
        .apply()
        .context("Apply global state tree updates")
}

fn deploy_contract(
    transaction: &Transaction<'_>,
    global_tree: &mut GlobalStateTree<'_>,
    contract: DeployedContract,
) -> anyhow::Result<()> {
    // Add a new contract to global tree, the contract root is initialized to ZERO.
    let contract_root = ContractRoot(StarkHash::ZERO);
    let state_hash = calculate_contract_state_hash(contract.hash, contract_root);
    global_tree
        .set(contract.address, state_hash)
        .context("Adding deployed contract to global state tree")?;
    ContractsStateTable::upsert(transaction, state_hash, contract.hash, contract_root)
        .context("Insert constract state hash into contracts state table")?;
    ContractsTable::upsert(transaction, contract.address, contract.hash)
        .context("Inserting class hash into contracts table")
}

/// Interval at which poll for new data when at the head of chain.
///
/// Returns the interval to be used when polling while at the head of the chain. The
/// interval is chosen to provide a good balance between spamming and getting new
/// block information as it is available. The interval is based on the block creation
/// time, which is 2 minutes for Goerlie and 2 hours for Mainnet.
pub fn head_poll_interval(chain: crate::ethereum::Chain) -> std::time::Duration {
    use crate::ethereum::Chain::*;
    use std::time::Duration;

    match chain {
        // 15 minute interval for a 2 hour block time.
        Mainnet => Duration::from_secs(60 * 15),
        // 30 second interval for a 2 minute block time.
        Goerli => Duration::from_secs(30),
    }
}

#[cfg(test)]
mod tests {
    use super::{l1, l2};
    use crate::{
        core::{
            CallSignatureElem, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
            EthereumTransactionIndex, Fee, GasPrice, GlobalRoot, SequencerAddress,
            StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
            StarknetTransactionHash, StorageAddress, StorageValue, TransactionNonce,
            TransactionVersion,
        },
        ethereum,
        rpc::types::BlockHashOrTag,
        sequencer::{
            self,
            error::SequencerError,
            reply,
            request::{self, add_transaction::ContractDefinition},
        },
        state,
        storage::{self, L1StateTable, RefsTable, StarknetBlocksTable, Storage},
    };
    use futures::stream::{StreamExt, TryStreamExt};
    use stark_hash::StarkHash;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;
    use web3::types::H256;

    #[derive(Debug, Clone)]
    struct FakeTransport;

    #[async_trait::async_trait]
    impl ethereum::transport::EthereumTransport for FakeTransport {
        async fn block(
            &self,
            _: web3::types::BlockId,
        ) -> web3::Result<Option<web3::types::Block<H256>>> {
            unimplemented!()
        }

        async fn block_number(&self) -> web3::Result<u64> {
            unimplemented!()
        }

        async fn chain(&self) -> anyhow::Result<ethereum::Chain> {
            unimplemented!()
        }

        async fn logs(
            &self,
            _: web3::types::Filter,
        ) -> std::result::Result<Vec<web3::types::Log>, ethereum::transport::LogsError> {
            unimplemented!()
        }

        async fn transaction(
            &self,
            _: web3::types::TransactionId,
        ) -> web3::Result<Option<web3::types::Transaction>> {
            unimplemented!()
        }

        async fn gas_price(&self) -> web3::Result<web3::types::U256> {
            unimplemented!()
        }
    }

    // We need a simple clonable mock here. Satisfies the sync() internals,
    // and is not really called anywhere in the tests except for status updates
    // which we don't test against here.
    #[derive(Debug, Clone)]
    struct FakeSequencer;

    #[async_trait::async_trait]
    impl sequencer::ClientApi for FakeSequencer {
        async fn block(&self, block: crate::core::BlockId) -> Result<reply::Block, SequencerError> {
            match block {
                crate::core::BlockId::Number(_) => Ok(BLOCK0.clone()),
                _ => unimplemented!(),
            }
        }

        async fn call(
            &self,
            _: request::Call,
            _: BlockHashOrTag,
        ) -> Result<reply::Call, SequencerError> {
            unimplemented!()
        }

        async fn full_contract(&self, _: ContractAddress) -> Result<bytes::Bytes, SequencerError> {
            unimplemented!()
        }

        async fn class_by_hash(&self, _: ClassHash) -> Result<bytes::Bytes, SequencerError> {
            unimplemented!()
        }

        async fn class_hash_at(&self, _: ContractAddress) -> Result<ClassHash, SequencerError> {
            unimplemented!()
        }

        async fn storage(
            &self,
            _: ContractAddress,
            _: StorageAddress,
            _: BlockHashOrTag,
        ) -> Result<StorageValue, SequencerError> {
            unimplemented!()
        }

        async fn transaction(
            &self,
            _: StarknetTransactionHash,
        ) -> Result<reply::Transaction, SequencerError> {
            unimplemented!()
        }

        async fn transaction_status(
            &self,
            _: StarknetTransactionHash,
        ) -> Result<reply::TransactionStatus, SequencerError> {
            unimplemented!()
        }

        async fn state_update(
            &self,
            _: crate::core::BlockId,
        ) -> Result<reply::StateUpdate, SequencerError> {
            unimplemented!()
        }

        async fn eth_contract_addresses(
            &self,
        ) -> Result<reply::EthContractAddresses, SequencerError> {
            unimplemented!()
        }

        async fn add_invoke_transaction(
            &self,
            _: crate::sequencer::request::Call,
            _: Fee,
            _: TransactionVersion,
        ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
            unimplemented!()
        }

        async fn add_declare_transaction(
            &self,
            _: ContractDefinition,
            _: ContractAddress,
            _: Fee,
            _: Vec<CallSignatureElem>,
            _: TransactionNonce,
            _: TransactionVersion,
            _: Option<String>,
        ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
            unimplemented!()
        }

        async fn add_deploy_transaction(
            &self,
            _: ContractAddressSalt,
            _: Vec<ConstructorParam>,
            _: ContractDefinition,
            _: Option<String>,
        ) -> Result<reply::add_transaction::DeployResponse, SequencerError> {
            unimplemented!()
        }
    }

    async fn l1_noop(
        _: mpsc::Sender<l1::Event>,
        _: FakeTransport,
        _: ethereum::Chain,
        _: Option<ethereum::log::StateUpdateLog>,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        let () = std::future::pending().await;
        Ok(())
    }

    async fn l2_noop(
        _: mpsc::Sender<l2::Event>,
        _: impl sequencer::ClientApi,
        _: Option<(StarknetBlockNumber, StarknetBlockHash)>,
        _: crate::ethereum::Chain,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        let () = std::future::pending().await;
        Ok(())
    }

    lazy_static::lazy_static! {
        static ref A: StarkHash = StarkHash::from_be_slice(&[0xA]).unwrap();
        static ref B: StarkHash = StarkHash::from_be_slice(&[0xB]).unwrap();
        static ref ETH_ORIG: ethereum::EthOrigin = ethereum::EthOrigin {
            block: ethereum::BlockOrigin {
                hash: EthereumBlockHash(H256::zero()),
                number: EthereumBlockNumber(0),
            },
            log_index: EthereumLogIndex(0),
            transaction: ethereum::TransactionOrigin {
                hash: EthereumTransactionHash(H256::zero()),
                index: EthereumTransactionIndex(0),
            },
        };
        pub static ref STATE_UPDATE_LOG0: ethereum::log::StateUpdateLog = ethereum::log::StateUpdateLog {
            block_number: StarknetBlockNumber(0),
            // State update actually doesn't change the state hence 0 root
            global_root: GlobalRoot(StarkHash::ZERO),
            origin: ETH_ORIG.clone(),
        };
        pub static ref STATE_UPDATE_LOG1: ethereum::log::StateUpdateLog = ethereum::log::StateUpdateLog {
            block_number: StarknetBlockNumber(1),
            global_root: GlobalRoot(*B),
            origin: ETH_ORIG.clone(),
        };
        pub static ref BLOCK0: reply::Block = reply::Block {
            block_hash: Some(StarknetBlockHash(*A)),
            block_number: Some(StarknetBlockNumber(0)),
            gas_price: Some(GasPrice::ZERO),
            parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
            sequencer_address: Some(SequencerAddress(StarkHash::ZERO)),
            state_root: Some(GlobalRoot(StarkHash::ZERO)),
            status: reply::Status::AcceptedOnL1,
            timestamp: crate::core::StarknetBlockTimestamp(0),
            transaction_receipts: vec![],
            transactions: vec![],
        };
        pub static ref BLOCK1: reply::Block = reply::Block {
            block_hash: Some(StarknetBlockHash(*B)),
            block_number: Some(StarknetBlockNumber(1)),
            gas_price: Some(GasPrice::from(1)),
            parent_block_hash: StarknetBlockHash(*A),
            sequencer_address: Some(SequencerAddress(StarkHash::from_be_bytes([1u8; 32]).unwrap())),
            state_root: Some(GlobalRoot(*B)),
            status: reply::Status::AcceptedOnL2,
            timestamp: crate::core::StarknetBlockTimestamp(1),
            transaction_receipts: vec![],
            transactions: vec![],
        };
        pub static ref STORAGE_BLOCK0: storage::StarknetBlock = storage::StarknetBlock {
            number: StarknetBlockNumber(0),
            hash: StarknetBlockHash(*A),
            root: GlobalRoot(StarkHash::ZERO),
            timestamp: StarknetBlockTimestamp(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(StarkHash::ZERO),
        };
        pub static ref STORAGE_BLOCK1: storage::StarknetBlock = storage::StarknetBlock {
            number: StarknetBlockNumber(1),
            hash: StarknetBlockHash(*B),
            root: GlobalRoot(*B),
            timestamp: StarknetBlockTimestamp(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(StarkHash::from_be_bytes([1u8; 32]).unwrap()),
        };
        // Causes root to remain 0
        pub static ref STATE_UPDATE0: ethereum::state_update::StateUpdate = ethereum::state_update::StateUpdate {
            contract_updates: vec![],
            deployed_contracts: vec![],
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_update() {
        let chain = ethereum::Chain::Goerli;
        let sync_state = Arc::new(state::SyncState::default());

        lazy_static::lazy_static! {
            static ref UPDATES: Arc<tokio::sync::RwLock<Vec<Vec<ethereum::log::StateUpdateLog>>>> =
            Arc::new(tokio::sync::RwLock::new(vec![
                vec![STATE_UPDATE_LOG0.clone(), STATE_UPDATE_LOG1.clone()],
                vec![STATE_UPDATE_LOG0.clone()],
                vec![STATE_UPDATE_LOG0.clone()],
            ]));
        }

        // A simple L1 sync task
        let l1 = |tx: mpsc::Sender<l1::Event>, _, _, _| async move {
            let mut update = UPDATES.write().await;
            if let Some(some_update) = update.pop() {
                tx.send(l1::Event::Update(some_update)).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        };

        let results = [
            // Case 0: no L2 head
            None,
            // Case 1: some L2 head
            Some(vec![STORAGE_BLOCK0.clone()]),
            // Case 2: some L2 head, update contains more than one item
            Some(vec![STORAGE_BLOCK0.clone(), STORAGE_BLOCK1.clone()]),
        ]
        .into_iter()
        .map(|blocks| async {
            let storage = Storage::in_memory().unwrap();
            let connection = storage.connection().unwrap();

            if let Some(some_blocks) = blocks {
                some_blocks
                    .iter()
                    .for_each(|block| StarknetBlocksTable::insert(&connection, block).unwrap());
            }

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                chain,
                FakeSequencer,
                sync_state.clone(),
                l1,
                l2_noop,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(300)).await;

            RefsTable::get_l1_l2_head(&connection)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected
                None,
                // Case 1: some L1-L2 head expected
                Some(StarknetBlockNumber(0)),
                // Case 2: some L1-L2 head expected
                Some(StarknetBlockNumber(1))
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_reorg() {
        let results = [
            // Case 0: single block in L1, reorg on genesis
            (vec![STATE_UPDATE_LOG0.clone()], 0),
            // Case 1: 2 blocks in L1, reorg on block #1
            (
                vec![STATE_UPDATE_LOG0.clone(), STATE_UPDATE_LOG1.clone()],
                1,
            ),
        ]
        .into_iter()
        .map(|(updates, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let connection = storage.connection().unwrap();

            // A simple L1 sync task
            let l1 = move |tx: mpsc::Sender<l1::Event>, _, _, _| async move {
                tx.send(l1::Event::Reorg(StarknetBlockNumber(reorg_on_block)))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            RefsTable::set_l1_l2_head(&connection, Some(StarknetBlockNumber(reorg_on_block)))
                .unwrap();
            updates
                .into_iter()
                .for_each(|update| L1StateTable::insert(&connection, &update).unwrap());

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                ethereum::Chain::Goerli,
                FakeSequencer,
                Arc::new(state::SyncState::default()),
                l1,
                l2_noop,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(10)).await;

            let latest_block_number =
                L1StateTable::get(&connection, storage::L1TableBlockId::Latest)
                    .unwrap()
                    .map(|s| s.block_number);
            let head = RefsTable::get_l1_l2_head(&connection).unwrap();
            (head, latest_block_number)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await;

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected, as we start from genesis
                (None, None),
                // Case 1: some L1-L2 head expected, block #1 removed
                (Some(StarknetBlockNumber(0)), Some(StarknetBlockNumber(0)))
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_query_update() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();

        // This is what we're asking for
        L1StateTable::insert(&connection, &*STATE_UPDATE_LOG0).unwrap();

        // A simple L1 sync task which does the request and checks he result
        let l1 = |tx: mpsc::Sender<l1::Event>, _, _, _| async move {
            let (tx1, rx1) =
                tokio::sync::oneshot::channel::<Option<ethereum::log::StateUpdateLog>>();

            tx.send(l1::Event::QueryUpdate(StarknetBlockNumber(0), tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            assert_eq!(rx1.await.unwrap().unwrap(), *STATE_UPDATE_LOG0);

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1,
            l2_noop,
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let storage = Storage::in_memory().unwrap();

        static CNT: AtomicUsize = AtomicUsize::new(0);

        // A simple L1 sync task
        let l1 = move |_, _, _, _| async move {
            CNT.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1,
            l2_noop,
        ));

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(CNT.load(Ordering::Relaxed) > 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_update() {
        let chain = ethereum::Chain::Goerli;
        let sync_state = Arc::new(state::SyncState::default());

        // Incoming L2 update
        let block = || BLOCK0.clone();
        let state_update = || STATE_UPDATE0.clone();
        let timings = l2::Timings {
            block_download: Duration::default(),
            state_diff_download: Duration::default(),
            contract_deployment: Duration::default(),
        };

        // A simple L2 sync task
        let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _| async move {
            tx.send(l2::Event::Update(
                Box::new(block()),
                state_update(),
                timings,
            ))
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        let results = [
            // Case 0: no L1 head
            None,
            // Case 1: some L1 head
            Some(STATE_UPDATE_LOG0.clone()),
        ]
        .into_iter()
        .map(|update_log| async {
            let storage = Storage::in_memory().unwrap();
            let connection = storage.connection().unwrap();

            if let Some(some_update_log) = update_log {
                L1StateTable::insert(&connection, &some_update_log).unwrap();
            }

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                chain,
                FakeSequencer,
                sync_state.clone(),
                l1_noop,
                l2,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(100)).await;

            RefsTable::get_l1_l2_head(&connection)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected
                None,
                // Case 1: some L1-L2 head expected
                Some(StarknetBlockNumber(0))
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_reorg() {
        let results = [
            // Case 0: single block in L2, reorg on genesis
            (vec![STORAGE_BLOCK0.clone()], 0),
            // Case 1: 2 blocks in L2, reorg on block #1
            (vec![STORAGE_BLOCK0.clone(), STORAGE_BLOCK1.clone()], 1),
        ]
        .into_iter()
        .map(|(updates, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let connection = storage.connection().unwrap();

            // A simple L2 sync task
            let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _| async move {
                tx.send(l2::Event::Reorg(StarknetBlockNumber(reorg_on_block)))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            RefsTable::set_l1_l2_head(&connection, Some(StarknetBlockNumber(reorg_on_block)))
                .unwrap();
            updates
                .into_iter()
                .for_each(|block| StarknetBlocksTable::insert(&connection, &block).unwrap());

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                ethereum::Chain::Goerli,
                FakeSequencer,
                Arc::new(state::SyncState::default()),
                l1_noop,
                l2,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(100)).await;

            let latest_block_number =
                StarknetBlocksTable::get(&connection, storage::StarknetBlocksBlockId::Latest)
                    .unwrap()
                    .map(|s| s.number);
            let head = RefsTable::get_l1_l2_head(&connection).unwrap();
            (head, latest_block_number)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await;

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected, as we start from genesis
                (None, None),
                // Case 1: some L1-L2 head expected, block #1 removed
                (Some(StarknetBlockNumber(0)), Some(StarknetBlockNumber(0)))
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_new_contract() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _| async move {
            let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
            tx.send(l2::Event::NewContract(state::CompressedContract {
                abi: zstd_magic.clone(),
                bytecode: zstd_magic.clone(),
                definition: zstd_magic,
                hash: ClassHash(*A),
            }))
            .await
            .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
        ));

        // TODO Find a better way to figure out that the DB update has already been performed
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            storage::ContractCodeTable::exists(&connection, &[ClassHash(*A)]).unwrap(),
            vec![true]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_query_hash() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();

        // This is what we're asking for
        StarknetBlocksTable::insert(&connection, &STORAGE_BLOCK0).unwrap();

        // A simple L2 sync task which does the request and checks he result
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _| async move {
            let (tx1, rx1) = tokio::sync::oneshot::channel::<Option<StarknetBlockHash>>();

            tx.send(l2::Event::QueryHash(StarknetBlockNumber(0), tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            assert_eq!(rx1.await.unwrap().unwrap(), StarknetBlockHash(*A));

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_query_contract_existance() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();
        let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

        // This is what we're asking for
        storage::ContractCodeTable::insert_compressed(
            &connection,
            &state::CompressedContract {
                abi: zstd_magic.clone(),
                bytecode: zstd_magic.clone(),
                definition: zstd_magic,
                hash: ClassHash(*A),
            },
        )
        .unwrap();

        // A simple L2 sync task which does the request and checks he result
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _| async move {
            let (tx1, rx1) = tokio::sync::oneshot::channel::<Vec<bool>>();

            tx.send(l2::Event::QueryContractExistance(vec![ClassHash(*A)], tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            assert_eq!(rx1.await.unwrap(), vec![true]);

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let storage = Storage::in_memory().unwrap();

        static CNT: AtomicUsize = AtomicUsize::new(0);

        // A simple L2 sync task
        let l2 = move |_, _, _, _| async move {
            CNT.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            ethereum::Chain::Goerli,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
        ));

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(CNT.load(Ordering::Relaxed) > 1);
    }
}
