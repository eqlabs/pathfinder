#![allow(dead_code)]

mod l1;
mod l2;

use crate::{
    core::{
        ContractHash, ContractRoot, GlobalRoot, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp,
    },
    ethereum::{
        log::StateUpdateLog,
        state_update::{DeployedContract, StateUpdate},
        Chain,
    },
    sequencer::{self, reply::Block},
    state::{
        calculate_contract_state_hash, state_tree::GlobalStateTree, update_contract_state,
        CompressedContract,
    },
    storage::{
        BlockId, ContractCodeTable, ContractsStateTable, ContractsTable, L1StateTable, RefsTable,
        StarknetBlock, StarknetBlocksTable, Storage,
    },
};

use anyhow::Context;
use pedersen::StarkHash;
use rusqlite::{Connection, Transaction};
use tokio::sync::{mpsc, oneshot};
use web3::{transports::Http, Web3};

/// The sync events which are emitted by the L1 and L2 sync processes.
#[derive(Debug)]
enum SyncEvent {
    L1Update(Vec<StateUpdateLog>),
    L2Update(Block, StateUpdate),
    L1Reorg(StarknetBlockNumber),
    L2Reorg(StarknetBlockNumber),
    L2NewContract(CompressedContract),
    QueryL1Update(StarknetBlockNumber, oneshot::Sender<Option<StateUpdateLog>>),
    QueryL2Hash(
        StarknetBlockNumber,
        oneshot::Sender<Option<StarknetBlockHash>>,
    ),
    QueryL2ContractExistance(Vec<ContractHash>, oneshot::Sender<Vec<bool>>),
}

pub fn sync(
    storage: Storage,
    transport: Web3<Http>,
    chain: Chain,
    sequencer: sequencer::Client,
) -> anyhow::Result<()> {
    // TODO: should this be owning a Storage, or just take in a Connection?
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_events, mut rx_events) = mpsc::channel(1);

    let l1_head =
        L1StateTable::get(&db_conn, BlockId::Latest).context("Query L1 head from database")?;

    let l2_head = StarknetBlocksTable::get_without_tx(&db_conn, BlockId::Latest)
        .context("Query L2 head from database")?
        .map(|block| (block.number, block.hash));

    let l1_process = tokio::spawn(l1::sync(tx_events.clone(), transport, chain, l1_head));
    let l2_process = tokio::spawn(l2::sync(tx_events, sequencer, l2_head));

    while let Some(event) = rx_events.blocking_recv() {
        match event {
            SyncEvent::L1Update(updates) => {
                let first = updates.first().map(|u| u.block_number.0);
                let last = updates.last().map(|u| u.block_number.0);

                l1_update(&mut db_conn, updates).with_context(|| {
                    format!("Update L1 state with blocks {:?}-{:?}", first, last)
                })?;

                println!("Updated L1 state with blocks {:?}-{:?}", first, last);
            }
            SyncEvent::L2Update(block, diff) => {
                // unwrap is safe as only pending query blocks are None.
                let block_num = block.block_number.unwrap().0;
                l2_update(&mut db_conn, block, diff)
                    .with_context(|| format!("Update L2 state to {}", block_num))?;

                println!("Updated L2 state to block {}", block_num);
            }
            SyncEvent::L1Reorg(reorg_tail) => {
                l1_reorg(&mut db_conn, reorg_tail)
                    .with_context(|| format!("Reorg L1 state to block {}", reorg_tail.0))?;

                let new_head = match reorg_tail {
                    StarknetBlockNumber::GENESIS => None,
                    other => Some(other - 1),
                };
                println!("L1 reorg occurred, new L1 head is {:?}", new_head);
            }
            SyncEvent::L2Reorg(reorg_tail) => {
                l2_reorg(&mut db_conn, reorg_tail)
                    .with_context(|| format!("Reorg L2 state to {:?}", reorg_tail))?;

                let new_head = match reorg_tail {
                    StarknetBlockNumber::GENESIS => None,
                    other => Some(other - 1),
                };
                println!("L2 reorg occurred, new L2 head is {:?}", new_head);
            }
            SyncEvent::L2NewContract(contract) => {
                ContractCodeTable::insert_compressed(&db_conn, &contract).with_context(|| {
                    format!("Insert contract definition with hash: {:?}", contract.hash)
                })?;

                println!("Inserted new contract with hash: {}", contract.hash.0.to_hex_str());
            }
            SyncEvent::QueryL1Update(block, tx) => {
                let update = L1StateTable::get(&db_conn, block.into())
                    .with_context(|| format!("Query L1 state for block {:?}", block))?;
                let _ = tx.send(update);
            }
            SyncEvent::QueryL2Hash(block, tx) => {
                let hash = StarknetBlocksTable::get_without_tx(&db_conn, block.into())
                    .with_context(|| format!("Query L2 block hash for block {:?}", block))?
                    .map(|block| block.hash);
                let _ = tx.send(hash);
            }
            SyncEvent::QueryL2ContractExistance(contracts, tx) => {
                let exists =
                    ContractCodeTable::exists(&db_conn, &contracts).with_context(|| {
                        format!("Query storage for existance of contracts {:?}", contracts)
                    })?;
                let _ = tx.send(exists);
            }
        }
    }

    l1_process.abort();
    l2_process.abort();

    Ok(())
}

fn l1_update(connection: &mut Connection, updates: Vec<StateUpdateLog>) -> anyhow::Result<()> {
    let transaction = connection
        .transaction()
        .context("Create database transaction")?;

    for update in &updates {
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
                    StarknetBlocksTable::get_without_tx(&transaction, update.block_number.into())
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
}

fn l1_reorg(connection: &mut Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
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
}

fn l2_update(
    connection: &mut Connection,
    block: Block,
    state_diff: StateUpdate,
) -> anyhow::Result<()> {
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
    let block = StarknetBlock {
        number: block.block_number.unwrap(),
        hash: block.block_hash.unwrap(),
        root: block.state_root.unwrap(),
        timestamp: StarknetBlockTimestamp(block.timestamp),
        transaction_receipts: block.transaction_receipts,
        transactions: block.transactions,
    };
    StarknetBlocksTable::insert(&transaction, &block).context("Insert update")?;

    // Track combined L1 and L2 state.
    let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
    let expected_next = l1_l2_head
        .map(|head| head + 1)
        .unwrap_or(StarknetBlockNumber::GENESIS);

    if expected_next == block.number {
        let l1_root =
            L1StateTable::get_root(&transaction, block.number.into()).context("Query L1 root")?;
        if l1_root == Some(block.root) {
            RefsTable::set_l1_l2_head(&transaction, Some(block.number))
                .context("Update L1-L2 head")?;
        }
    }

    transaction.commit().context("Commit database transaction")
}

fn l2_reorg(connection: &mut Connection, reorg_tail: StarknetBlockNumber) -> anyhow::Result<()> {
    let transaction = connection
        .transaction()
        .context("Create database transaction")?;

    // TODO: clean up state tree's as well...

    StarknetBlocksTable::reorg(&transaction, reorg_tail)
        .context("Delete L1 state from database")?;

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
}

fn update_starknet_state(
    transaction: &Transaction,
    diff: StateUpdate,
) -> anyhow::Result<GlobalRoot> {
    let global_root = StarknetBlocksTable::get_without_tx(transaction, BlockId::Latest)
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
    transaction: &Transaction,
    global_tree: &mut GlobalStateTree,
    contract: DeployedContract,
) -> anyhow::Result<()> {
    // Add a new contract to global tree, the contract root is initialized to ZERO.
    let contract_root = ContractRoot(StarkHash::ZERO);
    let state_hash = calculate_contract_state_hash(contract.hash, contract_root);
    global_tree
        .set(contract.address, state_hash)
        .context("Adding deployed contract to global state tree")?;
    ContractsStateTable::insert(transaction, state_hash, contract.hash, contract_root)
        .context("Insert constract state hash into contracts state table")?;
    ContractsTable::insert(transaction, contract.address, contract.hash)
        .context("Inserting contract hash into contracts table")
}
