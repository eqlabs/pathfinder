use std::time::Duration;

use anyhow::Context;
use pedersen::{pedersen_hash, StarkHash};
use rusqlite::{Connection, Transaction};
use web3::{Transport, Web3};

use crate::{
    core::{
        ContractCode, ContractHash, ContractRoot, ContractStateHash, GlobalRoot,
        StarknetBlockTimestamp,
    },
    ethereum::{
        log::{FetchError, StateUpdateLog},
        state_update::{
            state_root::StateRootFetcher, ContractUpdate, DeployedContract,
            RetrieveStateUpdateError, StateUpdate,
        },
        BlockOrigin, EthOrigin, TransactionOrigin,
    },
    rpc::types::BlockNumberOrTag,
    sequencer,
    state::state_tree::{ContractsStateTree, GlobalStateTree},
    storage::{
        ContractsStateTable, ContractsTable, EthereumBlocksTable, EthereumTransactionsTable,
        GlobalStateRecord, GlobalStateTable,
    },
};

mod merkle_node;
mod merkle_tree;
mod state_tree;

#[derive(thiserror::Error, Debug)]
enum UpdateError {
    #[error("Ethereum chain reorg detected")]
    Reorg,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Syncs the Starknet state with L1.
pub async fn sync<T: Transport>(
    database: &mut Connection,
    transport: &Web3<T>,
    sequencer: &sequencer::Client,
) -> anyhow::Result<()> {
    // TODO: Track sync progress in some global way, so that RPC can check and react accordingly.
    //       This could either be the database, or a mutable lazy_static thingy.

    let mut previous_state = {
        // Temporary transaction with no side-effects, which will rollback when
        // droppped anyway. Required because our database API only accepts transactions.
        let db_tx = database
            .transaction()
            .context("Create database transaction")?;
        GlobalStateTable::get_latest_state(&db_tx).context("Get latest StarkNet state")?
    };

    let mut global_root = previous_state
        .as_ref()
        .map(|record| record.global_root)
        .unwrap_or(GlobalRoot(StarkHash::ZERO));

    let latest_state_log = previous_state.as_ref().map(|record| StateUpdateLog {
        origin: EthOrigin {
            block: BlockOrigin {
                hash: record.eth_block_hash,
                number: record.eth_block_number,
            },
            transaction: TransactionOrigin {
                hash: record.eth_tx_hash,
                index: record.eth_tx_index,
            },
            log_index: record.eth_log_index,
        },
        global_root: record.global_root,
        block_number: record.block_number,
    });

    let mut root_fetcher = StateRootFetcher::new(latest_state_log);

    loop {
        // Download the next set of updates logs from L1.
        let root_logs = match root_fetcher.fetch(transport).await {
            Ok(logs) if logs.is_empty() => return Ok(()),
            Ok(logs) => logs,
            Err(FetchError::Reorg) => todo!("Handle reorg event!"),
            Err(FetchError::Other(other)) => {
                return Err(other.context("Fetching new Starknet roots from L1"))
            }
        };

        for root_log in root_logs {
            // Perform each update as an atomic database unit.
            let db_transaction = database.transaction().with_context(|| {
                format!(
                    "Creating database transaction for block number {}",
                    root_log.block_number.0
                )
            })?;

            // Verify database state integretity i.e. latest state should be sequential,
            // and we are the only writer.
            let previous_state_db = GlobalStateTable::get_latest_state(&db_transaction)
                .with_context(|| {
                    format!(
                        "Get latest StarkNet state for block number {}",
                        root_log.block_number.0
                    )
                })?;
            anyhow::ensure!(
                previous_state_db == previous_state,
                "State mismatch between database and sync process for block number {}\n{:?}\n\n{:?}",
                root_log.block_number.0,
                previous_state,
                previous_state_db
            );

            previous_state = match update(
                transport,
                global_root,
                &root_log,
                &db_transaction,
                sequencer,
            )
            .await
            {
                Ok(state) => Some(state),
                Err(UpdateError::Reorg) => todo!("Handle reorg event!"),
                Err(UpdateError::Other(other)) => {
                    return Err(other).with_context(|| {
                        format!("Updating to block number {}", root_log.block_number.0)
                    });
                }
            };
            db_transaction.commit().with_context(|| {
                format!(
                    "Committing database transaction for block number {}",
                    root_log.block_number.0
                )
            })?;

            global_root = root_log.global_root;
        }
    }
}

/// Updates the Starknet state with a new block described by [StateUpdateLog].
///
/// Returns the new global root.
async fn update<T: Transport>(
    transport: &Web3<T>,
    global_root: GlobalRoot,
    update_log: &StateUpdateLog,
    db: &Transaction<'_>,
    sequencer: &sequencer::Client,
) -> Result<GlobalStateRecord, UpdateError> {
    // Download update from L1.
    use RetrieveStateUpdateError::*;
    let state_update = match StateUpdate::retrieve(transport, update_log.clone()).await {
        Ok(state_update) => state_update,
        Err(Other(other)) => {
            return Err(UpdateError::Other(anyhow::anyhow!(
                "Fetching state update failed. {}",
                other
            )));
        }
        // Treat the rest as a reorg event.
        Err(_reorg) => return Err(UpdateError::Reorg),
    };

    // Deploy contracts
    for contract in state_update.deployed_contracts {
        deploy_contract(contract, db, sequencer)
            .await
            .context("Contract deployment")?;
    }

    // Get the current contract root from global state. The global state stores
    // the contract state hash. We then lookup the mapping of state hash to contract root.
    let mut global_tree =
        GlobalStateTree::load(db, global_root).context("Loading global state tree")?;

    // Update contract state tree
    for contract_update in state_update.contract_updates {
        let contract_state_hash = update_contract_state(&contract_update, &global_tree, db)
            .await
            .context("Updating contract state")?;

        // Update the global state tree.
        global_tree
            .set(contract_update.address, contract_state_hash)
            .context("Updating global state tree")?;
    }

    // Apply all global tree changes.
    let new_global_root = global_tree
        .apply()
        .context("Applying global state tree updates")?;

    // Validate calculated root against the one received from L1.
    if new_global_root != update_log.global_root {
        return Err(UpdateError::Other(anyhow::anyhow!(
            "New global state root did not match L1."
        )));
    }

    // Download additional block information from sequencer. Use a custom timeout with retry strategy
    // to work-around the sequencer's poor performance (spurious lack of response) for early blocks.
    let block = loop {
        match sequencer
            .block_by_number_with_timeout(
                BlockNumberOrTag::Number(update_log.block_number),
                Duration::from_secs(3),
            )
            .await
        {
            Ok(block) => break block,
            Err(err) => {
                use sequencer::error::*;
                match err {
                    SequencerError::TransportError(terr) if terr.is_timeout() => continue,
                    other => {
                        let err = anyhow::anyhow!("{}", other)
                            .context("Downloading StarkNet block from sequencer");
                        return Err(UpdateError::Other(err));
                    }
                }
            }
        }
    };

    // Verify sequencer root against L1.
    let sequencer_root = block.state_root.context("Sequencer state root missing")?;

    if sequencer_root != update_log.global_root {
        return Err(UpdateError::Other(anyhow::anyhow!(
            "Sequencer state root did not match L1."
        )));
    }

    let block_hash = block.block_hash.context("Sequencer block hash missing")?;

    // Persist new global root et al to database.
    EthereumBlocksTable::insert(
        db,
        update_log.origin.block.hash,
        update_log.origin.block.number,
    )
    .context("Updating Ethereum blocks table")?;

    EthereumTransactionsTable::insert(
        db,
        update_log.origin.block.hash,
        update_log.origin.transaction.hash,
        update_log.origin.transaction.index,
    )
    .context("Updating Ethereum transactions table")?;

    GlobalStateTable::insert(
        db,
        update_log.block_number,
        block_hash,
        StarknetBlockTimestamp(block.timestamp),
        new_global_root,
        update_log.origin.transaction.hash,
        update_log.origin.log_index,
    )
    .context("Updating global state table")?;

    // TODO: Transactions and stuff. No idea how that works yet.

    Ok(GlobalStateRecord {
        block_number: update_log.block_number,
        block_hash,
        block_timestamp: StarknetBlockTimestamp(block.timestamp),
        global_root: new_global_root,
        eth_block_number: update_log.origin.block.number,
        eth_block_hash: update_log.origin.block.hash,
        eth_tx_hash: update_log.origin.transaction.hash,
        eth_tx_index: update_log.origin.transaction.index,
        eth_log_index: update_log.origin.log_index,
    })
}

/// Updates a contract's state with the given [storage updates](ContractUpdate). It returns the
/// [ContractStateHash] of the new state.
///
/// Specifically, it updates the [ContractsStateTree] and [ContractsStateTable].
async fn update_contract_state(
    update: &ContractUpdate,
    global_tree: &GlobalStateTree<'_>,
    db: &Transaction<'_>,
) -> anyhow::Result<ContractStateHash> {
    // Update the contract state tree.
    let contract_state_hash = global_tree
        .get(update.address)
        .context("Get contract state hash from global state tree")?;
    let contract_root = ContractsStateTable::get_root(db, contract_state_hash)
        .context("Read contract root from contracts state table")?
        .unwrap_or(ContractRoot(StarkHash::ZERO));

    // Load the contract tree and insert the updates.
    let mut contract_tree =
        ContractsStateTree::load(db, contract_root).context("Load contract state tree")?;
    for storage_update in &update.storage_updates {
        contract_tree
            .set(storage_update.address, storage_update.value)
            .context("Update contract storage tree")?;
    }
    let new_contract_root = contract_tree
        .apply()
        .context("Apply contract storage tree changes")?;

    // Calculate contract state hash, update global state tree and persist pre-image.
    let contract_hash = ContractsTable::get_hash(db, update.address)
        .context("Read contract hash from contracts table")?
        .context("Contract hash is missing from contracts table")?;
    let contract_state_hash = calculate_contract_state_hash(contract_hash, new_contract_root);

    ContractsStateTable::insert(db, contract_state_hash, contract_hash, new_contract_root)
        .context("Insert constract state hash into contracts state table")?;

    Ok(contract_state_hash)
}

/// Inserts a newly deployed Starknet contract into [ContractsTable].
async fn deploy_contract(
    contract: DeployedContract,
    db: &Transaction<'_>,
    sequencer: &sequencer::Client,
) -> anyhow::Result<()> {
    // Download code and ABI from the sequencer.
    let definition = sequencer
        .contract_definition(contract.address)
        .await
        .context("Download contract code and ABI from sequencer")?;
    let code = ContractCode {
        abi: definition.abi,
        bytecode: definition.bytecode,
    };

    // TODO: verify contract hash (waiting on contract definition API change).

    // TODO: This is not available from sequencer yet.
    let definition = "does not exist".as_bytes();

    ContractsTable::insert(db, contract.address, contract.hash, code, definition)
        .context("Inserting contract information into contracts table")?;
    Ok(())
}

/// Calculates the contract state hash from its preimage.
fn calculate_contract_state_hash(hash: ContractHash, root: ContractRoot) -> ContractStateHash {
    const RESERVED: StarkHash = StarkHash::ZERO;
    const CONTRACT_VERSION: StarkHash = StarkHash::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), RESERVED), CONTRACT_VERSION)
    let hash = pedersen_hash(hash.0, root.0);
    let hash = pedersen_hash(hash, RESERVED);
    let hash = pedersen_hash(hash, CONTRACT_VERSION);
    ContractStateHash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
            EthereumTransactionIndex, StarknetBlockHash, StarknetBlockNumber,
        },
        ethereum::test::create_test_transport,
    };
    use std::str::FromStr;
    use web3::types::H256;

    #[test]
    fn hash() {
        let root = StarkHash::from_hex_str(
            "04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028",
        )
        .unwrap();
        let root = ContractRoot(root);

        let hash = StarkHash::from_hex_str(
            "02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779",
        )
        .unwrap();
        let hash = ContractHash(hash);

        let expected = StarkHash::from_hex_str(
            "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3",
        )
        .unwrap();
        let expected = ContractStateHash(expected);

        let result = calculate_contract_state_hash(hash, root);

        assert_eq!(result, expected);
    }

    #[tokio::test]
    #[ignore = "Sequencer currently gives 502/503"]
    async fn genesis() {
        // Georli genesis block values from Alpha taken from Voyager block explorer.
        // https://goerli.voyager.online/block/0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b

        let starknet_block_hash = StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b",
            )
            .unwrap(),
        );

        let genesis = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: EthereumBlockHash(
                        H256::from_str(
                            "a3c7bb4baa81bb8bc5cc75ace7d8296b2668ccc2fd5ac9d22b5eefcfbf7f3444",
                        )
                        .unwrap(),
                    ),
                    number: EthereumBlockNumber(5854324),
                },
                transaction: TransactionOrigin {
                    hash: EthereumTransactionHash(
                        H256::from_str(
                            "97ee44ba80d1ad5cff4a5adc02311f6e19490f48ea5a57c7f510e469cae7e65b",
                        )
                        .unwrap(),
                    ),
                    index: EthereumTransactionIndex(4),
                },
                log_index: EthereumLogIndex(23),
            },
            global_root: GlobalRoot(
                StarkHash::from_hex_str(
                    "02c2bb91714f8448ed814bdac274ab6fcdbafc22d835f9e847e5bee8c2e5444e",
                )
                .unwrap(),
            ),
            block_number: StarknetBlockNumber(0),
        };

        let sequencer = sequencer::Client::goerli().unwrap();

        let storage = crate::storage::Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let transport = create_test_transport(crate::ethereum::Chain::Goerli).await;

        update(
            &transport,
            GlobalRoot(StarkHash::ZERO),
            &genesis,
            &transaction,
            &sequencer,
        )
        .await
        .unwrap();

        // Read the new latest state from database.
        let state = GlobalStateTable::get_latest_state(&transaction)
            .unwrap()
            .unwrap();

        assert_eq!(state.block_hash, starknet_block_hash);
        assert_eq!(state.global_root, genesis.global_root);
        assert_eq!(state.block_number, genesis.block_number);
        assert_eq!(state.eth_block_hash, genesis.origin.block.hash);
        assert_eq!(state.eth_block_number, genesis.origin.block.number);
        assert_eq!(state.eth_tx_hash, genesis.origin.transaction.hash);
        assert_eq!(state.eth_tx_index, genesis.origin.transaction.index);
        assert_eq!(state.eth_log_index, genesis.origin.log_index);
    }
}
