use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::{mpsc, oneshot};

use crate::core::{ClassHash, StarknetBlockHash, StarknetBlockNumber};
use crate::ethereum::state_update::{ContractUpdate, DeployedContract, StateUpdate, StorageUpdate};
use crate::sequencer::error::SequencerError;
use crate::sequencer::reply::state_update::{Contract, StateDiff};
use crate::sequencer::reply::Block;
use crate::sequencer::{self};
use crate::state::block_hash::{verify_block_hash, VerifyResult};
use crate::state::class_hash::extract_abi_code_hash;
use crate::state::CompressedContract;

#[derive(Debug, Clone, Copy)]
pub struct Timings {
    pub block_download: Duration,
    pub state_diff_download: Duration,
    pub contract_deployment: Duration,
}

/// Events and queries emitted by L2 sync process.
#[derive(Debug)]
pub enum Event {
    /// New L2 [block update](StateUpdate) found.
    Update(Box<Block>, StateUpdate, Timings),
    /// An L2 reorg was detected, contains the reorg-tail which
    /// indicates the oldest block which is now invalid
    /// i.e. reorg-tail + 1 should be the new head.
    Reorg(StarknetBlockNumber),
    /// A new unique L2 [contract](CompressedContract) was found.
    NewContract(CompressedContract),
    /// Query for the [block hash](StarknetBlockHash) of the given block.
    ///
    /// The receiver should return the [block hash](StarknetBlockHash) using the
    /// [oneshot::channel].
    QueryHash(
        StarknetBlockNumber,
        oneshot::Sender<Option<StarknetBlockHash>>,
    ),
    /// Query for the existance of the the given [contracts](ClassHash) in storage.
    ///
    /// The receiver should return true (if the contract exists) or false (if it does not exist)
    /// for each contract using the [oneshot::channel].
    QueryContractExistance(Vec<ClassHash>, oneshot::Sender<Vec<bool>>),
}

pub async fn sync(
    tx_event: mpsc::Sender<Event>,
    sequencer: impl sequencer::ClientApi,
    mut head: Option<(StarknetBlockNumber, StarknetBlockHash)>,
    chain: crate::ethereum::Chain,
) -> anyhow::Result<()> {
    use crate::state::sync::head_poll_interval;

    'outer: loop {
        // Get the next block from L2.
        let (next, head_hash) = match head {
            Some((number, hash)) => (number + 1, Some(hash)),
            None => (StarknetBlockNumber::GENESIS, None),
        };

        let t_block = std::time::Instant::now();
        let block = loop {
            match download_block(next, chain, head_hash, &sequencer).await? {
                DownloadBlock::Block(block) => break block,
                DownloadBlock::AtHead => {
                    let poll_interval = head_poll_interval(chain);
                    tracing::info!(poll_interval=?poll_interval, "At head of chain");
                    tokio::time::sleep(poll_interval).await;
                }
                DownloadBlock::Reorg => {
                    let some_head = head.unwrap();
                    head = reorg(some_head, chain, &tx_event, &sequencer)
                        .await
                        .context("L2 reorg")?;

                    continue 'outer;
                }
            }
        };
        let t_block = t_block.elapsed();

        if let Some(some_head) = head {
            if some_head.1 != block.parent_block_hash {
                head = reorg(some_head, chain, &tx_event, &sequencer)
                    .await
                    .context("L2 reorg")?;

                continue 'outer;
            }
        }

        // Unwrap in both block and state update is safe as the block hash always exists (unless we query for pending).
        let block_hash = block.block_hash.unwrap();
        let t_update = std::time::Instant::now();
        let state_update = sequencer
            .state_update(block_hash.into())
            .await
            .with_context(|| format!("Fetch state diff for block {:?} from sequencer", next))?;
        let state_update_block_hash = state_update.block_hash.unwrap();
        // An extra sanity check for the state update API.
        anyhow::ensure!(
            block_hash == state_update_block_hash,
            "State update block hash mismatch, actual {:x}, expected {:x}",
            block_hash.0,
            state_update_block_hash.0
        );
        let t_update = t_update.elapsed();

        let t_deploy = std::time::Instant::now();
        deploy_contracts(&tx_event, &sequencer, &state_update.state_diff)
            .await
            .with_context(|| format!("Deploying new contracts for block {:?}", next))?;
        let t_deploy = t_deploy.elapsed();

        // Map from sequencer type to the actual type... we should declutter these types.
        let deployed_contracts = state_update
            .state_diff
            .deployed_contracts
            .into_iter()
            .map(|contract| DeployedContract {
                address: contract.address,
                hash: contract.contract_hash,
                call_data: vec![], // todo!("This is missing from sequencer API..."),
            })
            .collect::<Vec<_>>();

        let contract_updates = state_update
            .state_diff
            .storage_diffs
            .into_iter()
            .map(|contract_update| {
                let storage_updates = contract_update
                    .1
                    .into_iter()
                    .map(|diff| StorageUpdate {
                        address: diff.key,
                        value: diff.value,
                    })
                    .collect();

                ContractUpdate {
                    address: contract_update.0,
                    storage_updates,
                }
            })
            .collect::<Vec<_>>();

        let update = StateUpdate {
            deployed_contracts,
            contract_updates,
        };

        head = Some((next, block_hash));

        let timings = Timings {
            block_download: t_block,
            state_diff_download: t_update,
            contract_deployment: t_deploy,
        };

        tx_event
            .send(Event::Update(block, update, timings))
            .await
            .context("Event channel closed")?;
    }
}

enum DownloadBlock {
    Block(Box<Block>),
    AtHead,
    Reorg,
}

async fn download_block(
    block_number: StarknetBlockNumber,
    chain: crate::ethereum::Chain,
    prev_block_hash: Option<StarknetBlockHash>,
    sequencer: &impl sequencer::ClientApi,
) -> anyhow::Result<DownloadBlock> {
    use crate::core::BlockId;
    use sequencer::error::StarknetErrorCode::BlockNotFound;

    let result = sequencer.block(block_number.into()).await;

    match result {
        Ok(block) => {
            // Check if block hash is correct.
            let expected_block_hash = block.block_hash.unwrap();
            if verify_block_hash(&block, chain, expected_block_hash)? == VerifyResult::Mismatch {
                let block_number = block.block_number.unwrap();
                tracing::warn!(?block_number, block_hash = ?expected_block_hash, "Block hash mismatch");
            }
            Ok(DownloadBlock::Block(Box::new(block)))
        }
        Err(SequencerError::StarknetError(err)) if err.code == BlockNotFound => {
            // This would occur if we queried past the head of the chain. We now need to check that
            // a reorg hasn't put us too far in the future. This does run into race conditions with
            // the sequencer but this is the best we can do I think.
            let latest = sequencer
                .block(BlockId::Latest)
                .await
                .context("Query sequencer for latest block")?;

            if latest.block_number.unwrap() + 1 == block_number {
                match prev_block_hash {
                    // We are definitely still at the head and it's just that a new block
                    // has not been published yet
                    Some(parent_block_hash) if parent_block_hash == latest.block_hash.unwrap() => {
                        Ok(DownloadBlock::AtHead)
                    }
                    // Our head is not valid anymore so there must have been a reorg only at this height
                    Some(_) => Ok(DownloadBlock::Reorg),
                    // There is something wrong with the sequencer, as we are attempting to get the genesis block
                    // Let's retry in a while
                    None => Ok(DownloadBlock::AtHead),
                }
            } else {
                // The new head is at lower height than our head which means there must have been a reorg
                Ok(DownloadBlock::Reorg)
            }
        }
        Err(other) => Err(other).context("Download block from sequencer"),
    }
}

async fn reorg(
    head: (StarknetBlockNumber, StarknetBlockHash),
    chain: crate::ethereum::Chain,
    tx_event: &mpsc::Sender<Event>,
    sequencer: &impl sequencer::ClientApi,
) -> anyhow::Result<Option<(StarknetBlockNumber, StarknetBlockHash)>> {
    // Go back in history until we find an L2 block that does still exist.
    // We already know the current head is invalid.
    let mut reorg_tail = head;

    let new_head = loop {
        if reorg_tail.0 == StarknetBlockNumber::GENESIS {
            break None;
        }

        let previous_block_number = reorg_tail.0 - 1;

        let (tx, rx) = oneshot::channel();
        tx_event
            .send(Event::QueryHash(previous_block_number, tx))
            .await
            .context("Event channel closed")?;

        let previous_hash = match rx.await.context("Oneshot channel closed")? {
            Some(hash) => hash,
            None => break None,
        };

        match download_block(previous_block_number, chain, Some(previous_hash), sequencer)
            .await
            .with_context(|| format!("Download block {} from sequencer", previous_block_number.0))?
        {
            // Unwrap is safe bacause this is not a `pending` block
            DownloadBlock::Block(block) if block.block_hash.unwrap() == previous_hash => {
                break Some((previous_block_number, previous_hash));
            }
            _ => {}
        };

        reorg_tail = (previous_block_number, previous_hash);
    };

    let reorg_tail = new_head
        .map(|x| x.0 + 1)
        .unwrap_or(StarknetBlockNumber::GENESIS);

    tx_event
        .send(Event::Reorg(reorg_tail))
        .await
        .context("Event channel closed")?;

    Ok(new_head)
}

async fn deploy_contracts(
    tx_event: &mpsc::Sender<Event>,
    sequencer: &impl sequencer::ClientApi,
    state_diff: &StateDiff,
) -> anyhow::Result<()> {
    let unique_contracts = state_diff
        .deployed_contracts
        .iter()
        .map(|contract| contract.contract_hash)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if unique_contracts.is_empty() {
        return Ok(());
    }

    // Query database to see which of these contracts still needs downloading.
    let (tx, rx) = oneshot::channel();
    tx_event
        .send(Event::QueryContractExistance(unique_contracts.clone(), tx))
        .await
        .context("Event channel closed")?;
    let already_downloaded = rx.await.context("Oneshot channel closed")?;
    anyhow::ensure!(
        already_downloaded.len() == unique_contracts.len(),
        "Query for existance of contracts in storage returned {} values instead of the expected {}",
        already_downloaded.len(),
        unique_contracts.len()
    );

    let require_downloading = unique_contracts
        .into_iter()
        .zip(already_downloaded.into_iter())
        .filter_map(|(contract, exists)| match exists {
            false => Some(contract),
            true => None,
        })
        .collect::<Vec<_>>();

    // Download each contract and push it to storage.
    for contract_hash in require_downloading {
        // Find the relevant contract address.
        let contract = state_diff
            .deployed_contracts
            .iter()
            .find(|contract| contract.contract_hash == contract_hash)
            .unwrap();

        let contract = download_and_compress_contract(contract, sequencer)
            .await
            .with_context(|| format!("Download and compress contract {:?}", contract.address))?;

        tx_event
            .send(Event::NewContract(contract))
            .await
            .context("Event channel closed")?;
    }

    Ok(())
}

async fn download_and_compress_contract(
    contract: &Contract,
    sequencer: &impl sequencer::ClientApi,
) -> anyhow::Result<CompressedContract> {
    let contract_definition = sequencer
        .full_contract(contract.address)
        .await
        .context("Download contract from sequencer")?;

    // Parse the contract definition for ABI, code and calculate the class hash. This can
    // be expensive, so perform in a blocking task.
    let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let (abi, bytecode, hash) = extract_abi_code_hash(&contract_definition)?;
        Ok((contract_definition, abi, bytecode, hash))
    });
    let (contract_definition, abi, bytecode, hash) = extract
        .await
        .context("Parse contract definition and compute hash")??;

    // Sanity check.
    anyhow::ensure!(
        contract.contract_hash == hash,
        "Class hash mismatch for contract {:?}",
        contract.address
    );

    let compress = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

        let abi = compressor.compress(&abi).context("Compress ABI")?;
        let bytecode = compressor
            .compress(&bytecode)
            .context("Compress bytecode")?;
        let definition = compressor
            .compress(&*contract_definition)
            .context("Compress definition")?;

        Ok((abi, bytecode, definition))
    });
    let (abi, bytecode, definition) = compress.await.context("Compress contract")??;

    Ok(CompressedContract {
        abi,
        bytecode,
        definition,
        hash,
    })
}

#[cfg(test)]
mod tests {
    mod sync {
        use super::super::{sync, Event};
        use crate::{
            core::{
                BlockId, ClassHash, ContractAddress, GasPrice, GlobalRoot, SequencerAddress,
                StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StorageAddress,
                StorageValue,
            },
            ethereum::state_update,
            sequencer::{
                error::{SequencerError, StarknetError, StarknetErrorCode},
                reply, MockClientApi,
            },
            state,
        };
        use assert_matches::assert_matches;
        use stark_hash::StarkHash;
        use std::collections::HashMap;

        const DEF0: &str = r#"{
            "abi": [],
            "program": {
                "attributes": [],
                "builtins": [],
                "data": [],
                "hints": {},
                "identifiers": {},
                "main_scope": "contract definition "#;
        const DEF1: &str = r#"",
                "prime": "",
                "reference_manager": ""
            },
            "entry_points_by_type": {}
        }"#;

        const BLOCK0_NUMBER: StarknetBlockNumber = StarknetBlockNumber::GENESIS;
        const BLOCK1_NUMBER: StarknetBlockNumber = StarknetBlockNumber(1);
        const BLOCK2_NUMBER: StarknetBlockNumber = StarknetBlockNumber(2);
        const BLOCK3_NUMBER: StarknetBlockNumber = StarknetBlockNumber(3);
        const BLOCK4_NUMBER: StarknetBlockNumber = StarknetBlockNumber(4);

        lazy_static::lazy_static! {
            static ref BLOCK0_HASH: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 0 hash").unwrap());
            static ref BLOCK0_HASH_V2: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 0 hash v2").unwrap());
            static ref BLOCK1_HASH: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 1 hash").unwrap());
            static ref BLOCK1_HASH_V2: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 1 hash v2").unwrap());
            static ref BLOCK2_HASH: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 2 hash").unwrap());
            static ref BLOCK2_HASH_V2: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 2 hash v2").unwrap());
            static ref BLOCK3_HASH: StarknetBlockHash = StarknetBlockHash(StarkHash::from_be_slice(b"block 3 hash").unwrap());

            static ref GLOBAL_ROOT0: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 0").unwrap());
            static ref GLOBAL_ROOT0_V2: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 0 v2").unwrap());
            static ref GLOBAL_ROOT1: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 1").unwrap());
            static ref GLOBAL_ROOT1_V2: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 1 v2").unwrap());
            static ref GLOBAL_ROOT2: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 2").unwrap());
            static ref GLOBAL_ROOT2_V2: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 2 v2").unwrap());
            static ref GLOBAL_ROOT3: GlobalRoot = GlobalRoot(StarkHash::from_be_slice(b"global root 3").unwrap());

            static ref CONTRACT0_ADDR: ContractAddress = ContractAddress(StarkHash::from_be_slice(b"contract 0 addr").unwrap());
            static ref CONTRACT0_ADDR_V2: ContractAddress = ContractAddress(StarkHash::from_be_slice(b"contract 0 addr v2").unwrap());
            static ref CONTRACT1_ADDR: ContractAddress = ContractAddress(StarkHash::from_be_slice(b"contract 1 addr").unwrap());

            static ref CONTRACT0_HASH: ClassHash = ClassHash(
                StarkHash::from_hex_str(
                    "0x03CC4D0167577958ADD7DD759418506E0930BB061597519CCEB8C3AC6277692E",
                )
                .unwrap(),
            );
            static ref CONTRACT0_HASH_V2: ClassHash = ClassHash(
                StarkHash::from_hex_str(
                    "0x01BE539E97D3BEFAE5D56D780BAF433802B3203DC6B2947FDB90C384AEF39F3E",
                )
                .unwrap(),
            );
            static ref CONTRACT1_HASH: ClassHash = ClassHash(
                StarkHash::from_hex_str(
                    "0x071B088C5C8CD884F3106D62C6CB8B423D1D3A58BFAD2EAA8AAC9E4E3E73529D",
                )
                .unwrap(),
            );

            static ref CONTRACT0_DEF: bytes::Bytes = bytes::Bytes::from(format!("{}0{}", DEF0, DEF1));
            static ref CONTRACT0_DEF_V2: bytes::Bytes = bytes::Bytes::from(format!("{}0 v2{}", DEF0, DEF1));
            static ref CONTRACT1_DEF: bytes::Bytes = bytes::Bytes::from(format!("{}1{}", DEF0, DEF1));

            static ref STORAGE_KEY0: StorageAddress = StorageAddress(StarkHash::from_be_slice(b"contract 0 storage addr 0").unwrap());
            static ref STORAGE_KEY1: StorageAddress = StorageAddress(StarkHash::from_be_slice(b"contract 1 storage addr 0").unwrap());

            static ref STORAGE_VAL0: StorageValue = StorageValue(StarkHash::from_be_slice(b"contract 0 storage val 0").unwrap());
            static ref STORAGE_VAL0_V2: StorageValue = StorageValue(StarkHash::from_be_slice(b"contract 0 storage val 0 v2").unwrap());
            static ref STORAGE_VAL1: StorageValue = StorageValue(StarkHash::from_be_slice(b"contract 1 storage val 0").unwrap());

            static ref BLOCK0: reply::Block = reply::Block {
                block_hash: Some(*BLOCK0_HASH),
                block_number: Some(BLOCK0_NUMBER),
                gas_price: Some(GasPrice::ZERO),
                parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
                sequencer_address: Some(SequencerAddress(StarkHash::ZERO)),
                state_root: Some(*GLOBAL_ROOT0),
                status: reply::Status::AcceptedOnL1,
                timestamp: StarknetBlockTimestamp(0),
                transaction_receipts: vec![],
                transactions: vec![],
            };
            static ref BLOCK0_V2: reply::Block = reply::Block {
                block_hash: Some(*BLOCK0_HASH_V2),
                block_number: Some(BLOCK0_NUMBER),
                gas_price: Some(GasPrice::from_be_slice(b"gas price 0 v2").unwrap()),
                parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
                sequencer_address: Some(SequencerAddress(StarkHash::from_be_slice(b"sequencer addr. 0 v2").unwrap())),
                state_root: Some(*GLOBAL_ROOT0_V2),
                status: reply::Status::AcceptedOnL2,
                timestamp: StarknetBlockTimestamp(10),
                transaction_receipts: vec![],
                transactions: vec![],
            };
            static ref BLOCK1: reply::Block = reply::Block {
                block_hash: Some(*BLOCK1_HASH),
                block_number: Some(BLOCK1_NUMBER),
                gas_price: Some(GasPrice::from(1)),
                parent_block_hash: *BLOCK0_HASH,
                sequencer_address: Some(SequencerAddress(StarkHash::from_be_slice(b"sequencer address 1").unwrap())),
                state_root: Some(*GLOBAL_ROOT1),
                status: reply::Status::AcceptedOnL1,
                timestamp: StarknetBlockTimestamp(1),
                transaction_receipts: vec![],
                transactions: vec![],
            };
            static ref BLOCK2: reply::Block = reply::Block {
                block_hash: Some(*BLOCK2_HASH),
                block_number: Some(BLOCK2_NUMBER),
                gas_price: Some(GasPrice::from(2)),
                parent_block_hash: *BLOCK1_HASH,
                sequencer_address: Some(SequencerAddress(StarkHash::from_be_slice(b"sequencer address 2").unwrap())),
                state_root: Some(*GLOBAL_ROOT2),
                status: reply::Status::AcceptedOnL1,
                timestamp: StarknetBlockTimestamp(2),
                transaction_receipts: vec![],
                transactions: vec![],
            };

            static ref STATE_UPDATE0: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK0_HASH),
                new_root: *GLOBAL_ROOT0,
                old_root: GlobalRoot(StarkHash::ZERO),
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![reply::state_update::Contract {
                        address: *CONTRACT0_ADDR,
                        contract_hash: *CONTRACT0_HASH,
                    }],
                    storage_diffs: HashMap::from([(
                     *CONTRACT0_ADDR,
                        vec![reply::state_update::StorageDiff {
                            key: *STORAGE_KEY0,
                            value: *STORAGE_VAL0,
                        }],
                    )]),
                },
            };
            static ref STATE_UPDATE0_V2: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK0_HASH_V2),
                new_root: *GLOBAL_ROOT0_V2,
                old_root: GlobalRoot(StarkHash::ZERO),
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![reply::state_update::Contract {
                        address: *CONTRACT0_ADDR_V2,
                        contract_hash: *CONTRACT0_HASH_V2,
                    }],
                    storage_diffs: HashMap::new(),
                },
            };
            static ref STATE_UPDATE1: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK1_HASH),
                new_root: *GLOBAL_ROOT1,
                old_root: *GLOBAL_ROOT0,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![reply::state_update::Contract {
                        address: *CONTRACT1_ADDR,
                        contract_hash: *CONTRACT1_HASH,
                    }],
                    storage_diffs: HashMap::from([
                        (
                            *CONTRACT0_ADDR,
                            vec![reply::state_update::StorageDiff {
                                key: *STORAGE_KEY0,
                                value: *STORAGE_VAL0_V2,
                            }],
                        ),
                        (
                            *CONTRACT1_ADDR,
                            vec![reply::state_update::StorageDiff {
                                key: *STORAGE_KEY1,
                                value: *STORAGE_VAL1,
                            }],
                        ),
                    ]),
                },
            };
            static ref STATE_UPDATE1_V2: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK1_HASH_V2),
                new_root: *GLOBAL_ROOT1_V2,
                old_root: *GLOBAL_ROOT0_V2,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![],
                    storage_diffs: HashMap::new(),
                },
            };
            static ref STATE_UPDATE2: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK2_HASH),
                new_root: *GLOBAL_ROOT2,
                old_root: *GLOBAL_ROOT1,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![],
                    storage_diffs: HashMap::new(),
                },
            };
            static ref STATE_UPDATE2_V2: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK2_HASH_V2),
                new_root: *GLOBAL_ROOT2_V2,
                old_root: *GLOBAL_ROOT1_V2,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![],
                    storage_diffs: HashMap::new(),
                },
            };
            static ref STATE_UPDATE3: reply::StateUpdate = reply::StateUpdate {
                block_hash: Some(*BLOCK3_HASH),
                new_root: *GLOBAL_ROOT3,
                old_root: *GLOBAL_ROOT2,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![],
                    storage_diffs: HashMap::new(),
                },
            };

            static ref EXPECTED_STATE_UPDATE0: state_update::StateUpdate = state_update::StateUpdate {
                contract_updates: vec![state_update::ContractUpdate {
                    address: *CONTRACT0_ADDR,
                    storage_updates: vec![
                        state_update::StorageUpdate {
                            address: *STORAGE_KEY0,
                            value: *STORAGE_VAL0,
                        }
                    ]
                }],
                deployed_contracts: vec![
                    state::sync::DeployedContract {
                        address: *CONTRACT0_ADDR,
                        hash: *CONTRACT0_HASH,
                        call_data: vec![],
                }],
            };
            static ref EXPECTED_STATE_UPDATE1: state_update::StateUpdate = state_update::StateUpdate {
                contract_updates: vec![
                    state_update::ContractUpdate {
                        address: *CONTRACT0_ADDR,
                        storage_updates: vec![
                            state_update::StorageUpdate {
                                address: *STORAGE_KEY0,
                                value: *STORAGE_VAL0_V2,
                            }
                        ]
                    },
                    state_update::ContractUpdate {
                        address: *CONTRACT1_ADDR,
                        storage_updates: vec![
                            state_update::StorageUpdate {
                                address: *STORAGE_KEY1,
                                value: *STORAGE_VAL1,
                            }
                        ]
                    }
                ],
                deployed_contracts: vec![
                    state::sync::DeployedContract {
                        address: *CONTRACT1_ADDR,
                        hash: *CONTRACT1_HASH,
                        call_data: vec![],
                }],
            };
        }

        /// Convenience wrapper
        fn expect_block(
            mock: &mut MockClientApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<reply::Block, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_block()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(move |_| returned_result);
        }

        /// Convenience wrapper
        fn expect_state_update(
            mock: &mut MockClientApi,
            seq: &mut mockall::Sequence,
            block: BlockId,
            returned_result: Result<reply::StateUpdate, SequencerError>,
        ) {
            use mockall::predicate::eq;

            mock.expect_state_update()
                .with(eq(block))
                .times(1)
                .in_sequence(seq)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn expect_full_contract(
            mock: &mut MockClientApi,
            seq: &mut mockall::Sequence,
            contract_address: ContractAddress,
            returned_result: Result<bytes::Bytes, SequencerError>,
        ) {
            mock.expect_full_contract()
                .withf(move |x| x == &contract_address)
                .times(1)
                .in_sequence(seq)
                .return_once(|_| returned_result);
        }

        /// Convenience wrapper
        fn block_not_found() -> SequencerError {
            SequencerError::StarknetError(StarknetError {
                code: StarknetErrorCode::BlockNotFound,
                message: String::new(),
            })
        }

        mod happy_path {
            use super::*;
            use crate::ethereum::Chain;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            async fn from_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                // Downlad the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );
                // Downlad block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );
                // Stay at head, no more blocks available
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(BLOCK1.clone()));

                // Let's run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Contract 0 definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block,state_update,_) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Contract 1 definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block,mut state_update,_) => {
                    assert_eq!(*block, *BLOCK1);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
            }

            #[tokio::test]
            async fn resumed_after_genesis() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                // Start with downloading block #1
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );

                // Stay at head, no more blocks available
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(BLOCK1.clone()));

                // Let's run the UUT
                let _jh = tokio::spawn(sync(
                    tx_event,
                    mock,
                    Some((BLOCK0_NUMBER, *BLOCK0_HASH)),
                    Chain::Goerli,
                ));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Contract 1 definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block,mut state_update,_) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT1_ADDR,
                            hash: *CONTRACT1_HASH,
                            call_data: vec![],
                    }]);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
            }
        }

        mod reorg {
            use super::*;
            use crate::ethereum::Chain;
            use pretty_assertions::assert_eq;

            #[tokio::test]
            // This reorg occurs at the genesis block, which is swapped for a new one.
            //
            // [block 0]
            //
            // Becomes:
            //
            // [block 0 v2]
            //
            async fn at_genesis_which_is_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );

                // Block #1 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occured
                // We indicate that reorg started at genesis
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(BLOCK0_V2.clone()));

                // Finally the L2 sync task is downloading the new genesis block
                // from the fork with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH_V2).into(),
                    Ok(STATE_UPDATE0_V2.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Err(block_not_found()),
                );

                // Indicate that we are still staying at the head - the latest block matches our head
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(BLOCK0_V2.clone()));

                // Let's run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                // Reorg started from the genesis block
                assert_matches!(rx_event.recv().await.unwrap(), Event::Reorg(tail) => {
                    assert_eq!(tail, BLOCK0_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH_V2]);
                    // Indicate that contract 0 v2 definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT0_ADDR_V2,
                            hash: *CONTRACT0_HASH_V2,
                            call_data: vec![],
                    }]);
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            // This reorg occurs at the genesis block, which means that the fork replaces the entire chain.
            //
            // [block 0]-------[block 1]-------[block 2]
            //
            // Becomes:
            //
            // [block 0 v2]----[block 1 v2]
            //
            async fn at_genesis_which_is_not_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: Some(*BLOCK1_HASH_V2),
                    block_number: Some(BLOCK1_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
                    parent_block_hash: *BLOCK0_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT1_V2),
                    status: reply::Status::AcceptedOnL2,
                    timestamp: StarknetBlockTimestamp(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH).into(),
                    Ok(STATE_UPDATE2.clone()),
                );

                // Block #3 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occured
                // We indicate that reorg started at genesis by setting the latest on the new genesis block
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(BLOCK0_V2.clone()));
                // Then the L2 sync task goes back block by block to find the last block where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone()),
                );

                // Once the L2 sync task has found where reorg occured,
                // it can get back to downloading the new blocks
                // Fetch the new genesis block from the fork with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0_V2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH_V2).into(),
                    Ok(STATE_UPDATE0_V2.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR_V2,
                    Ok(CONTRACT0_DEF_V2.clone()),
                );
                // Fetch the new block #1 from the fork with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH_V2).into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );

                // Indicate that we are still staying at the head
                // No new blocks found and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block1_v2.clone()));

                // Run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, mut state_update, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT1_ADDR,
                            hash: *CONTRACT1_HASH,
                            call_data: vec![],
                    }]);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK1_NUMBER);
                    sender.send(Some(*BLOCK1_HASH)).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK0_NUMBER);
                    sender.send(Some(*BLOCK0_HASH)).unwrap();
                });
                // Reorg started at the genesis block
                assert_matches!(rx_event.recv().await.unwrap(), Event::Reorg(tail) => {
                    assert_eq!(tail, BLOCK0_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH_V2]);
                    // Indicate that contract 0 v2 definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH_V2);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0_V2);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT0_ADDR_V2,
                            hash: *CONTRACT0_HASH_V2,
                            call_data: vec![],
                    }]);
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block1_v2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            // This reorg occurs after the genesis block, the fork
            // replaces the entire chain except the genesis block.
            //
            // [block 0]----[block 1]-------[block 2]-------[block 3]
            //
            // Becomes:
            //
            // [block 0]----[block 1 v2]----[block 2 v2]
            //
            async fn after_genesis_and_not_at_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: Some(*BLOCK1_HASH_V2),
                    block_number: Some(BLOCK1_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
                    parent_block_hash: *BLOCK0_HASH,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT1_V2),
                    status: reply::Status::AcceptedOnL2,
                    timestamp: StarknetBlockTimestamp(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };
                let block2_v2 = reply::Block {
                    block_hash: Some(*BLOCK2_HASH_V2),
                    block_number: Some(BLOCK2_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2 v2").unwrap()),
                    parent_block_hash: *BLOCK1_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer addr. 2 v2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT2_V2),
                    status: reply::Status::AcceptedOnL2,
                    timestamp: StarknetBlockTimestamp(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };
                let block3 = reply::Block {
                    block_hash: Some(*BLOCK3_HASH),
                    block_number: Some(BLOCK3_NUMBER),
                    gas_price: Some(GasPrice::from(3)),
                    parent_block_hash: *BLOCK2_HASH,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer address 3").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT3),
                    status: reply::Status::AcceptedOnL1,
                    timestamp: StarknetBlockTimestamp(3),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH).into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                // Fetch block #3 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Ok(block3.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK3_HASH).into(),
                    Ok(STATE_UPDATE3.clone()),
                );
                // Block #4 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK4_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occured
                // We indicate that reorg started at block #1
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block1_v2.clone()));

                // L2 sync task goes back block by block to find where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone()),
                );
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #1 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH_V2).into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );
                // Fetch the new block #2 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH_V2).into(),
                    Ok(STATE_UPDATE2_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block2_v2.clone()));

                // Run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, mut state_update, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT1_ADDR,
                            hash: *CONTRACT1_HASH,
                            call_data: vec![],
                    }]);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block3);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK2_NUMBER);
                    sender.send(Some(*BLOCK2_HASH)).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK1_NUMBER);
                    sender.send(Some(*BLOCK1_HASH)).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK0_NUMBER);
                    sender.send(Some(*BLOCK0_HASH)).unwrap();
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), Event::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block1_v2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block2_v2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            // This reorg occurs after the genesis block, the fork
            // replaces only the head block.
            //
            // [block 0]----[block 1]----[block 2]
            //
            // Becomes:
            //
            // [block 0]----[block 1]----[block 2 v2]
            //
            async fn after_genesis_and_at_head() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                let block2_v2 = reply::Block {
                    block_hash: Some(*BLOCK2_HASH_V2),
                    block_number: Some(BLOCK2_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2 v2").unwrap()),
                    parent_block_hash: *BLOCK1_HASH,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer addr. 2 v2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT2_V2),
                    status: reply::Status::AcceptedOnL2,
                    timestamp: StarknetBlockTimestamp(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );
                // Fetch block #2 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(BLOCK2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH).into(),
                    Ok(STATE_UPDATE2.clone()),
                );
                // Block #3 is not there
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );

                // L2 sync task is then looking if reorg occured
                // We indicate that reorg started at block #2
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block2_v2.clone()));

                // L2 sync task goes back block by block to find where the block hash matches the DB
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #2 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2_v2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH_V2).into(),
                    Ok(STATE_UPDATE2_V2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block2_v2.clone()));

                // Run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, mut state_update, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT1_ADDR,
                            hash: *CONTRACT1_HASH,
                            call_data: vec![],
                    }]);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK1_NUMBER);
                    sender.send(Some(*BLOCK1_HASH)).unwrap();
                });
                // Reorg started from block #2
                assert_matches!(rx_event.recv().await.unwrap(), Event::Reorg(tail) => {
                    assert_eq!(tail, BLOCK2_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block2_v2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            // This reorg occurs because the downloaded block at head turns out to indicate
            // a different parent hash than the previous downloaded block.
            //
            // [block 0]-----[block 1]       --[block 2]
            //            \                 /
            //             --[block 1 v2]--
            //
            async fn parent_hash_mismatch() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                let block1_v2 = reply::Block {
                    block_hash: Some(*BLOCK1_HASH_V2),
                    block_number: Some(BLOCK1_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 1 v2").unwrap()),
                    parent_block_hash: *BLOCK0_HASH,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer addr. 1 v2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT1_V2),
                    status: reply::Status::AcceptedOnL2,
                    timestamp: StarknetBlockTimestamp(4),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };
                let block2 = reply::Block {
                    block_hash: Some(*BLOCK2_HASH),
                    block_number: Some(BLOCK2_NUMBER),
                    gas_price: Some(GasPrice::from_be_slice(b"gas price 2").unwrap()),
                    parent_block_hash: *BLOCK1_HASH_V2,
                    sequencer_address: Some(SequencerAddress(
                        StarkHash::from_be_slice(b"sequencer address 2").unwrap(),
                    )),
                    state_root: Some(*GLOBAL_ROOT2),
                    status: reply::Status::AcceptedOnL1,
                    timestamp: StarknetBlockTimestamp(5),
                    transaction_receipts: vec![],
                    transactions: vec![],
                };

                // Fetch the genesis block with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT0_ADDR,
                    Ok(CONTRACT0_DEF.clone()),
                );
                // Fetch block #1 with respective state update and contracts
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(BLOCK1.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH).into(),
                    Ok(STATE_UPDATE1.clone()),
                );
                expect_full_contract(
                    &mut mock,
                    &mut seq,
                    *CONTRACT1_ADDR,
                    Ok(CONTRACT1_DEF.clone()),
                );
                // Fetch block #2 whose parent hash does not match block #1 hash
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2.clone()),
                );

                // L2 sync task goes back block by block to find where the block hash matches the DB
                // It starts at the previous block to which the mismatch happened
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );

                // Finally the L2 sync task is downloading the new blocks once it knows where to start again
                // Fetch the new block #1 from the fork with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK1_NUMBER.into(),
                    Ok(block1_v2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK1_HASH_V2).into(),
                    Ok(STATE_UPDATE1_V2.clone()),
                );
                // Fetch the block #2 again, now with respective state update
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK2_NUMBER.into(),
                    Ok(block2.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK2_HASH).into(),
                    Ok(STATE_UPDATE2.clone()),
                );

                // Indicate that we are still staying at the head - no new blocks and the latest block matches our head
                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK3_NUMBER.into(),
                    Err(block_not_found()),
                );
                expect_block(&mut mock, &mut seq, BlockId::Latest, Ok(block2.clone()));

                // Run the UUT
                let _jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT0_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT0_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, *BLOCK0);
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE0);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                    assert_eq!(contract_hashes, vec![*CONTRACT1_HASH]);
                    // Indicate that contract definition is not in the DB yet
                    sender.send(vec![false]).unwrap();
                });
                assert_matches!(rx_event.recv().await.unwrap(),
                    Event::NewContract(compressed_contract) => {
                        assert_eq!(compressed_contract.abi[..4], zstd_magic);
                        assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                        assert_eq!(compressed_contract.definition[..4], zstd_magic);
                        assert_eq!(compressed_contract.hash, *CONTRACT1_HASH);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, mut state_update, _) => {
                    assert_eq!(*block, *BLOCK1);
                    assert_eq!(state_update.deployed_contracts, vec![
                        state::sync::DeployedContract {
                            address: *CONTRACT1_ADDR,
                            hash: *CONTRACT1_HASH,
                            call_data: vec![],
                    }]);
                    state_update.contract_updates.sort();
                    assert_eq!(state_update, *EXPECTED_STATE_UPDATE1);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::QueryHash(block_number, sender) => {
                    assert_eq!(block_number, BLOCK0_NUMBER);
                    sender.send(Some(*BLOCK0_HASH)).unwrap();
                });
                // Reorg started from block #1
                assert_matches!(rx_event.recv().await.unwrap(), Event::Reorg(tail) => {
                    assert_eq!(tail, BLOCK1_NUMBER);
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block1_v2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
                assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block, state_update, _) => {
                    assert_eq!(*block, block2);
                    assert!(state_update.deployed_contracts.is_empty());
                    assert!(state_update.contract_updates.is_empty());
                });
            }

            #[tokio::test]
            async fn shutdown() {
                let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
                // Closing the event's channel should trigger the sync to exit with error after the first send.
                rx_event.close();

                let mut mock = MockClientApi::new();
                let mut seq = mockall::Sequence::new();

                expect_block(
                    &mut mock,
                    &mut seq,
                    BLOCK0_NUMBER.into(),
                    Ok(BLOCK0.clone()),
                );
                expect_state_update(
                    &mut mock,
                    &mut seq,
                    (*BLOCK0_HASH).into(),
                    Ok(STATE_UPDATE0.clone()),
                );

                // Run the UUT
                let jh = tokio::spawn(sync(tx_event, mock, None, Chain::Goerli));

                // Wrap this in a timeout so we don't wait forever in case of test failure.
                // Right now closing the channel causes an error.
                tokio::time::timeout(std::time::Duration::from_secs(2), jh)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
            }
        }
    }
}
