use std::{collections::HashSet, time::Duration};

use anyhow::Context;

use tokio::sync::{mpsc, oneshot};

use crate::{
    core::{ContractHash, StarknetBlockHash, StarknetBlockNumber},
    ethereum::state_update::{ContractUpdate, DeployedContract, StateUpdate, StorageUpdate},
    rpc::types::{BlockNumberOrTag, Tag},
    sequencer::{
        self,
        error::SequencerError,
        reply::{
            state_update::{Contract, StateDiff},
            Block,
        },
    },
    state::{contract_hash::extract_abi_code_hash, CompressedContract},
};

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
    Update(Block, StateUpdate, Timings),
    /// An L@ reorg was detected, contains the reorg-tail which
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
    /// Query for the existance of the the given [contracts](ContractHash) in storage.
    ///
    /// The receiver should return true (if the contract exists) or false (if it does not exist)
    /// for each contract using the [oneshot::channel].
    QueryContractExistance(Vec<ContractHash>, oneshot::Sender<Vec<bool>>),
}

pub async fn sync(
    tx_event: mpsc::Sender<Event>,
    sequencer: impl sequencer::ClientApi,
    mut head: Option<(StarknetBlockNumber, StarknetBlockHash)>,
) -> anyhow::Result<()> {
    'outer: loop {
        // Get the next block from L2.
        let next = match head {
            Some((number, _)) => number + 1,
            None => StarknetBlockNumber::GENESIS,
        };

        let t_block = std::time::Instant::now();
        let block = loop {
            match download_block(next, &sequencer).await? {
                DownloadBlock::Block(block) => break block,
                DownloadBlock::AtHead => tokio::time::sleep(Duration::from_secs(5)).await,
                DownloadBlock::Reorg => {
                    let some_head = head.unwrap();
                    head = reorg(some_head, &tx_event, &sequencer)
                        .await
                        .context("L2 reorg")?;

                    continue 'outer;
                }
            }
        };
        let t_block = t_block.elapsed();

        if let Some(some_head) = head {
            if some_head.1 != block.parent_block_hash {
                head = reorg(some_head, &tx_event, &sequencer)
                    .await
                    .context("L2 reorg")?;

                continue 'outer;
            }
        }

        // unwrap is safe as the block hash always exists (unless we query for pending).
        let t_update = std::time::Instant::now();
        let state_update = sequencer
            .state_update_by_hash(block.block_hash.unwrap().into())
            .await
            .with_context(|| format!("Fetch state diff for block {:?} from sequencer", next))?;
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

        head = Some((next, block.block_hash.unwrap()));

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
    Block(Block),
    AtHead,
    Reorg,
}

async fn download_block(
    block: StarknetBlockNumber,
    sequencer: &impl sequencer::ClientApi,
) -> anyhow::Result<DownloadBlock> {
    use sequencer::error::StarknetErrorCode::BlockNotFound;

    let result = sequencer.block_by_number(block.into()).await;

    match result {
        Ok(block) => Ok(DownloadBlock::Block(block)),
        Err(SequencerError::StarknetError(err)) if err.code == BlockNotFound => {
            // This would occur if we queried past the head of the chain. We now need to check that
            // a reorg hasn't put us too far in the future. This does run into race conditions with the
            // sequencer but this is the best we can do I think.
            let latest = sequencer
                .block_by_number(BlockNumberOrTag::Tag(Tag::Latest))
                .await
                .context("Query sequencer for latest block")?;

            if latest.block_number.unwrap() + 1 == block {
                Ok(DownloadBlock::AtHead)
            } else {
                Ok(DownloadBlock::Reorg)
            }
        }
        Err(other) => Err(other).context("Download block from sequencer"),
    }
}

async fn reorg(
    head: (StarknetBlockNumber, StarknetBlockHash),
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

        match download_block(previous_block_number, sequencer)
            .await
            .with_context(|| format!("Download block {} from sequencer", previous_block_number.0))?
        {
            DownloadBlock::Block(block) if block.block_hash.unwrap() == previous_hash => {
                break Some((previous_block_number, previous_hash))
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
            .find_map(|contract| match contract.contract_hash == contract_hash {
                true => Some(contract),
                false => None,
            })
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

    // Parse the contract definition for ABI, code and calculate the contract hash. This can
    // be expensive, so perform in a blocking task.
    let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let (abi, bytecode, hash) = extract_abi_code_hash(&contract_definition)?;
        Ok((contract_definition, abi, bytecode, hash))
    });
    let (contract_definition, abi, bytecode, hash) = extract
        .await
        .context("Parse contract definition and compute hash")??;

    eprintln!("{}", contract.contract_hash.0);
    eprintln!("{}", hash.0);

    // Sanity check.
    anyhow::ensure!(
        contract.contract_hash == hash,
        "Contract hash mismatch for contract {:?}",
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
                ContractAddress, ContractHash, GlobalRoot, StarknetBlockHash, StarknetBlockNumber,
                StarknetBlockTimestamp, StorageAddress, StorageValue,
            },
            ethereum::state_update,
            rpc::types::BlockNumberOrTag,
            sequencer::{reply, MockClientApi},
            state,
        };
        use assert_matches::assert_matches;
        use pedersen::StarkHash;
        use pretty_assertions::assert_eq;
        use std::collections::HashMap;

        #[tokio::test]
        async fn happy_path_from_genesis() {
            let (tx_event, mut rx_event) = tokio::sync::mpsc::channel(1);
            let mut mock_sequencer = MockClientApi::new();
            let mut seq = mockall::Sequence::new();

            let block0_number = StarknetBlockNumber(0);
            let block0_hash = StarknetBlockHash(StarkHash::from_be_slice(b"block 0 hash").unwrap());
            let global_root0 = GlobalRoot(StarkHash::from_be_slice(b"global root 0").unwrap());
            let block0 = reply::Block {
                block_hash: Some(block0_hash),
                block_number: Some(block0_number),
                parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
                state_root: Some(global_root0),
                status: reply::Status::AcceptedOnL1,
                timestamp: StarknetBlockTimestamp(0),
                transaction_receipts: vec![],
                transactions: vec![],
            };
            let contract0_addr =
                ContractAddress(StarkHash::from_be_slice(b"contract 0 addr").unwrap());
            let contract0_hash = ContractHash(
                StarkHash::from_hex_str(
                    "0x0450FBC0994727C70DDAA04FDF10C362E45CB46130146FE16F70584E8E642182",
                )
                .unwrap(),
            );
            let contract0_def_bytes = bytes::Bytes::from(
                r#"{
                    "abi": [],
                    "program": {
                        "attributes": [],
                        "builtins": [],
                        "data": [],
                        "hints": {},
                        "identifiers": {},
                        "main_scope": "contract 0 definition",
                        "prime": "",
                        "reference_manager": ""

                    },
                    "entry_points_by_type": {}
                }"#,
            );
            let storage_key0 =
                StorageAddress(StarkHash::from_be_slice(b"contract 0 storage addr 0").unwrap());
            let storage_val0 =
                StorageValue(StarkHash::from_be_slice(b"contract 0 storage val 0").unwrap());
            let state_update0 = reply::StateUpdate {
                new_root: global_root0,
                old_root: GlobalRoot(StarkHash::ZERO),
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![reply::state_update::Contract {
                        address: contract0_addr,
                        contract_hash: contract0_hash,
                    }],
                    storage_diffs: HashMap::from([(
                        contract0_addr,
                        vec![reply::state_update::StorageDiff {
                            key: storage_key0,
                            value: storage_val0,
                        }],
                    )]),
                },
            };

            let block1_number = StarknetBlockNumber(1);
            let block1_hash = StarknetBlockHash(StarkHash::from_be_slice(b"block 1 hash").unwrap());
            let global_root1 = GlobalRoot(StarkHash::from_be_slice(b"global root 1").unwrap());
            let block1 = reply::Block {
                block_hash: Some(block1_hash),
                block_number: Some(block1_number),
                parent_block_hash: block0_hash,
                state_root: Some(global_root1),
                status: reply::Status::AcceptedOnL1,
                timestamp: StarknetBlockTimestamp(1),
                transaction_receipts: vec![],
                transactions: vec![],
            };
            let contract1_addr =
                ContractAddress(StarkHash::from_be_slice(b"contract 1 addr").unwrap());
            let contract1_hash = ContractHash(
                StarkHash::from_hex_str(
                    "0x0676540F61FDED9A4161AEA1A8B229F273A14FD89A7E0047D80BA74B5EA3D55D",
                )
                .unwrap(),
            );
            let contract1_def_bytes = bytes::Bytes::from(
                r#"{
                    "abi": [],
                    "program": {
                        "attributes": [],
                        "builtins": [],
                        "data": [],
                        "hints": {},
                        "identifiers": {},
                        "main_scope": "contract 1 definition",
                        "prime": "",
                        "reference_manager": ""

                    },
                    "entry_points_by_type": {}
                }"#,
            );
            let storage_key1 =
                StorageAddress(StarkHash::from_be_slice(b"contract 1 storage addr 0").unwrap());
            let storage_val1 =
                StorageValue(StarkHash::from_be_slice(b"contract 1 storage val 0").unwrap());
            let storage_val0_v2 =
                StorageValue(StarkHash::from_be_slice(b"contract 0 storage val 0 v2").unwrap());
            let state_update1 = reply::StateUpdate {
                new_root: global_root1,
                old_root: global_root0,
                state_diff: reply::state_update::StateDiff {
                    deployed_contracts: vec![reply::state_update::Contract {
                        address: contract1_addr,
                        contract_hash: contract1_hash,
                    }],
                    storage_diffs: HashMap::from([
                        (
                            contract0_addr,
                            vec![reply::state_update::StorageDiff {
                                key: storage_key0,
                                value: storage_val0_v2,
                            }],
                        ),
                        (
                            contract1_addr,
                            vec![reply::state_update::StorageDiff {
                                key: storage_key1,
                                value: storage_val1,
                            }],
                        ),
                    ]),
                },
            };

            let mock_output = block0.clone();
            mock_sequencer
                .expect_block_by_number()
                .withf(move |x| x == &BlockNumberOrTag::Number(block0_number))
                .times(1)
                .in_sequence(&mut seq)
                .return_once(move |_| Ok(mock_output));

            mock_sequencer
                .expect_state_update_by_hash()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(state_update0));

            mock_sequencer
                .expect_full_contract()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(contract0_def_bytes));

            let mock_output = block1.clone();
            mock_sequencer
                .expect_block_by_number()
                .withf(move |x| x == &BlockNumberOrTag::Number(block1_number))
                .times(1)
                .in_sequence(&mut seq)
                .return_once(move |_| Ok(mock_output));

            mock_sequencer
                .expect_state_update_by_hash()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(state_update1));

            mock_sequencer
                .expect_full_contract()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Ok(contract1_def_bytes));

            // Let's run the UUT
            let _jh = tokio::spawn(sync(tx_event, mock_sequencer, None));

            let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

            assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                assert_eq!(contract_hashes, vec![contract0_hash]);
                // Contract 0 definition is not in the DB yet
                sender.send(vec![false]).unwrap();
            });
            assert_matches!(rx_event.recv().await.unwrap(),
                Event::NewContract(compressed_contract) => {
                    assert_eq!(compressed_contract.abi[..4], zstd_magic);
                    assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                    assert_eq!(compressed_contract.definition[..4], zstd_magic);
                    assert_eq!(compressed_contract.hash, contract0_hash);
            });
            assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block,state_update,_) => {
                assert_eq!(block, block0);
                assert_eq!(state_update, state_update::StateUpdate {
                    contract_updates: vec![state_update::ContractUpdate {
                        address: contract0_addr,
                        storage_updates: vec![
                            state_update::StorageUpdate {
                                address: storage_key0,
                                value: storage_val0,
                            }
                        ]
                    }],
                    deployed_contracts: vec![
                        state::sync::DeployedContract {
                            address: contract0_addr,
                            hash: contract0_hash,
                            call_data: vec![],
                    }]});
            });
            assert_matches!(rx_event.recv().await.unwrap(), Event::QueryContractExistance(contract_hashes, sender) => {
                assert_eq!(contract_hashes, vec![contract1_hash]);
                // Contract 1 definition is not in the DB yet
                sender.send(vec![false]).unwrap();
            });
            assert_matches!(rx_event.recv().await.unwrap(),
                Event::NewContract(compressed_contract) => {
                    assert_eq!(compressed_contract.abi[..4], zstd_magic);
                    assert_eq!(compressed_contract.bytecode[..4], zstd_magic);
                    assert_eq!(compressed_contract.definition[..4], zstd_magic);
                    assert_eq!(compressed_contract.hash, contract1_hash);
            });
            assert_matches!(rx_event.recv().await.unwrap(), Event::Update(block,mut state_update,_) => {
                assert_eq!(block, block1);
                assert_eq!(state_update.deployed_contracts, vec![
                    state::sync::DeployedContract {
                        address: contract1_addr,
                        hash: contract1_hash,
                        call_data: vec![],
                }]);

                state_update.contract_updates.sort();

                assert_eq!(state_update.contract_updates, vec![
                    state_update::ContractUpdate {
                        address: contract0_addr,
                        storage_updates: vec![
                            state_update::StorageUpdate {
                                address: storage_key0,
                                value: storage_val0_v2,
                            }
                        ]
                    },
                    state_update::ContractUpdate {
                        address: contract1_addr,
                        storage_updates: vec![
                            state_update::StorageUpdate {
                                address: storage_key1,
                                value: storage_val1,
                            }
                        ]
                    }
                ]);
            });
        }
    }
}
