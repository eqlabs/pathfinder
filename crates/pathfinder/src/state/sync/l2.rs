use std::collections::HashSet;

use anyhow::Context;

use tokio::sync::{mpsc, oneshot};

use crate::{
    core::{StarknetBlockHash, StarknetBlockNumber},
    ethereum::state_update::{ContractUpdate, DeployedContract, StateUpdate, StorageUpdate},
    sequencer::{self},
    state::{contract_hash::extract_abi_code_hash, sync::SyncEvent, CompressedContract},
};

pub(super) async fn sync(
    tx_event: mpsc::Sender<SyncEvent>,
    sequencer: sequencer::Client,
    mut head: Option<(StarknetBlockNumber, StarknetBlockHash)>,
) -> anyhow::Result<()> {
    let mut compressor = zstd::bulk::Compressor::new(10)
        .context("Couldn't create zstd compressor for ContractsTable")
        .unwrap();

    'outer: loop {
        // Get the next block from L2.
        let next = match head {
            Some((number, _)) => number + 1,
            None => StarknetBlockNumber::GENESIS,
        };
        // TODO: deal with these Sequencer errors in some sensible fashion.
        // Not all of them are fatal -- some just indicate that the block is
        // actually missing / invalid so we are at head already...
        let block = sequencer
            .block_by_number(next.into())
            .await
            .with_context(|| format!("Fetch block {:?} from sequencer", next))?;

        // Check for reorg.
        if let Some(some_head) = head {
            if some_head.1 != block.parent_block_hash {
                // Go back in history until we find an L2 block that does still exist.
                // We already know the current head is invalid.
                let mut reorg_tail = some_head;

                let new_head = loop {
                    if reorg_tail.0 == StarknetBlockNumber::GENESIS {
                        break None;
                    }

                    let previous_block_number = reorg_tail.0 - 1;

                    let (tx, rx) = oneshot::channel();
                    if let Err(_closed) = tx_event
                        .send(SyncEvent::QueryL2Hash(previous_block_number, tx))
                        .await
                    {
                        return Ok(());
                    }

                    let previous_hash = match rx.await {
                        Ok(Some(hash)) => hash,
                        Ok(None) => break None,
                        Err(_closed) => return Ok(()),
                    };

                    // TODO: Handle 'None' option from sequencer reply.
                    let sequencer_hash = sequencer
                        .block_by_number(previous_block_number.into())
                        .await
                        .with_context(|| {
                            format!(
                                "Fetch block {:?} from sequencer during L2 reorg check",
                                previous_block_number
                            )
                        })?
                        .block_hash
                        .unwrap();

                    // We found the end of the L2 reorg.
                    if sequencer_hash == previous_hash {
                        break Some((previous_block_number, previous_hash));
                    }

                    reorg_tail = (previous_block_number, previous_hash);
                };

                head = new_head;

                let reorg_tail = head.map(|x| x.0).unwrap_or(StarknetBlockNumber::GENESIS);

                if let Err(_closed) = tx_event.send(SyncEvent::L2Reorg(reorg_tail)).await {
                    return Ok(());
                }

                continue 'outer;
            }
        }

        // unwrap is safe as the block hash always exists (unless we query for pending).
        let state_diff = sequencer
            .state_update_by_hash(block.block_hash.unwrap().into())
            .await
            .with_context(|| format!("Fetch state diff for block {:?} from sequencer", next))?;

        // Download newly deployed contracts which are not already in the database.
        let unique_contracts = state_diff
            .state_diff
            .deployed_contracts
            .iter()
            .map(|contract| contract.contract_hash)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        // Query database to see which of these contracts still needs downloading.
        let (tx, rx) = oneshot::channel();
        if let Err(_closed) = tx_event
            .send(SyncEvent::QueryL2ContractExistance(
                unique_contracts.clone(),
                tx,
            ))
            .await
        {
            // Treat event channel closure as exit instruction.
            return Ok(());
        }
        let already_downloaded = match rx.await {
            Ok(exist) => exist,
            Err(_closed) => return Ok(()),
        };

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
                .state_diff
                .deployed_contracts
                .iter()
                .find_map(|contract| match contract.contract_hash == contract_hash {
                    true => Some(contract),
                    false => None,
                })
                .unwrap();

            // TODO: consider what to do if this fails -- there might be some reorg timing clash here,
            //       in which case we need to restart the loop..
            let contract_definition = sequencer
                .full_contract(contract.address)
                .await
                .context("Download contract from sequencer")?
                .to_vec();

            // Perform the extraction and compression.
            let (abi, bytecode, hash) =
                extract_abi_code_hash(&contract_definition).context("Compute contract hash")?;

            // Sanity check.
            // TODO: what do we do in case of a mismatch? Is there anything to do, apart from bail out?
            anyhow::ensure!(
                contract.contract_hash == hash,
                "Contract hash mismatch for contract {:?}",
                contract.address
            );

            // TODO: insert contract into database event.
            let abi = compressor
                .compress(&abi)
                .context("Failed to compress ABI")?;
            let bytecode = compressor
                .compress(&bytecode)
                .context("Failed to compress bytecode")?;
            let definition = compressor
                .compress(&*contract_definition)
                .context("Failed to compress definition")?;

            let contract = CompressedContract {
                abi,
                bytecode,
                definition,
                hash,
            };

            if let Err(_closed) = tx_event.send(SyncEvent::L2NewContract(contract)).await {
                return Ok(());
            }
        }

        // Map from sequencer type to the actual type... we should declutter these types.
        let deployed_contracts = state_diff
            .state_diff
            .deployed_contracts
            .into_iter()
            .map(|contract| DeployedContract {
                address: contract.address,
                hash: contract.contract_hash,
                call_data: vec![], // todo!("This is missing from sequencer API..."),
            })
            .collect::<Vec<_>>();

        let contract_updates = state_diff
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

        if let Err(_closed) = tx_event.send(SyncEvent::L2Update(block, update)).await {
            return Ok(());
        }
    }
}
