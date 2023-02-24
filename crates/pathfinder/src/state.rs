pub mod block_hash;
mod sync;

pub use sync::{l1, l2, sync};

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn init_deployed_contracts_root_to_zero_regression() {
        todo!("Update me to new sync process when possible");
        // This is a regression test for a bug that we encountered at block 47047 on alpha4/goerli.
        // It resulted in a global root mismatch due to the fact that we did not initialize
        // the contract root to zero when a contract was deployed.
        // use pathfinder_common::StarknetBlockTimestamp;

        // let s = crate::storage::Storage::in_memory().unwrap();

        // let contract_hash = ClassHash(StarkHash::from_hex_str("0x11").unwrap());
        // let contract_addr = ContractAddress::new_or_panic(StarkHash::from_hex_str("1").unwrap());
        // let contract_deploy = DeployedContract {
        //     address: contract_addr,
        //     hash: contract_hash,
        //     call_data: vec![],
        // };

        // let state_update = StateUpdate {
        //     deployed_contracts: vec![contract_deploy.clone()],
        //     contract_updates: vec![],
        // };

        // // The global root that we start with
        // let global_root = StateCommitment(Felt::ZERO);

        // // The global root that we end with
        // let expected_global_root = StateCommitment(
        //     StarkHash::from_hex_str(
        //         "04BA80F86439D380FF9EC91EE316C9FEA4C5AD2CAEFA8D5CC098AED72DE445B8",
        //     )
        //     .unwrap(),
        // );

        // let update_log = StateUpdateLog {
        //     origin: EthOrigin {
        //         block: BlockOrigin {
        //             hash: EthereumBlockHash(H256::zero()),
        //             number: EthereumBlockNumber(0),
        //         },
        //         transaction: TransactionOrigin {
        //             hash: EthereumTransactionHash(H256::zero()),
        //             index: EthereumTransactionIndex(0),
        //         },
        //         log_index: EthereumLogIndex(0),
        //     },
        //     global_root: expected_global_root,
        //     block_number: StarknetBlockNumber(0),
        // };

        // let (c_tx, mut c_rx) = mpsc::channel(1);
        // let (r_tx, mut r_rx) = mpsc::channel(1);

        // // Run the code that we want to test
        // let jh = std::thread::spawn(move || {
        //     let mut conn = s.connection().unwrap();
        //     let tx = conn.transaction().unwrap();
        //     update(
        //         state_update,
        //         global_root,
        //         &update_log,
        //         &tx,
        //         &c_tx,
        //         &mut r_rx,
        //     )
        //     .unwrap()
        // });

        // // Consume update's request to fetch the contract to proceed futher
        // let requests = c_rx.blocking_recv().unwrap();

        // assert_eq!(
        //     requests,
        //     vec![FetchExtractContract {
        //         deploy_info: contract_deploy.clone(),
        //         fetch: true
        //     }]
        // );

        // // We need to set the magic bytes for zstd compression to simulate a compressed
        // // contract definition, as this is asserted for internally
        // let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

        // let contract_fetched_compressed = FetchedCompressedContract {
        //     deploy_info: contract_deploy,
        //     payload: Some(CompressedContract {
        //         definition: zstd_magic,
        //         hash: contract_hash,
        //     }),
        // };

        // // Send simulated fetched and compressed contract definition to
        // // trigger global state tree update.
        // r_tx.blocking_send(contract_fetched_compressed).unwrap();

        // // Before the fix we would get a global root mismatch error here.
        // let block_updated = jh.join().unwrap();

        // let expected_block_updated = BlockUpdated {
        //     record: GlobalStateRecord {
        //         block_hash: StarknetBlockHash(
        //             StarkHash::from_hex_str(
        //                 "0x00275921A89D44EF9D4EE74BFFF189D6F995DD07CFF9D0B8637B5C4619E9A05D",
        //             )
        //             .unwrap(),
        //         ),
        //         global_root: expected_global_root,
        //         block_number: StarknetBlockNumber(0),
        //         block_timestamp: StarknetBlockTimestamp::new_or_panic(0),
        //         eth_block_hash: EthereumBlockHash(H256::zero()),
        //         eth_block_number: EthereumBlockNumber(0),
        //         eth_log_index: EthereumLogIndex(0),
        //         eth_tx_hash: EthereumTransactionHash(H256::zero()),
        //         eth_tx_index: EthereumTransactionIndex(0),
        //     },
        //     info: BlockInfo {
        //         deployed_contract_count: 1,
        //         total_updates: 0,
        //         updated_contracts: 0,
        //     },
        // };

        // // There should not be a global root mismatch anymore
        // assert_eq!(block_updated, expected_block_updated);
    }

    #[test]
    #[ignore]
    fn update_requests_fetching_unique_new_contracts() {
        todo!("Update me to new sync process when possible");
        // use pathfinder_common::{StorageAddress, StorageValue};
        // use pathfinder_ethereum::state_update::{ContractUpdate, StorageUpdate};

        // let s = crate::storage::Storage::in_memory().unwrap();

        // let shared_hash =
        //     ClassHash(StarkHash::from_be_slice(&b"this is shared by multiple"[..]).unwrap());
        // let unique_hash =
        //     ClassHash(StarkHash::from_be_slice(&b"this is unique contract"[..]).unwrap());

        // let one = ContractAddress::new_or_panic(StarkHash::from_hex_str("1").unwrap());
        // let two = ContractAddress::new_or_panic(StarkHash::from_hex_str("2").unwrap());
        // let three = ContractAddress::new_or_panic(StarkHash::from_hex_str("3").unwrap());

        // let one_deploy = DeployedContract {
        //     address: one,
        //     hash: shared_hash,
        //     call_data: vec![],
        // };

        // let two_deploy = DeployedContract {
        //     address: two,
        //     hash: shared_hash,
        //     call_data: vec![],
        // };

        // let three_deploy = DeployedContract {
        //     address: three,
        //     hash: unique_hash,
        //     call_data: vec![],
        // };

        // // neither of these deployed contracts are in database, which is empty
        // let state_update = StateUpdate {
        //     deployed_contracts: vec![one_deploy.clone(), two_deploy.clone(), three_deploy.clone()],
        //     contract_updates: vec![ContractUpdate {
        //         address: one,
        //         storage_updates: vec![StorageUpdate {
        //             address: StorageAddress::new_or_panic(StarkHash::from_hex_str("1").unwrap()),
        //             value: StorageValue(StarkHash::from_hex_str("dead").unwrap()),
        //         }],
        //     }],
        // };

        // let global_root = StateCommitment(Felt::ZERO);
        // let update_log = StateUpdateLog {
        //     origin: EthOrigin {
        //         block: BlockOrigin {
        //             hash: EthereumBlockHash(H256::zero()),
        //             number: EthereumBlockNumber(0),
        //         },
        //         transaction: TransactionOrigin {
        //             hash: EthereumTransactionHash(H256::zero()),
        //             index: EthereumTransactionIndex(0),
        //         },
        //         log_index: EthereumLogIndex(0),
        //     },
        //     global_root: StateCommitment(Felt::ZERO),
        //     block_number: StarknetBlockNumber(0),
        // };

        // let (c_tx, mut c_rx) = mpsc::channel(1);
        // let (r_tx, mut r_rx) = mpsc::channel(1);

        // let jh = std::thread::spawn(move || {
        //     let mut conn = s.connection().unwrap();
        //     let tx = conn.transaction().unwrap();
        //     update(
        //         state_update,
        //         global_root,
        //         &update_log,
        //         &tx,
        //         &c_tx,
        //         &mut r_rx,
        //     )
        //     .unwrap();
        // });

        // let requests = c_rx.blocking_recv().unwrap();

        // // since the two deployed contracts share the hash only first of them must be `fetch:
        // // true`, third is unique
        // assert_eq!(
        //     requests,
        //     vec![
        //         FetchExtractContract {
        //             deploy_info: one_deploy,
        //             fetch: true
        //         },
        //         FetchExtractContract {
        //             deploy_info: two_deploy,
        //             fetch: false
        //         },
        //         FetchExtractContract {
        //             deploy_info: three_deploy,
        //             fetch: true
        //         }
        //     ]
        // );

        // // this will lead to panic when awaiting for the ready contracts.
        // drop(r_tx);

        // // which we assert here; now it could be some other panic as well
        // jh.join().unwrap_err();
    }

    #[tokio::test]
    #[ignore = "Sequencer currently gives 502/503"]
    async fn genesis() {
        todo!("Update me to new sync process when possible");
        // use pathfinder_common::{
        //     EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
        //     EthereumTransactionIndex, StateCommitment, StarknetBlockHash, StarknetBlockNumber,
        // };
        // use pathfinder_ethereum::{
        //     log::StateUpdateLog, test::create_test_transport, BlockOrigin, EthOrigin,
        //     TransactionOrigin,
        // };
        // use std::str::FromStr;
        // use web3::types::H256;
        // // Georli genesis block values from Alpha taken from Voyager block explorer.
        // // https://goerli.voyager.online/block/0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b

        // let starknet_block_hash = StarknetBlockHash(
        //     StarkHash::from_hex_str(
        //         "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b",
        //     )
        //     .unwrap(),
        // );

        // let genesis = StateUpdateLog {
        //     origin: EthOrigin {
        //         block: BlockOrigin {
        //             hash: EthereumBlockHash(
        //                 H256::from_str(
        //                     "a3c7bb4baa81bb8bc5cc75ace7d8296b2668ccc2fd5ac9d22b5eefcfbf7f3444",
        //                 )
        //                 .unwrap(),
        //             ),
        //             number: EthereumBlockNumber(5854324),
        //         },
        //         transaction: TransactionOrigin {
        //             hash: EthereumTransactionHash(
        //                 H256::from_str(
        //                     "97ee44ba80d1ad5cff4a5adc02311f6e19490f48ea5a57c7f510e469cae7e65b",
        //                 )
        //                 .unwrap(),
        //             ),
        //             index: EthereumTransactionIndex(4),
        //         },
        //         log_index: EthereumLogIndex(23),
        //     },
        //     global_root: StateCommitment(
        //         StarkHash::from_hex_str(
        //             "02c2bb91714f8448ed814bdac274ab6fcdbafc22d835f9e847e5bee8c2e5444e",
        //         )
        //         .unwrap(),
        //     ),
        //     block_number: StarknetBlockNumber(0),
        // };

        // let chain = crate::core::Chain::Goerli;
        // let _sequencer = crate::sequencer::Client::new(chain).unwrap();

        // let storage = crate::storage::Storage::in_memory().unwrap();
        // let mut conn = storage.connection().unwrap();
        // let transaction = conn.transaction().unwrap();

        // let _transport = create_test_transport(chain);

        // /*
        // update(
        //     &transport,
        //     StateCommitment(Felt::ZERO),
        //     &genesis,
        //     &transaction,
        //     &sequencer,
        // )
        // .await
        // .unwrap();
        // */

        // // TODO: "is this test supposed to be sync for one block?

        // // Read the new latest state from database.
        // let state = crate::storage::GlobalStateTable::get_latest_state(&transaction)
        //     .unwrap()
        //     .unwrap();

        // assert_eq!(state.block_hash, starknet_block_hash);
        // assert_eq!(state.global_root, genesis.global_root);
        // assert_eq!(state.block_number, genesis.block_number);
        // assert_eq!(state.eth_block_hash, genesis.origin.block.hash);
        // assert_eq!(state.eth_block_number, genesis.origin.block.number);
        // assert_eq!(state.eth_tx_hash, genesis.origin.transaction.hash);
        // assert_eq!(state.eth_tx_index, genesis.origin.transaction.index);
        // assert_eq!(state.eth_log_index, genesis.origin.log_index);
    }
}
