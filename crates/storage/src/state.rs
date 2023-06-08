use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, ClassHash, ContractNonce, ContractRoot,
    ContractStateHash, EventCommitment, GasPrice, SequencerAddress, StateCommitment,
    TransactionCommitment,
};

use crate::prelude::*;

pub(crate) fn contract_state(
    tx: &Transaction<'_>,
    state_hash: ContractStateHash,
) -> anyhow::Result<Option<(ContractRoot, ClassHash, ContractNonce)>> {
    tx.query_row(
        "SELECT root, hash, nonce FROM contract_states WHERE state_hash = :state_hash",
        named_params! {
            ":state_hash": &state_hash
        },
        |row| {
            let root = row.get_contract_root("root")?;
            let hash = row.get_class_hash("hash")?;
            let nonce = row.get_contract_nonce("nonce")?;

            Ok((root, hash, nonce))
        },
    )
    .optional()
    .map_err(|e| e.into())
}

pub(crate) fn insert_contract_state(
    tx: &Transaction<'_>,
    state_hash: ContractStateHash,
    class_hash: ClassHash,
    root: ContractRoot,
    nonce: ContractNonce,
) -> anyhow::Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO contract_states (state_hash, hash, root, nonce) VALUES (:state_hash, :hash, :root, :nonce)",
        named_params! {
            ":state_hash": &state_hash,
            ":hash": &class_hash,
            ":root": &root,
            ":nonce": &nonce,
        },
    )?;
    Ok(())
}

/// Describes a Starknet block.
///
/// While the sequencer version on each block (when present) is stored since starknet 0.9.1, it is
/// not yet read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarknetBlock {
    pub number: BlockNumber,
    pub hash: BlockHash,
    pub state_commmitment: StateCommitment,
    pub timestamp: BlockTimestamp,
    pub gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub transaction_commitment: Option<TransactionCommitment>,
    pub event_commitment: Option<EventCommitment>,
}

#[cfg(test)]
mod tests {
    // use super::*;

    // mod starknet_blocks {
    //     use super::*;
    //     use crate::test_utils::{self, BlockWithCommitment};

    //     fn create_blocks() -> [BlockWithCommitment; test_utils::NUM_BLOCKS] {
    //         test_utils::create_blocks()
    //     }

    //     fn with_default_blocks<F>(f: F)
    //     where
    //         F: FnOnce(&Transaction<'_>, [BlockWithCommitment; test_utils::NUM_BLOCKS]),
    //     {
    //         let storage = Storage::in_memory().unwrap();
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let blocks = create_blocks();
    //         for block in &blocks {
    //             StarknetBlocksTable::insert(
    //                 &tx,
    //                 &block.block,
    //                 &StarknetVersion::default(),
    //                 block.storage_commitment,
    //                 block.class_commitment,
    //             )
    //             .unwrap();
    //         }

    //         f(&tx, blocks)
    //     }

    //     mod get {
    //         use super::*;

    //         mod by_number {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let result = StarknetBlocksTable::get(tx, block.block.number.into())
    //                             .unwrap()
    //                             .unwrap();

    //                         assert_eq!(result, block.block);
    //                     }
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let non_existent = blocks.last().unwrap().block.number + 1;
    //                     assert_eq!(
    //                         StarknetBlocksTable::get(tx, non_existent.into()).unwrap(),
    //                         None
    //                     );
    //                 });
    //             }
    //         }

    //         mod by_hash {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let result = StarknetBlocksTable::get(tx, block.block.hash.into())
    //                             .unwrap()
    //                             .unwrap();

    //                         assert_eq!(result, block.block);
    //                     }
    //                 });
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, _blocks| {
    //                     let non_existent = BlockHash(Felt::from_hex_str(&"b".repeat(10)).unwrap());
    //                     assert_eq!(
    //                         StarknetBlocksTable::get(tx, non_existent.into()).unwrap(),
    //                         None
    //                     );
    //                 });
    //             }
    //         }

    //         mod latest {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let expected = &blocks.last().unwrap().block;

    //                     let latest = StarknetBlocksTable::get(tx, BlockId::Latest)
    //                         .unwrap()
    //                         .unwrap();
    //                     assert_eq!(&latest, expected);
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 let storage = Storage::in_memory().unwrap();
    //                 let mut connection = storage.connection().unwrap();
    //                 let tx = connection.transaction().unwrap();

    //                 let latest = StarknetBlocksTable::get(&tx, BlockId::Latest).unwrap();
    //                 assert_eq!(latest, None);
    //             }
    //         }

    //         mod number_by_hash {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let result = StarknetBlocksTable::get_number(tx, block.block.hash)
    //                             .unwrap()
    //                             .unwrap();

    //                         assert_eq!(result, block.block.number);
    //                     }
    //                 });
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, _blocks| {
    //                     let non_existent = BlockHash(Felt::from_hex_str(&"b".repeat(10)).unwrap());
    //                     assert_eq!(
    //                         StarknetBlocksTable::get_number(tx, non_existent).unwrap(),
    //                         None
    //                     );
    //                 });
    //             }
    //         }
    //     }

    //     mod get_storage_and_state_commitments {
    //         use super::*;

    //         mod by_number {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let storage_commitment = StarknetBlocksTable::get_storage_commitment(
    //                             tx,
    //                             block.block.number.into(),
    //                         )
    //                         .unwrap()
    //                         .unwrap();
    //                         let state_commitment = StarknetBlocksTable::get_state_commitment(
    //                             tx,
    //                             block.block.number.into(),
    //                         )
    //                         .unwrap()
    //                         .unwrap();

    //                         assert_eq!(storage_commitment, state_commitment.0);
    //                         assert_eq!(state_commitment.0, block.storage_commitment);
    //                         assert_eq!(state_commitment.1, block.class_commitment);
    //                         assert_eq!(
    //                             StateCommitment::calculate(state_commitment.0, state_commitment.1),
    //                             block.block.state_commmitment
    //                         );
    //                     }
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let non_existent = blocks.last().unwrap().block.number + 1;
    //                     assert_eq!(
    //                         StarknetBlocksTable::get_storage_commitment(tx, non_existent.into())
    //                             .unwrap(),
    //                         None
    //                     );
    //                     assert_eq!(
    //                         StarknetBlocksTable::get_state_commitment(tx, non_existent.into())
    //                             .unwrap(),
    //                         None
    //                     );
    //                 })
    //             }
    //         }

    //         mod by_hash {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let storage_commitment = StarknetBlocksTable::get_storage_commitment(
    //                             tx,
    //                             block.block.hash.into(),
    //                         )
    //                         .unwrap()
    //                         .unwrap();
    //                         let state_commitment = StarknetBlocksTable::get_state_commitment(
    //                             tx,
    //                             block.block.hash.into(),
    //                         )
    //                         .unwrap()
    //                         .unwrap();

    //                         assert_eq!(storage_commitment, state_commitment.0);
    //                         assert_eq!(state_commitment.0, block.storage_commitment);
    //                         assert_eq!(state_commitment.1, block.class_commitment);
    //                         assert_eq!(
    //                             StateCommitment::calculate(state_commitment.0, state_commitment.1),
    //                             block.block.state_commmitment
    //                         );
    //                     }
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, _blocks| {
    //                     let non_existent = BlockHash(Felt::from_hex_str(&"b".repeat(10)).unwrap());
    //                     assert_eq!(
    //                         StarknetBlocksTable::get_storage_commitment(tx, non_existent.into())
    //                             .unwrap(),
    //                         None
    //                     );
    //                     assert_eq!(
    //                         StarknetBlocksTable::get_state_commitment(tx, non_existent.into())
    //                             .unwrap(),
    //                         None
    //                     );
    //                 })
    //             }
    //         }

    //         mod latest {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let expected = blocks.last().unwrap();

    //                     let storage_commitment =
    //                         StarknetBlocksTable::get_storage_commitment(tx, BlockId::Latest)
    //                             .unwrap()
    //                             .unwrap();
    //                     let state_commitment =
    //                         StarknetBlocksTable::get_state_commitment(tx, BlockId::Latest)
    //                             .unwrap()
    //                             .unwrap();

    //                     assert_eq!(storage_commitment, state_commitment.0);
    //                     assert_eq!(state_commitment.0, expected.storage_commitment);
    //                     assert_eq!(state_commitment.1, expected.class_commitment);
    //                     assert_eq!(
    //                         StateCommitment::calculate(state_commitment.0, state_commitment.1),
    //                         expected.block.state_commmitment
    //                     );
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 let storage = Storage::in_memory().unwrap();
    //                 let mut connection = storage.connection().unwrap();
    //                 let tx = connection.transaction().unwrap();

    //                 assert_eq!(
    //                     StarknetBlocksTable::get_storage_commitment(&tx, BlockId::Latest,).unwrap(),
    //                     None
    //                 );
    //                 assert_eq!(
    //                     StarknetBlocksTable::get_state_commitment(&tx, BlockId::Latest,).unwrap(),
    //                     None
    //                 );
    //             }
    //         }
    //     }

    //     mod reorg {
    //         use super::*;

    //         #[test]
    //         fn full() {
    //             with_default_blocks(|tx, _blocks| {
    //                 // reorg to genesis expected to wipe the blocks
    //                 StarknetBlocksTable::reorg(tx, BlockNumber::GENESIS).unwrap();

    //                 assert_eq!(StarknetBlocksTable::get(tx, BlockId::Latest).unwrap(), None);
    //             })
    //         }

    //         #[test]
    //         fn partial() {
    //             with_default_blocks(|tx, blocks| {
    //                 let reorg_tail = blocks[1].block.number;
    //                 StarknetBlocksTable::reorg(tx, reorg_tail).unwrap();

    //                 let expected = StarknetBlock {
    //                     number: blocks[0].block.number,
    //                     hash: blocks[0].block.hash,
    //                     state_commmitment: blocks[0].block.state_commmitment,
    //                     timestamp: blocks[0].block.timestamp,
    //                     gas_price: blocks[0].block.gas_price,
    //                     sequencer_address: blocks[0].block.sequencer_address,
    //                     transaction_commitment: Some(TransactionCommitment(Felt::ZERO)),
    //                     event_commitment: Some(EventCommitment(Felt::ZERO)),
    //                 };

    //                 assert_eq!(
    //                     StarknetBlocksTable::get(tx, BlockId::Latest).unwrap(),
    //                     Some(expected)
    //                 );
    //             })
    //         }
    //     }

    //     mod interned_version {
    //         use super::super::Storage;
    //         use super::StarknetBlocksTable;
    //         use pathfinder_common::{ClassCommitment, StarknetVersion, StorageCommitment};

    //         #[test]
    //         fn duplicate_versions_interned() {
    //             let storage = Storage::in_memory().unwrap();
    //             let mut connection = storage.connection().unwrap();
    //             let tx = connection.transaction().unwrap();

    //             let blocks = super::create_blocks();
    //             let versions = [StarknetVersion::new(0, 9, 1), StarknetVersion::new(0, 9, 1)]
    //                 .into_iter()
    //                 .chain(std::iter::repeat(StarknetVersion::new(0, 9, 2)));

    //             let mut inserted = 0;

    //             for (block, version) in blocks.iter().zip(versions) {
    //                 StarknetBlocksTable::insert(
    //                     &tx,
    //                     &block.block,
    //                     &version,
    //                     StorageCommitment::ZERO,
    //                     ClassCommitment::ZERO,
    //                 )
    //                 .unwrap();
    //                 inserted += 1;
    //             }

    //             let rows = tx.prepare("select version_id, count(1) from starknet_blocks group by version_id order by version_id")
    //                 .unwrap()
    //                 .query([])
    //                 .unwrap()
    //                 .mapped(|r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, i64>(1)?)))
    //                 .collect::<Result<Vec<(Option<i64>, i64)>, _>>()
    //                 .unwrap();

    //             // there should be two of 0.9.1
    //             assert_eq!(rows.first(), Some(&(Some(1), 2)));

    //             // there should be a few for 0.9.2 (initially the create_rows returned 3 => 1)
    //             assert_eq!(rows.last(), Some(&(Some(2), inserted - 2)));

    //             // we should not have any nulls
    //             assert_eq!(rows.len(), 2, "nulls were not expected in {rows:?}");
    //         }
    //     }

    //     mod get_latest_number {
    //         use super::*;

    //         #[test]
    //         fn some() {
    //             with_default_blocks(|tx, blocks| {
    //                 let latest = blocks.last().unwrap().block.number;
    //                 assert_eq!(
    //                     StarknetBlocksTable::get_latest_number(tx).unwrap(),
    //                     Some(latest)
    //                 );
    //             });
    //         }

    //         #[test]
    //         fn none() {
    //             let storage = Storage::in_memory().unwrap();
    //             let mut connection = storage.connection().unwrap();
    //             let tx = connection.transaction().unwrap();

    //             assert_eq!(StarknetBlocksTable::get_latest_number(&tx).unwrap(), None);
    //         }
    //     }

    //     mod get_latest_hash_and_number {
    //         use super::*;

    //         #[test]
    //         fn some() {
    //             with_default_blocks(|tx, blocks| {
    //                 let latest = &blocks.last().unwrap().block;
    //                 assert_eq!(
    //                     StarknetBlocksTable::get_latest_hash_and_number(tx).unwrap(),
    //                     Some((latest.hash, latest.number))
    //                 );
    //             });
    //         }

    //         #[test]
    //         fn none() {
    //             let storage = Storage::in_memory().unwrap();
    //             let mut connection = storage.connection().unwrap();
    //             let tx = connection.transaction().unwrap();

    //             assert_eq!(
    //                 StarknetBlocksTable::get_latest_hash_and_number(&tx).unwrap(),
    //                 None
    //             );
    //         }
    //     }

    //     mod get_hash {
    //         use super::*;

    //         mod by_number {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     for block in blocks {
    //                         let result =
    //                             StarknetBlocksTable::get_hash(tx, block.block.number.into())
    //                                 .unwrap()
    //                                 .unwrap();

    //                         assert_eq!(result, block.block.hash);
    //                     }
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let non_existent = blocks.last().unwrap().block.number + 1;
    //                     assert_eq!(
    //                         StarknetBlocksTable::get(tx, non_existent.into()).unwrap(),
    //                         None
    //                     );
    //                 });
    //             }
    //         }

    //         mod latest {
    //             use super::*;

    //             #[test]
    //             fn some() {
    //                 with_default_blocks(|tx, blocks| {
    //                     let expected = blocks.last().unwrap().block.hash;

    //                     let latest =
    //                         StarknetBlocksTable::get_hash(tx, StarknetBlocksNumberOrLatest::Latest)
    //                             .unwrap()
    //                             .unwrap();
    //                     assert_eq!(latest, expected);
    //                 })
    //             }

    //             #[test]
    //             fn none() {
    //                 let storage = Storage::in_memory().unwrap();
    //                 let mut connection = storage.connection().unwrap();
    //                 let tx = connection.transaction().unwrap();

    //                 let latest = StarknetBlocksTable::get(&tx, BlockId::Latest).unwrap();
    //                 assert_eq!(latest, None);
    //             }
    //         }
    //     }
    // }

    // mod starknet_events {
    //     use super::*;
    //     use crate::test_utils;
    //     use assert_matches::assert_matches;
    //     use pathfinder_common::felt;
    //     use pathfinder_common::{EntryPoint, EventData, Fee};

    //     #[test]
    //     fn event_data_serialization() {
    //         let data = [
    //             EventData(felt!("0x1")),
    //             EventData(felt!("0x2")),
    //             EventData(felt!("0x3")),
    //         ];

    //         let mut buffer = Vec::new();
    //         StarknetEventsTable::encode_event_data_to_bytes(&data, &mut buffer);

    //         assert_eq!(
    //             &buffer,
    //             &[
    //                 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //                 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
    //             ]
    //         );
    //     }

    //     #[test]
    //     fn event_keys_to_base64_strings() {
    //         let event = transaction::Event {
    //             from_address: ContractAddress::new_or_panic(felt!(
    //                 "06fbd460228d843b7fbef670ff15607bf72e19fa94de21e29811ada167b4ca39"
    //             )),
    //             data: vec![],
    //             keys: vec![
    //                 EventKey(felt!("0x901823")),
    //                 EventKey(felt!("0x901824")),
    //                 EventKey(felt!("0x901825")),
    //             ],
    //         };

    //         let mut buf = String::new();
    //         StarknetEventsTable::event_keys_to_base64_strings(&event.keys, &mut buf);
    //         assert_eq!(buf.capacity(), buf.len());
    //         assert_eq!(
    //             buf,
    //             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCM= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCQ= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQGCU="
    //         );
    //     }

    //     #[test]
    //     fn get_events_with_fully_specified_filter() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_event = &emitted_events[1];
    //         let filter = StarknetEventFilter {
    //             from_block: Some(expected_event.block_number),
    //             to_block: Some(expected_event.block_number),
    //             contract_address: Some(expected_event.from_address),
    //             // we're using a key which is present in _all_ events
    //             keys: V02KeyFilter(vec![EventKey(felt!("0xdeadbeef"))]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![expected_event.clone()],
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn events_are_ordered() {
    //         // This is a regression test where events were incorrectly ordered by transaction hash
    //         // instead of transaction index.
    //         //
    //         // Events should be ordered by block number, transaction index, event index.
    //         use pathfinder_common::TransactionHash;

    //         // All events we are storing, arbitrarily use from_address to distinguish them.
    //         let expected_events = (0u8..5)
    //             .map(|idx| transaction::Event {
    //                 data: Vec::new(),
    //                 keys: Vec::new(),
    //                 from_address: ContractAddress::new_or_panic(
    //                     Felt::from_be_slice(&idx.to_be_bytes()).unwrap(),
    //                 ),
    //             })
    //             .collect::<Vec<_>>();

    //         let block = StarknetBlock {
    //             number: BlockNumber::GENESIS,
    //             hash: BlockHash(felt!("0x1234")),
    //             state_commmitment: StateCommitment(felt!("0x1234")),
    //             timestamp: BlockTimestamp::new_or_panic(0),
    //             gas_price: GasPrice(0),
    //             sequencer_address: SequencerAddress(felt!("0x1234")),
    //             transaction_commitment: None,
    //             event_commitment: None,
    //         };

    //         // Note: hashes are reverse ordered to trigger the sorting bug.
    //         let transactions = vec![
    //             transaction::Transaction::Invoke(transaction::InvokeTransaction::V0(
    //                 transaction::InvokeTransactionV0 {
    //                     calldata: vec![],
    //                     // Only required because event insert rejects if this is None
    //                     sender_address: ContractAddress::new_or_panic(Felt::ZERO),
    //                     entry_point_type: Some(transaction::EntryPointType::External),
    //                     entry_point_selector: EntryPoint(Felt::ZERO),
    //                     max_fee: Fee::ZERO,
    //                     signature: vec![],
    //                     transaction_hash: TransactionHash(felt!("0xF")),
    //                 },
    //             )),
    //             transaction::Transaction::Invoke(transaction::InvokeTransaction::V0(
    //                 transaction::InvokeTransactionV0 {
    //                     calldata: vec![],
    //                     // Only required because event insert rejects if this is None
    //                     sender_address: ContractAddress::new_or_panic(Felt::ZERO),
    //                     entry_point_type: Some(transaction::EntryPointType::External),
    //                     entry_point_selector: EntryPoint(Felt::ZERO),
    //                     max_fee: Fee::ZERO,
    //                     signature: vec![],
    //                     transaction_hash: TransactionHash(felt!("0x1")),
    //                 },
    //             )),
    //         ];

    //         let receipts = vec![
    //             transaction::Receipt {
    //                 actual_fee: None,
    //                 events: expected_events[..3].to_vec(),
    //                 execution_resources: Some(transaction::ExecutionResources {
    //                     builtin_instance_counter:
    //                         transaction::execution_resources::BuiltinInstanceCounter::Empty(
    //                             transaction::execution_resources::EmptyBuiltinInstanceCounter {},
    //                         ),
    //                     n_steps: 0,
    //                     n_memory_holes: 0,
    //                 }),
    //                 l1_to_l2_consumed_message: None,
    //                 l2_to_l1_messages: Vec::new(),
    //                 transaction_hash: transactions[0].hash(),
    //                 transaction_index: pathfinder_common::TransactionIndex::new_or_panic(0),
    //             },
    //             transaction::Receipt {
    //                 actual_fee: None,
    //                 events: expected_events[3..].to_vec(),
    //                 execution_resources: Some(transaction::ExecutionResources {
    //                     builtin_instance_counter:
    //                         transaction::execution_resources::BuiltinInstanceCounter::Empty(
    //                             transaction::execution_resources::EmptyBuiltinInstanceCounter {},
    //                         ),
    //                     n_steps: 0,
    //                     n_memory_holes: 0,
    //                 }),
    //                 l1_to_l2_consumed_message: None,
    //                 l2_to_l1_messages: Vec::new(),
    //                 transaction_hash: transactions[1].hash(),
    //                 transaction_index: pathfinder_common::TransactionIndex::new_or_panic(1),
    //             },
    //         ];

    //         let storage = Storage::in_memory().unwrap();
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         StarknetBlocksTable::insert(
    //             &tx,
    //             &block,
    //             &StarknetVersion::default(),
    //             StorageCommitment::ZERO,
    //             ClassCommitment::ZERO,
    //         )
    //         .unwrap();
    //         CanonicalBlocksTable::insert(&tx, block.number, block.hash).unwrap();
    //         StarknetTransactionsTable::upsert(
    //             &tx,
    //             block.hash,
    //             block.number,
    //             &vec![
    //                 (transactions[0].clone(), receipts[0].clone()),
    //                 (transactions[1].clone(), receipts[1].clone()),
    //             ],
    //         )
    //         .unwrap();

    //         let addresses = StarknetEventsTable::get_events(
    //             &tx,
    //             &StarknetEventFilter {
    //                 from_block: None,
    //                 to_block: None,
    //                 contract_address: None,
    //                 keys: V02KeyFilter(vec![]),
    //                 page_size: 1024,
    //                 offset: 0,
    //             },
    //         )
    //         .unwrap()
    //         .events
    //         .iter()
    //         .map(|e| e.from_address)
    //         .collect::<Vec<_>>();

    //         let expected = expected_events
    //             .iter()
    //             .map(|e| e.from_address)
    //             .collect::<Vec<_>>();

    //         assert_eq!(addresses, expected);
    //     }

    //     #[test]
    //     fn get_events_by_block() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         const BLOCK_NUMBER: usize = 2;
    //         let filter = StarknetEventFilter {
    //             from_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64)),
    //             to_block: Some(BlockNumber::new_or_panic(BLOCK_NUMBER as u64)),
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let expected_events = &emitted_events[test_utils::EVENTS_PER_BLOCK * BLOCK_NUMBER
    //             ..test_utils::EVENTS_PER_BLOCK * (BLOCK_NUMBER + 1)];
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events.to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_up_to_block() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         const UNTIL_BLOCK_NUMBER: usize = 2;
    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: Some(BlockNumber::new_or_panic(UNTIL_BLOCK_NUMBER as u64)),
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let expected_events =
    //             &emitted_events[..test_utils::EVENTS_PER_BLOCK * (UNTIL_BLOCK_NUMBER + 1)];
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events.to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_from_block_onwards() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         const FROM_BLOCK_NUMBER: usize = 2;
    //         let filter = StarknetEventFilter {
    //             from_block: Some(BlockNumber::new_or_panic(FROM_BLOCK_NUMBER as u64)),
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let expected_events =
    //             &emitted_events[test_utils::EVENTS_PER_BLOCK * FROM_BLOCK_NUMBER..];
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events.to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_from_contract() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_event = &emitted_events[33];

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: Some(expected_event.from_address),
    //             keys: V02KeyFilter(vec![]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![expected_event.clone()],
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_by_key_v02() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_event = &emitted_events[27];
    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![expected_event.keys[0]]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![expected_event.clone()],
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_by_key_v03() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_event = &emitted_events[27];
    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V03KeyFilter(vec![
    //                 vec![expected_event.keys[0]],
    //                 vec![expected_event.keys[1]],
    //             ]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![expected_event.clone()],
    //                 is_last_page: true,
    //             }
    //         );

    //         // try event keys in the wrong order, should not match
    //         let filter = StarknetEventFilter {
    //             keys: V03KeyFilter(vec![
    //                 vec![expected_event.keys[1]],
    //                 vec![expected_event.keys[0]],
    //             ]),
    //             ..filter
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![],
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_with_no_filter() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: test_utils::NUM_EVENTS,
    //             offset: 0,
    //         };

    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: emitted_events,
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_with_no_filter_and_paging() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: 10,
    //             offset: 0,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: emitted_events[..10].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: 10,
    //             offset: 10,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: emitted_events[10..20].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: 10,
    //             offset: 30,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: emitted_events[30..40].to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_with_no_filter_and_nonexistent_page() {
    //         let (storage, _) = test_utils::setup_test_storage();
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         const PAGE_SIZE: usize = 10;
    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: PAGE_SIZE,
    //             // _after_ the last one
    //             offset: test_utils::NUM_BLOCKS * test_utils::EVENTS_PER_BLOCK,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: vec![],
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_with_invalid_page_size() {
    //         let (storage, _) = test_utils::setup_test_storage();
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: 0,
    //             offset: 0,
    //         };
    //         let result = StarknetEventsTable::get_events(&tx, &filter);
    //         assert!(result.is_err());
    //         assert_eq!(result.unwrap_err().to_string(), "Invalid page size");

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: V02KeyFilter(vec![]),
    //             page_size: StarknetEventsTable::PAGE_SIZE_LIMIT + 1,
    //             offset: 0,
    //         };
    //         let result = StarknetEventsTable::get_events(&tx, &filter);
    //         assert!(result.is_err());
    //         assert_eq!(
    //             result.unwrap_err().downcast::<EventFilterError>().unwrap(),
    //             EventFilterError::PageSizeTooBig(StarknetEventsTable::PAGE_SIZE_LIMIT)
    //         );
    //     }

    //     #[test]
    //     fn get_events_by_key_v02_with_paging() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_events = &emitted_events[27..32];
    //         let keys_for_expected_events =
    //             V02KeyFilter(expected_events.iter().map(|e| e.keys[0]).collect());

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events.clone(),
    //             page_size: 2,
    //             offset: 0,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[..2].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events.clone(),
    //             page_size: 2,
    //             offset: 2,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[2..4].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events,
    //             page_size: 2,
    //             offset: 4,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[4..].to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn get_events_by_key_v03_with_paging() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let expected_events = &emitted_events[27..32];
    //         let keys_for_expected_events = V03KeyFilter(vec![
    //             expected_events.iter().map(|e| e.keys[0]).collect(),
    //             expected_events.iter().map(|e| e.keys[1]).collect(),
    //         ]);

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events.clone(),
    //             page_size: 2,
    //             offset: 0,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[..2].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events.clone(),
    //             page_size: 2,
    //             offset: 2,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[2..4].to_vec(),
    //                 is_last_page: false,
    //             }
    //         );

    //         let filter = StarknetEventFilter {
    //             from_block: None,
    //             to_block: None,
    //             contract_address: None,
    //             keys: keys_for_expected_events,
    //             page_size: 2,
    //             offset: 4,
    //         };
    //         let events = StarknetEventsTable::get_events(&tx, &filter).unwrap();
    //         assert_eq!(
    //             events,
    //             PageOfEvents {
    //                 events: expected_events[4..].to_vec(),
    //                 is_last_page: true,
    //             }
    //         );
    //     }

    //     #[test]
    //     fn event_count_by_block() {
    //         let (storage, _) = test_utils::setup_test_storage();
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let block = Some(BlockNumber::new_or_panic(2));

    //         let count =
    //             StarknetEventsTable::event_count(&tx, block, block, None, &V02KeyFilter(vec![]))
    //                 .unwrap();
    //         assert_eq!(count, test_utils::EVENTS_PER_BLOCK);
    //     }

    //     #[test]
    //     fn event_count_from_contract() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let addr = events[0].from_address;
    //         let expected = events
    //             .iter()
    //             .filter(|event| event.from_address == addr)
    //             .count();

    //         let count = StarknetEventsTable::event_count(
    //             &tx,
    //             Some(BlockNumber::GENESIS),
    //             Some(BlockNumber::MAX),
    //             Some(addr),
    //             &V02KeyFilter(vec![]),
    //         )
    //         .unwrap();
    //         assert_eq!(count, expected);
    //     }

    //     #[test]
    //     fn event_count_by_key() {
    //         let (storage, test_data) = test_utils::setup_test_storage();
    //         let emitted_events = test_data.events;
    //         let mut connection = storage.connection().unwrap();
    //         let tx = connection.transaction().unwrap();

    //         let key = emitted_events[27].keys[0];
    //         let expected = emitted_events
    //             .iter()
    //             .filter(|event| event.keys.contains(&key))
    //             .count();

    //         let count = StarknetEventsTable::event_count(
    //             &tx,
    //             Some(BlockNumber::GENESIS),
    //             Some(BlockNumber::MAX),
    //             None,
    //             &V02KeyFilter(vec![key]),
    //         )
    //         .unwrap();
    //         assert_eq!(count, expected);
    //     }

    //     #[test]
    //     fn v03_key_filter() {
    //         check_v03_filter(vec![], None);
    //         check_v03_filter(vec![vec![], vec![]], None);
    //         check_v03_filter(
    //             vec![
    //                 vec![],
    //                 vec![EventKey(felt!("01")), EventKey(felt!("02"))],
    //                 vec![],
    //                 vec![EventKey(felt!("01")), EventKey(felt!("03"))],
    //                 vec![],
    //             ],
    //             Some("(\"AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\" OR \"AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE\") AND (\"AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\" OR \"AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG\")"),
    //         );
    //     }

    //     fn check_v03_filter(filter: Vec<Vec<EventKey>>, expected_fts_expression: Option<&str>) {
    //         let mut fts_expression = String::new();
    //         let filter = V03KeyFilter(filter);
    //         let result = filter.apply(&mut fts_expression);

    //         match expected_fts_expression {
    //             Some(expected_fts_expression) => assert_matches!(
    //                 result,
    //                 Some(result) => {assert_eq!(result, KeyFilterResult { base_query: " CROSS JOIN starknet_events_keys_03 ON starknet_events.rowid = starknet_events_keys_03.rowid",
    //                  where_statement: "starknet_events_keys_03.keys MATCH :events_match", param: (":events_match", expected_fts_expression) })}
    //             ),
    //             None => assert_eq!(result, None),
    //         }
    //     }
    // }
}
