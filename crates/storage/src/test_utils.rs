use crate::EmittedEvent;

use super::Storage;
use pathfinder_common::macro_prelude::*;
use pathfinder_common::{
    BlockHash, BlockHeader, BlockNumber, BlockTimestamp, CallParam, ClassCommitment, ClassHash,
    ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint, EventCommitment, EventData,
    EventKey, Fee, GasPrice, SequencerAddress, StorageCommitment, TransactionCommitment,
    TransactionHash, TransactionIndex, TransactionNonce, TransactionSignatureElem,
    TransactionVersion,
};
use primitive_types::H256;
use stark_hash::Felt;
use starknet_gateway_types::reply::transaction::{
    self, DeclareTransaction, DeclareTransactionV0V1, DeployTransaction, EntryPointType,
    InvokeTransaction, InvokeTransactionV0, Receipt,
};

pub const NUM_BLOCKS: usize = 4;
pub const TRANSACTIONS_PER_BLOCK: usize = 15;
const INVOKE_TRANSACTIONS_PER_BLOCK: usize = 5;
const DEPLOY_TRANSACTIONS_PER_BLOCK: usize = 5;
const DECLARE_TRANSACTIONS_PER_BLOCK: usize =
    TRANSACTIONS_PER_BLOCK - (INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK);
pub const EVENTS_PER_BLOCK: usize = INVOKE_TRANSACTIONS_PER_BLOCK + DECLARE_TRANSACTIONS_PER_BLOCK;
pub const NUM_TRANSACTIONS: usize = NUM_BLOCKS * TRANSACTIONS_PER_BLOCK;
pub const NUM_EVENTS: usize = NUM_BLOCKS * EVENTS_PER_BLOCK;

/// Creates a set of consecutive [BlockHeader]s starting from L2 genesis,
/// with arbitrary other values.
pub(crate) fn create_blocks() -> [BlockHeader; NUM_BLOCKS] {
    (0..NUM_BLOCKS)
        .map(|i| {
            let storage_commitment =
                StorageCommitment(Felt::from_hex_str(&"b".repeat(i + 3)).unwrap());
            let class_commitment = ClassCommitment(Felt::from_hex_str(&"c".repeat(i + 3)).unwrap());
            let index_as_felt = Felt::from_be_slice(&[i as u8]).unwrap();

            BlockHeader::builder()
                .with_number(BlockNumber::GENESIS + i as u64)
                .with_timestamp(BlockTimestamp::new_or_panic(i as u64 + 500))
                .with_class_commitment(class_commitment)
                .with_storage_commitment(storage_commitment)
                .with_calculated_state_commitment()
                .with_gas_price(GasPrice::from(i as u64))
                .with_sequencer_address(SequencerAddress(index_as_felt))
                .with_transaction_commitment(TransactionCommitment(index_as_felt))
                .with_event_commitment(EventCommitment(index_as_felt))
                .finalize_with_hash(BlockHash(Felt::from_hex_str(&"a".repeat(i + 3)).unwrap()))
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Creates a set of test transactions and receipts.
pub(crate) fn create_transactions_and_receipts(
) -> [(transaction::Transaction, transaction::Receipt); NUM_TRANSACTIONS] {
    let transactions = (0..NUM_TRANSACTIONS).map(|i| match i % TRANSACTIONS_PER_BLOCK {
        x if x < INVOKE_TRANSACTIONS_PER_BLOCK => {
            transaction::Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                calldata: vec![CallParam(Felt::from_hex_str(&"0".repeat(i + 3)).unwrap())],
                sender_address: ContractAddress::new_or_panic(
                    Felt::from_hex_str(&"1".repeat(i + 3)).unwrap(),
                ),
                entry_point_selector: EntryPoint(Felt::from_hex_str(&"2".repeat(i + 3)).unwrap()),
                entry_point_type: Some(if i & 1 == 0 {
                    EntryPointType::External
                } else {
                    EntryPointType::L1Handler
                }),
                max_fee: Fee::ZERO,
                signature: vec![TransactionSignatureElem(
                    Felt::from_hex_str(&"3".repeat(i + 3)).unwrap(),
                )],
                transaction_hash: TransactionHash(Felt::from_hex_str(&"4".repeat(i + 3)).unwrap()),
            }))
        }
        x if (INVOKE_TRANSACTIONS_PER_BLOCK
            ..INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK)
            .contains(&x) =>
        {
            transaction::Transaction::Deploy(DeployTransaction {
                contract_address: ContractAddress::new_or_panic(
                    Felt::from_hex_str(&"5".repeat(i + 3)).unwrap(),
                ),
                contract_address_salt: ContractAddressSalt(
                    Felt::from_hex_str(&"6".repeat(i + 3)).unwrap(),
                ),
                class_hash: ClassHash(Felt::from_hex_str(&"7".repeat(i + 3)).unwrap()),
                constructor_calldata: vec![ConstructorParam(
                    Felt::from_hex_str(&"8".repeat(i + 3)).unwrap(),
                )],
                transaction_hash: TransactionHash(Felt::from_hex_str(&"9".repeat(i + 3)).unwrap()),
                version: TransactionVersion(H256::zero()),
            })
        }
        _ => transaction::Transaction::Declare(DeclareTransaction::V0(DeclareTransactionV0V1 {
            class_hash: ClassHash(Felt::from_hex_str(&"a".repeat(i + 3)).unwrap()),
            max_fee: Fee::ZERO,
            nonce: TransactionNonce(Felt::from_hex_str(&"b".repeat(i + 3)).unwrap()),
            sender_address: ContractAddress::new_or_panic(
                Felt::from_hex_str(&"c".repeat(i + 3)).unwrap(),
            ),
            signature: vec![TransactionSignatureElem(
                Felt::from_hex_str(&"d".repeat(i + 3)).unwrap(),
            )],
            transaction_hash: TransactionHash(Felt::from_hex_str(&"e".repeat(i + 3)).unwrap()),
        })),
    });

    let tx_receipt = transactions.enumerate().map(|(i, tx)| {
        let receipt = transaction::Receipt {
            actual_fee: None,
            events: if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                vec![pathfinder_common::event::Event {
                    from_address: ContractAddress::new_or_panic(
                        Felt::from_hex_str(&"2".repeat(i + 3)).unwrap(),
                    ),
                    data: vec![EventData(Felt::from_hex_str(&"c".repeat(i + 3)).unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str(&"d".repeat(i + 3)).unwrap()),
                        event_key!("0xdeadbeef"),
                    ],
                }]
            } else {
                vec![]
            },
            execution_resources: Some(transaction::ExecutionResources {
                builtin_instance_counter: Default::default(),
                n_steps: i as u64 + 987,
                n_memory_holes: i as u64 + 1177,
            }),
            l1_to_l2_consumed_message: None,
            l2_to_l1_messages: Vec::new(),
            transaction_hash: tx.hash(),
            transaction_index: TransactionIndex::new_or_panic(i as u64 + 2311),
            execution_status: Default::default(),
            revert_error: Default::default(),
        };

        (tx, receipt)
    });

    tx_receipt.collect::<Vec<_>>().try_into().unwrap()
}

/// Creates a set of emitted events from given blocks and transactions.
pub(crate) fn extract_events(
    blocks: &[BlockHeader],
    transactions_and_receipts: &[(transaction::Transaction, transaction::Receipt)],
) -> Vec<EmittedEvent> {
    transactions_and_receipts
        .iter()
        .enumerate()
        .filter_map(|(i, (txn, receipt))| {
            if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                let event = &receipt.events[0];
                let block = &blocks[i / TRANSACTIONS_PER_BLOCK];

                Some(EmittedEvent {
                    data: event.data.clone(),
                    from_address: event.from_address,
                    keys: event.keys.clone(),
                    block_hash: block.hash,
                    block_number: block.number,
                    transaction_hash: txn.hash(),
                })
            } else {
                None
            }
        })
        .collect()
}

pub struct TestData {
    pub headers: Vec<BlockHeader>,
    pub transactions: Vec<transaction::Transaction>,
    pub receipts: Vec<Receipt>,
    pub events: Vec<EmittedEvent>,
}

// Creates a storage instance in memory with a set of expected emitted event
pub fn setup_test_storage() -> (Storage, TestData) {
    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    let headers = create_blocks();
    let transactions_and_receipts = create_transactions_and_receipts();

    for (i, header) in headers.iter().enumerate() {
        tx.insert_block_header(header).unwrap();
        tx.insert_transaction_data(
            header.hash,
            header.number,
            &transactions_and_receipts
                [i * TRANSACTIONS_PER_BLOCK..(i + 1) * TRANSACTIONS_PER_BLOCK],
        )
        .unwrap();
    }

    tx.commit().unwrap();

    let events = extract_events(&headers, &transactions_and_receipts);
    let (transactions, receipts): (Vec<_>, Vec<_>) = transactions_and_receipts.into_iter().unzip();

    (
        storage,
        TestData {
            headers: headers.to_vec(),
            transactions,
            receipts,
            events,
        },
    )
}
