use pathfinder_common::event::Event;
use pathfinder_common::macro_prelude::*;
use pathfinder_common::receipt::{ExecutionResources, L1Gas, Receipt};
use pathfinder_common::transaction::{
    DeclareTransactionV0V1,
    DeployTransactionV0,
    EntryPointType,
    InvokeTransactionV0,
    Transaction,
    TransactionVariant,
};
use pathfinder_common::*;
use pathfinder_crypto::Felt;

use crate::EmittedEvent;

pub const NUM_BLOCKS: usize = 4;
pub const TRANSACTIONS_PER_BLOCK: usize = 15;
const INVOKE_TRANSACTIONS_PER_BLOCK: usize = 5;
const DEPLOY_TRANSACTIONS_PER_BLOCK: usize = 5;
const DECLARE_TRANSACTIONS_PER_BLOCK: usize =
    TRANSACTIONS_PER_BLOCK - (INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK);
pub const EVENTS_PER_BLOCK: usize = INVOKE_TRANSACTIONS_PER_BLOCK + DECLARE_TRANSACTIONS_PER_BLOCK;
pub const NUM_TRANSACTIONS: usize = NUM_BLOCKS * TRANSACTIONS_PER_BLOCK;
pub const NUM_EVENTS: usize = NUM_BLOCKS * EVENTS_PER_BLOCK;

/// Creates a custom set of [BlockHeader]s with arbitrary values.
pub(crate) fn create_blocks(n_blocks: usize) -> Vec<BlockHeader> {
    (0..n_blocks)
        .map(|block_number| {
            let storage_commitment =
                StorageCommitment(Felt::from_hex_str(&"b".repeat(block_number + 3)).unwrap());
            let class_commitment =
                ClassCommitment(Felt::from_hex_str(&"c".repeat(block_number + 3)).unwrap());
            let index_as_felt = Felt::from_be_slice(&[block_number as u8]).unwrap();

            BlockHeader::builder()
                .number(BlockNumber::GENESIS + block_number as u64)
                .timestamp(BlockTimestamp::new_or_panic(block_number as u64 + 500))
                .calculated_state_commitment(storage_commitment, class_commitment)
                .eth_l1_gas_price(GasPrice::from(block_number as u64))
                .sequencer_address(SequencerAddress(index_as_felt))
                .transaction_commitment(TransactionCommitment(index_as_felt))
                .event_commitment(EventCommitment(index_as_felt))
                .finalize_with_hash(BlockHash(
                    Felt::from_hex_str(&"a".repeat(block_number + 3)).unwrap(),
                ))
        })
        .collect::<Vec<_>>()
}

/// Creates a custom test set of transactions and receipts.
pub(crate) fn create_transactions_and_receipts(
    n_blocks: usize,
    transactions_per_block: usize,
) -> Vec<(Transaction, Receipt, Vec<Event>)> {
    let n_transactions = n_blocks * transactions_per_block;
    assert!(
        n_transactions < 64,
        "Too many transactions ({} > {}), `Felt::from_hex_str()` will overflow.",
        n_transactions,
        64
    );
    let transactions = (0..n_transactions).map(|i| match i % transactions_per_block {
        x if x < INVOKE_TRANSACTIONS_PER_BLOCK => Transaction {
            hash: TransactionHash(Felt::from_hex_str(&"4".repeat(i + 3)).unwrap()),
            variant: TransactionVariant::InvokeV0(InvokeTransactionV0 {
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
            }),
        },
        x if (INVOKE_TRANSACTIONS_PER_BLOCK
            ..INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK)
            .contains(&x) =>
        {
            Transaction {
                hash: TransactionHash(Felt::from_hex_str(&"9".repeat(i + 3)).unwrap()),
                variant: TransactionVariant::DeployV0(DeployTransactionV0 {
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
                }),
            }
        }
        _ => Transaction {
            hash: TransactionHash(Felt::from_hex_str(&"e".repeat(i + 3)).unwrap()),
            variant: TransactionVariant::DeclareV0(DeclareTransactionV0V1 {
                class_hash: ClassHash(Felt::from_hex_str(&"a".repeat(i + 3)).unwrap()),
                max_fee: Fee::ZERO,
                nonce: TransactionNonce(Felt::from_hex_str(&"b".repeat(i + 3)).unwrap()),
                sender_address: ContractAddress::new_or_panic(
                    Felt::from_hex_str(&"c".repeat(i + 3)).unwrap(),
                ),
                signature: vec![TransactionSignatureElem(
                    Felt::from_hex_str(&"d".repeat(i + 3)).unwrap(),
                )],
            }),
        },
    });

    transactions
        .enumerate()
        .map(|(i, tx)| {
            let receipt = Receipt {
                actual_fee: Fee::ZERO,
                execution_resources: ExecutionResources {
                    builtins: Default::default(),
                    n_steps: i as u64 + 987,
                    n_memory_holes: i as u64 + 1177,
                    data_availability: L1Gas {
                        l1_gas: i as u128 + 124,
                        l1_data_gas: i as u128 + 457,
                    },
                    total_gas_consumed: L1Gas {
                        l1_gas: i as u128 + 333,
                        l1_data_gas: i as u128 + 666,
                    },
                    l2_gas: Default::default(),
                },
                transaction_hash: tx.hash,
                transaction_index: TransactionIndex::new_or_panic(
                    (i % transactions_per_block).try_into().unwrap(),
                ),
                ..Default::default()
            };
            let events = if i % transactions_per_block < EVENTS_PER_BLOCK {
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
            };

            (tx, receipt, events)
        })
        .collect::<Vec<_>>()
}

/// Creates a set of emitted events from given blocks and transactions.
pub(crate) fn extract_events(
    blocks: &[BlockHeader],
    transactions: &[(Transaction, Receipt, Vec<Event>)],
    transactions_per_block: usize,
) -> Vec<EmittedEvent> {
    transactions
        .iter()
        .enumerate()
        .filter_map(|(i, (txn, rcpt, events))| {
            if i % transactions_per_block < EVENTS_PER_BLOCK {
                let event = &events[0];
                let block = &blocks[i / transactions_per_block];

                Some(EmittedEvent {
                    data: event.data.clone(),
                    from_address: event.from_address,
                    keys: event.keys.clone(),
                    block_hash: block.hash,
                    block_number: block.number,
                    transaction_hash: txn.hash,
                    transaction_index: rcpt.transaction_index,
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

/// Creates an in-memory storage instance that contains a set of consecutive
/// [BlockHeader]s starting from L2 genesis, with arbitrary other values and a
/// set of expected emitted events.
pub fn setup_test_storage() -> (crate::Storage, TestData) {
    setup_custom_test_storage(NUM_BLOCKS, TRANSACTIONS_PER_BLOCK)
}

// Creates an in-memory storage instance with N blocks and a custom number of
// transactions per block, with a set of expected emitted events.
pub fn setup_custom_test_storage(
    n_blocks: usize,
    transactions_per_block: usize,
) -> (crate::Storage, TestData) {
    let storage = crate::StorageBuilder::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    let headers = create_blocks(n_blocks);
    let transactions_and_receipts =
        create_transactions_and_receipts(n_blocks, transactions_per_block);

    for (i, header) in headers.iter().enumerate() {
        tx.insert_block_header(header).unwrap();
        tx.insert_transaction_data(
            header.number,
            &transactions_and_receipts
                [i * transactions_per_block..(i + 1) * transactions_per_block]
                .iter()
                .cloned()
                .map(|(tx, receipt, ..)| (tx, receipt))
                .collect::<Vec<_>>(),
            Some(
                &transactions_and_receipts
                    [i * transactions_per_block..(i + 1) * transactions_per_block]
                    .iter()
                    .cloned()
                    .map(|(_, _, events)| events)
                    .collect::<Vec<_>>(),
            ),
        )
        .unwrap();
    }

    tx.commit().unwrap();

    let events = extract_events(&headers, &transactions_and_receipts, transactions_per_block);
    let (transactions, receipts): (Vec<_>, Vec<_>) = transactions_and_receipts
        .into_iter()
        .map(|(transaction, receipts, _)| (transaction, receipts))
        .unzip();

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
