use super::{
    StarknetBlock, StarknetBlocksTable, StarknetEmittedEvent, StarknetTransactionsTable, Storage,
};
use ethers::types::{H128, H256};
use pathfinder_common::{
    felt, CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
    EventData, EventKey, Fee, GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash,
    StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash, StarknetTransactionIndex,
    TransactionNonce, TransactionSignatureElem, TransactionVersion,
};
use stark_hash::Felt;
use starknet_gateway_types::reply::transaction::{
    self, DeclareTransaction, DeployTransaction, EntryPointType, InvokeTransaction,
    InvokeTransactionV0,
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

/// Creates a set of consecutive [StarknetBlock]s starting from L2 genesis,
/// with arbitrary other values.
pub(crate) fn create_blocks() -> [StarknetBlock; NUM_BLOCKS] {
    (0..NUM_BLOCKS)
        .map(|i| StarknetBlock {
            number: StarknetBlockNumber::GENESIS + i as u64,
            hash: StarknetBlockHash(Felt::from_hex_str(&"a".repeat(i + 3)).unwrap()),
            root: GlobalRoot(Felt::from_hex_str(&"f".repeat(i + 3)).unwrap()),
            timestamp: StarknetBlockTimestamp::new_or_panic(i as u64 + 500),
            gas_price: GasPrice::from(i as u64),
            sequencer_address: SequencerAddress(Felt::from_be_slice(&[i as u8]).unwrap()),
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
                contract_address: ContractAddress::new_or_panic(
                    Felt::from_hex_str(&"1".repeat(i + 3)).unwrap(),
                ),
                entry_point_selector: EntryPoint(Felt::from_hex_str(&"2".repeat(i + 3)).unwrap()),
                entry_point_type: Some(if i & 1 == 0 {
                    EntryPointType::External
                } else {
                    EntryPointType::L1Handler
                }),
                max_fee: Fee(H128::zero()),
                signature: vec![TransactionSignatureElem(
                    Felt::from_hex_str(&"3".repeat(i + 3)).unwrap(),
                )],
                transaction_hash: StarknetTransactionHash(
                    Felt::from_hex_str(&"4".repeat(i + 3)).unwrap(),
                ),
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
                transaction_hash: StarknetTransactionHash(
                    Felt::from_hex_str(&"9".repeat(i + 3)).unwrap(),
                ),
                version: TransactionVersion(ethers::types::H256::zero()),
            })
        }
        _ => transaction::Transaction::Declare(DeclareTransaction {
            class_hash: ClassHash(Felt::from_hex_str(&"a".repeat(i + 3)).unwrap()),
            max_fee: Fee(H128::zero()),
            nonce: TransactionNonce(Felt::from_hex_str(&"b".repeat(i + 3)).unwrap()),
            sender_address: ContractAddress::new_or_panic(
                Felt::from_hex_str(&"c".repeat(i + 3)).unwrap(),
            ),
            signature: vec![TransactionSignatureElem(
                Felt::from_hex_str(&"d".repeat(i + 3)).unwrap(),
            )],
            transaction_hash: StarknetTransactionHash(
                Felt::from_hex_str(&"e".repeat(i + 3)).unwrap(),
            ),
            version: TransactionVersion(H256::zero()),
        }),
    });

    let tx_receipt = transactions.enumerate().map(|(i, tx)| {
        let receipt = transaction::Receipt {
            actual_fee: None,
            events: if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                vec![transaction::Event {
                    from_address: ContractAddress::new_or_panic(
                        Felt::from_hex_str(&"2".repeat(i + 3)).unwrap(),
                    ),
                    data: vec![EventData(Felt::from_hex_str(&"c".repeat(i + 3)).unwrap())],
                    keys: vec![
                        EventKey(Felt::from_hex_str(&"d".repeat(i + 3)).unwrap()),
                        EventKey(felt!("0xdeadbeef")),
                    ],
                }]
            } else {
                vec![]
            },
            execution_resources: Some(transaction::ExecutionResources {
                builtin_instance_counter:
                    transaction::execution_resources::BuiltinInstanceCounter::Empty(
                        transaction::execution_resources::EmptyBuiltinInstanceCounter {},
                    ),
                n_steps: i as u64 + 987,
                n_memory_holes: i as u64 + 1177,
            }),
            l1_to_l2_consumed_message: None,
            l2_to_l1_messages: Vec::new(),
            transaction_hash: tx.hash(),
            transaction_index: StarknetTransactionIndex::new_or_panic(i as u64 + 2311),
        };

        (tx, receipt)
    });

    tx_receipt.collect::<Vec<_>>().try_into().unwrap()
}

/// Creates a set of emitted events from given blocks and transactions.
pub(crate) fn extract_events(
    blocks: &[StarknetBlock],
    transactions_and_receipts: &[(transaction::Transaction, transaction::Receipt)],
) -> Vec<StarknetEmittedEvent> {
    transactions_and_receipts
        .iter()
        .enumerate()
        .filter_map(|(i, (txn, receipt))| {
            if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                let event = &receipt.events[0];
                let block = &blocks[i / TRANSACTIONS_PER_BLOCK];

                Some(StarknetEmittedEvent {
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

/// Creates a storage instance in memory with a set of expected emitted events
pub fn setup_test_storage() -> (Storage, Vec<StarknetEmittedEvent>) {
    use crate::CanonicalBlocksTable;

    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    let blocks = create_blocks();
    let transactions_and_receipts = create_transactions_and_receipts();

    for (i, block) in blocks.iter().enumerate() {
        StarknetBlocksTable::insert(&tx, block, None).unwrap();
        CanonicalBlocksTable::insert(&tx, block.number, block.hash).unwrap();
        StarknetTransactionsTable::upsert(
            &tx,
            block.hash,
            block.number,
            &transactions_and_receipts
                [i * TRANSACTIONS_PER_BLOCK..(i + 1) * TRANSACTIONS_PER_BLOCK],
        )
        .unwrap();
    }

    tx.commit().unwrap();

    let events = extract_events(&blocks, &transactions_and_receipts);

    (storage, events)
}
