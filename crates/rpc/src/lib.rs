//! StarkNet node JSON-RPC related modules.
pub mod cairo;
pub mod context;
mod error;
mod felt;
pub mod gas_price;
pub mod metrics;
mod module;
mod pathfinder;
#[cfg(test)]
pub mod test_client;
pub mod v02;
pub mod v03;

use crate::metrics::middleware::{MaybeRpcMetricsMiddleware, RpcMetricsMiddleware};
use crate::v02::types::syncing::Syncing;
use context::RpcContext;
use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};
use std::{net::SocketAddr, result::Result};
use tokio::sync::RwLock;

pub struct RpcServer {
    addr: SocketAddr,
    context: RpcContext,
    middleware: MaybeRpcMetricsMiddleware,
}

impl RpcServer {
    pub fn new(addr: SocketAddr, context: RpcContext) -> Self {
        Self {
            addr,
            context,
            middleware: MaybeRpcMetricsMiddleware::NoOp,
        }
    }

    pub fn with_middleware(self, middleware: RpcMetricsMiddleware) -> Self {
        Self {
            middleware: MaybeRpcMetricsMiddleware::Middleware(middleware),
            ..self
        }
    }

    /// Starts the HTTP-RPC server.
    pub async fn run(self) -> Result<(HttpServerHandle, SocketAddr), anyhow::Error> {
        let server = HttpServerBuilder::default()
            .set_middleware(self.middleware)
            .build(self.addr)
            .await
            .map_err(|e| match e {
                jsonrpsee::core::Error::Transport(_) => {
                    use std::error::Error;

                    if let Some(inner) = e.source().and_then(|inner| inner.downcast_ref::<std::io::Error>()) {
                        if let std::io::ErrorKind::AddrInUse = inner.kind() {
                            return anyhow::Error::new(e)
                                .context(format!("RPC address is already in use: {}.

Hint: This usually means you are already running another instance of pathfinder.
Hint: If this happens when upgrading, make sure to shut down the first one first.
Hint: If you are looking to run two instances of pathfinder, you must configure them with different http rpc addresses.", self.addr));
                        }
                    }

                    anyhow::Error::new(e)
                }
                _ => anyhow::Error::new(e),
            })?;
        let local_addr = server.local_addr()?;

        let module_v02 = v02::register_methods(self.context.clone())?;
        let pathfinder_module = pathfinder::register_methods(self.context.clone())?;
        let module_v03 = v03::register_methods(self.context)?;

        Ok(server
            .start_with_paths([
                (vec!["/", "/rpc/v0.2"], module_v02),
                (vec!["/rpc/v0.3"], module_v03),
                (vec!["/rpc/pathfinder/v0.1"], pathfinder_module),
            ])
            .map(|handle| (handle, local_addr))?)
    }
}

pub struct SyncState {
    pub status: RwLock<Syncing>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            status: RwLock::new(Syncing::False(false)),
        }
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::H256;
    use pathfinder_common::{
        felt, felt_bytes, ClassCommitment, ClassHash, ContractAddress, ContractAddressSalt,
        EntryPoint, EventData, EventKey, GasPrice, SequencerAddress, StarknetBlockHash,
        StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash,
        StarknetTransactionIndex, StateCommitment, StorageAddress, StorageCommitment,
        TransactionVersion,
    };
    use pathfinder_merkle_tree::state_tree::StorageCommitmentTree;
    use pathfinder_storage::{
        types::CompressedContract, CanonicalBlocksTable, ContractCodeTable, StarknetBlock,
        StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
    };
    use stark_hash::Felt;
    use starknet_gateway_types::{
        pending::PendingData,
        reply::{
            state_update::{ReplacedClass, StorageDiff},
            transaction::{
                execution_resources::{BuiltinInstanceCounter, EmptyBuiltinInstanceCounter},
                DeployTransaction, EntryPointType, Event, ExecutionResources, InvokeTransaction,
                InvokeTransactionV0, Receipt, Transaction,
            },
        },
    };
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    lazy_static::lazy_static! {
        pub static ref LOCALHOST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    }

    // Local test helper
    pub fn setup_storage() -> Storage {
        use ethers::types::H128;
        use pathfinder_common::{ContractNonce, StorageValue};
        use pathfinder_merkle_tree::contract_state::update_contract_state;

        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let db_txn = connection.transaction().unwrap();

        let class_commitment0 = ClassCommitment(felt_bytes!(b"class commitment 0"));
        let class_commitment1 = ClassCommitment(felt_bytes!(b"class commitment 1"));
        let class_commitment2 = ClassCommitment(felt_bytes!(b"class commitment 2"));

        let contract0_addr = ContractAddress::new_or_panic(felt_bytes!(b"contract 0"));
        let contract1_addr = ContractAddress::new_or_panic(felt_bytes!(b"contract 1"));
        let contract2_addr = ContractAddress::new_or_panic(felt_bytes!(b"contract 2 (sierra)"));

        let class0_hash = ClassHash(felt_bytes!(b"class 0 hash"));
        let class1_hash = ClassHash(felt_bytes!(b"class 1 hash"));
        let class2_hash = ClassHash(felt_bytes!(b"class 2 hash (sierra)"));

        let contract0_update = vec![];

        let storage_addr = StorageAddress::new_or_panic(felt_bytes!(b"storage addr 0"));
        let contract1_update0 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(felt_bytes!(b"storage value 0")),
        }];
        let contract1_update1 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(felt_bytes!(b"storage value 1")),
        }];
        let contract1_update2 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(felt_bytes!(b"storage value 2")),
        }];

        let contract_definition =
            starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION.to_vec();
        let contract0_code = CompressedContract {
            definition: contract_definition,
            hash: class0_hash,
        };
        let mut contract1_code = contract0_code.clone();
        contract1_code.hash = class1_hash;
        let sierra_class_definition =
            starknet_gateway_test_fixtures::zstd_compressed_contracts::CAIRO_0_11_SIERRA.to_vec();
        let contract2_code = CompressedContract {
            definition: sierra_class_definition,
            hash: class2_hash,
        };

        ContractCodeTable::insert_compressed(&db_txn, &contract0_code).unwrap();
        ContractCodeTable::insert_compressed(&db_txn, &contract1_code).unwrap();
        ContractCodeTable::insert_compressed(&db_txn, &contract2_code).unwrap();

        let mut storage_commitment_tree =
            StorageCommitmentTree::load(&db_txn, StorageCommitment(Felt::ZERO)).unwrap();
        let contract_state_hash = update_contract_state(
            contract0_addr,
            &contract0_update,
            Some(ContractNonce(felt!("0x1"))),
            Some(class0_hash),
            &storage_commitment_tree,
            &db_txn,
        )
        .unwrap();
        storage_commitment_tree
            .set(contract0_addr, contract_state_hash)
            .unwrap();
        let storage_commitment0 = storage_commitment_tree.apply().unwrap();

        let mut storage_commitment_tree =
            StorageCommitmentTree::load(&db_txn, storage_commitment0).unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update0,
            None,
            Some(class1_hash),
            &storage_commitment_tree,
            &db_txn,
        )
        .unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update1,
            None,
            None,
            &storage_commitment_tree,
            &db_txn,
        )
        .unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let storage_commitment1 = storage_commitment_tree.apply().unwrap();

        let mut storage_commitment_tree =
            StorageCommitmentTree::load(&db_txn, storage_commitment1).unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update2,
            Some(ContractNonce(felt!("0x10"))),
            None,
            &storage_commitment_tree,
            &db_txn,
        )
        .unwrap();
        storage_commitment_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let contract_state_hash = update_contract_state(
            contract2_addr,
            &[],
            Some(ContractNonce(felt!("0xfeed"))),
            Some(class2_hash),
            &storage_commitment_tree,
            &db_txn,
        )
        .unwrap();
        storage_commitment_tree
            .set(contract2_addr, contract_state_hash)
            .unwrap();
        let storage_commitment2 = storage_commitment_tree.apply().unwrap();

        let genesis_hash = StarknetBlockHash(felt_bytes!(b"genesis"));
        let block0 = StarknetBlock {
            number: StarknetBlockNumber::GENESIS,
            hash: genesis_hash,
            root: StateCommitment::calculate(storage_commitment0, class_commitment0),
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(Felt::ZERO),
            transaction_commitment: None,
            event_commitment: None,
        };
        let block1_hash = StarknetBlockHash(felt_bytes!(b"block 1"));
        let block1 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(1),
            hash: block1_hash,
            root: StateCommitment::calculate(storage_commitment1, class_commitment1),
            timestamp: StarknetBlockTimestamp::new_or_panic(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(felt_bytes!(&[1u8])),
            transaction_commitment: None,
            event_commitment: None,
        };
        let latest_hash = StarknetBlockHash(felt_bytes!(b"latest"));
        let block2 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(2),
            hash: latest_hash,
            root: StateCommitment::calculate(storage_commitment2, class_commitment2),
            timestamp: StarknetBlockTimestamp::new_or_panic(2),
            gas_price: GasPrice::from(2),
            sequencer_address: SequencerAddress(felt_bytes!(&[2u8])),
            transaction_commitment: None,
            event_commitment: None,
        };
        StarknetBlocksTable::insert(
            &db_txn,
            &block0,
            None,
            storage_commitment0,
            class_commitment0,
        )
        .unwrap();
        StarknetBlocksTable::insert(
            &db_txn,
            &block1,
            None,
            storage_commitment1,
            class_commitment1,
        )
        .unwrap();
        StarknetBlocksTable::insert(
            &db_txn,
            &block2,
            None,
            storage_commitment2,
            class_commitment2,
        )
        .unwrap();

        CanonicalBlocksTable::insert(&db_txn, block0.number, block0.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block1.number, block1.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block2.number, block2.hash).unwrap();

        ContractCodeTable::update_declared_on_if_null(&db_txn, class0_hash, block1.hash).unwrap();
        ContractCodeTable::update_declared_on_if_null(&db_txn, class2_hash, block2.hash).unwrap();

        let txn0_hash = StarknetTransactionHash(felt_bytes!(b"txn 0"));
        // TODO introduce other types of transactions too
        let txn0 = InvokeTransactionV0 {
            calldata: vec![],
            sender_address: contract0_addr,
            entry_point_type: Some(EntryPointType::External),
            entry_point_selector: EntryPoint(Felt::ZERO),
            max_fee: pathfinder_common::Fee(H128::zero()),
            signature: vec![],
            transaction_hash: txn0_hash,
        };
        let mut receipt0 = Receipt {
            actual_fee: None,
            events: vec![],
            execution_resources: Some(ExecutionResources {
                builtin_instance_counter: BuiltinInstanceCounter::Empty(
                    EmptyBuiltinInstanceCounter {},
                ),
                n_memory_holes: 0,
                n_steps: 0,
            }),
            l1_to_l2_consumed_message: None,
            l2_to_l1_messages: vec![],
            transaction_hash: txn0_hash,
            transaction_index: StarknetTransactionIndex::new_or_panic(0),
        };
        let txn1_hash = StarknetTransactionHash(felt_bytes!(b"txn 1"));
        let txn2_hash = StarknetTransactionHash(felt_bytes!(b"txn 2"));
        let txn3_hash = StarknetTransactionHash(felt_bytes!(b"txn 3"));
        let txn4_hash = StarknetTransactionHash(felt_bytes!(b"txn 4 "));
        let txn5_hash = StarknetTransactionHash(felt_bytes!(b"txn 5"));
        let mut txn1 = txn0.clone();
        let mut txn2 = txn0.clone();
        let mut txn3 = txn0.clone();
        let mut txn4 = txn0.clone();
        txn1.transaction_hash = txn1_hash;
        txn1.sender_address = contract1_addr;
        txn2.transaction_hash = txn2_hash;
        txn2.sender_address = contract1_addr;
        txn3.transaction_hash = txn3_hash;
        txn3.sender_address = contract1_addr;
        txn4.transaction_hash = txn4_hash;

        txn4.sender_address = ContractAddress::new_or_panic(Felt::ZERO);
        let mut txn5 = txn4.clone();
        txn5.transaction_hash = txn5_hash;
        let txn0 = Transaction::Invoke(txn0.into());
        let txn1 = Transaction::Invoke(txn1.into());
        let txn2 = Transaction::Invoke(txn2.into());
        let txn3 = Transaction::Invoke(txn3.into());
        let txn4 = Transaction::Invoke(txn4.into());
        let txn5 = Transaction::Invoke(txn5.into());
        let mut receipt1 = receipt0.clone();
        let mut receipt2 = receipt0.clone();
        let mut receipt3 = receipt0.clone();
        let mut receipt4 = receipt0.clone();
        let mut receipt5 = receipt0.clone();
        receipt0.events = vec![Event {
            data: vec![EventData(felt_bytes!(b"event 0 data"))],
            from_address: ContractAddress::new_or_panic(felt_bytes!(b"event 0 from addr")),
            keys: vec![EventKey(felt_bytes!(b"event 0 key"))],
        }];
        receipt1.transaction_hash = txn1_hash;
        receipt2.transaction_hash = txn2_hash;
        receipt3.transaction_hash = txn3_hash;
        receipt4.transaction_hash = txn4_hash;
        receipt5.transaction_hash = txn5_hash;
        let transaction_data0 = [(txn0, receipt0)];
        let transaction_data1 = [(txn1, receipt1), (txn2, receipt2)];
        let transaction_data2 = [(txn3, receipt3), (txn4, receipt4), (txn5, receipt5)];
        StarknetTransactionsTable::upsert(&db_txn, block0.hash, block0.number, &transaction_data0)
            .unwrap();
        StarknetTransactionsTable::upsert(&db_txn, block1.hash, block1.number, &transaction_data1)
            .unwrap();
        StarknetTransactionsTable::upsert(&db_txn, block2.hash, block2.number, &transaction_data2)
            .unwrap();

        db_txn.commit().unwrap();
        storage
    }

    /// Creates [PendingData] which correctly links to the provided [Storage].
    ///
    /// i.e. the pending block's parent hash will be the latest block's hash from storage,
    /// and similarly for the pending state diffs state root.
    pub async fn create_pending_data(storage: Storage) -> PendingData {
        use pathfinder_common::StorageValue;

        let storage2 = storage.clone();
        let latest = tokio::task::spawn_blocking(move || {
            let mut db = storage2.connection().unwrap();
            let tx = db.transaction().unwrap();

            StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
                .unwrap()
                .expect("Storage should contain a latest block")
        })
        .await
        .unwrap();

        let transactions: Vec<Transaction> = vec![
            InvokeTransaction::V0(InvokeTransactionV0 {
                calldata: vec![],
                sender_address: ContractAddress::new_or_panic(felt_bytes!(
                    b"pending contract addr 0"
                )),
                entry_point_selector: EntryPoint(felt_bytes!(b"entry point 0")),
                entry_point_type: Some(EntryPointType::External),
                max_fee: crate::v02::types::request::Call::DEFAULT_MAX_FEE,
                signature: vec![],
                transaction_hash: StarknetTransactionHash(felt_bytes!(b"pending tx hash 0")),
            })
            .into(),
            DeployTransaction {
                contract_address: ContractAddress::new_or_panic(felt!("0x1122355")),
                contract_address_salt: ContractAddressSalt(felt_bytes!(b"salty")),
                class_hash: ClassHash(felt_bytes!(b"pending class hash 1")),
                constructor_calldata: vec![],
                transaction_hash: StarknetTransactionHash(felt_bytes!(b"pending tx hash 1")),
                version: TransactionVersion(H256::zero()),
            }
            .into(),
        ];

        let transaction_receipts = vec![
            Receipt {
                actual_fee: None,
                events: vec![
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(felt!("0xabcddddddd")),
                        keys: vec![EventKey(felt_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(felt!("0xabcddddddd")),
                        keys: vec![EventKey(felt_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(felt!("0xabcaaaaaaa")),
                        keys: vec![EventKey(felt_bytes!(b"pending key 2"))],
                    },
                ],
                execution_resources: Some(ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter::Empty(
                        EmptyBuiltinInstanceCounter {},
                    ),
                    n_memory_holes: 0,
                    n_steps: 0,
                }),
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: vec![],
                transaction_hash: transactions[0].hash(),
                transaction_index: StarknetTransactionIndex::new_or_panic(0),
            },
            Receipt {
                actual_fee: None,
                events: vec![],
                execution_resources: Some(ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter::Empty(
                        EmptyBuiltinInstanceCounter {},
                    ),
                    n_memory_holes: 0,
                    n_steps: 0,
                }),
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: vec![],
                transaction_hash: transactions[1].hash(),
                transaction_index: StarknetTransactionIndex::new_or_panic(1),
            },
        ];

        let block = starknet_gateway_types::reply::PendingBlock {
            gas_price: GasPrice::from_be_slice(b"gas price").unwrap(),
            parent_hash: latest.hash,
            sequencer_address: SequencerAddress(felt_bytes!(b"pending sequencer address")),
            status: starknet_gateway_types::reply::Status::Pending,
            timestamp: StarknetBlockTimestamp::new_or_panic(1234567),
            transaction_receipts,
            transactions,
            starknet_version: Some("pending version".to_owned()),
        };

        use starknet_gateway_types::reply as seq_reply;
        let deployed_contracts = vec![
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(felt_bytes!(b"pending contract 0 address")),
                class_hash: ClassHash(felt_bytes!(b"pending class 0 hash")),
            },
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(felt_bytes!(b"pending contract 1 address")),
                class_hash: ClassHash(felt_bytes!(b"pending class 1 hash")),
            },
        ];
        let storage_diffs = [(
            deployed_contracts[1].address,
            vec![
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(felt_bytes!(b"pending storage key 0")),
                    value: StorageValue(felt_bytes!(b"pending storage value 0")),
                },
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(felt_bytes!(b"pending storage key 1")),
                    value: StorageValue(felt_bytes!(b"pending storage value 1")),
                },
            ],
        )]
        .into_iter()
        .collect();
        let replaced_classes = vec![ReplacedClass {
            address: ContractAddress::new_or_panic(felt_bytes!(b"pending contract 2 (replaced)")),
            class_hash: ClassHash(felt_bytes!(b"pending class 2 hash (replaced)")),
        }];

        let state_diff = starknet_gateway_types::reply::state_update::StateDiff {
            storage_diffs,
            deployed_contracts,
            old_declared_contracts: Vec::new(),
            declared_classes: Vec::new(),
            nonces: std::collections::HashMap::new(),
            replaced_classes,
        };

        // The class definitions must be inserted into the database.
        let deployed_contracts = state_diff.deployed_contracts.clone();
        let deploy_storage = storage.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = deploy_storage.connection().unwrap();
            let tx = db.transaction().unwrap();
            let compressed_definition =
                starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION
                    .to_vec();
            for deployed in deployed_contracts {
                // The abi, bytecode, definition are expected to be zstd compressed, and are
                // checked for the magic bytes.
                let contract = CompressedContract {
                    definition: compressed_definition.to_vec(),
                    hash: deployed.class_hash,
                };
                ContractCodeTable::insert_compressed(&tx, &contract).unwrap();
            }
            tx.commit().unwrap();
        })
        .await
        .unwrap();

        let state_update = starknet_gateway_types::reply::PendingStateUpdate {
            old_root: latest.root,
            state_diff,
        };

        let pending_data = PendingData::default();
        pending_data
            .set(Arc::new(block), Arc::new(state_update))
            .await;
        pending_data
    }

    #[test]
    fn roundtrip_syncing() {
        use crate::v02::types::syncing::{NumberedBlock, Status, Syncing};

        let examples = [
            (line!(), "false", Syncing::False(false)),
            // this shouldn't exist but it exists now
            (line!(), "true", Syncing::False(true)),
            (
                line!(),
                r#"{"starting_block_hash":"0xa","starting_block_num":"0x1","current_block_hash":"0xb","current_block_num":"0x2","highest_block_hash":"0xc","highest_block_num":"0x3"}"#,
                Syncing::Status(Status {
                    starting: NumberedBlock::from(("a", 1)),
                    current: NumberedBlock::from(("b", 2)),
                    highest: NumberedBlock::from(("c", 3)),
                }),
            ),
        ];

        for (line, input, expected) in examples {
            let parsed = serde_json::from_str::<Syncing>(input).unwrap();
            let output = serde_json::to_string(&parsed).unwrap();

            assert_eq!(parsed, expected, "example from line {line}");
            assert_eq!(&output, input, "example from line {line}");
        }
    }
}
