//! StarkNet node JSON-RPC related modules.
mod error;
pub mod gas_price;
pub mod serde;
#[cfg(test)]
pub mod test_client;
#[cfg(test)]
pub mod test_setup;
pub mod v01;
pub mod v02;

use crate::monitoring::metrics::middleware::{MaybeRpcMetricsMiddleware, RpcMetricsMiddleware};
use jsonrpsee::{
    core::server::rpc_module::Methods,
    server::{RpcModule, ServerBuilder, ServerHandle},
};

use std::{net::SocketAddr, result::Result};
use v01::api::RpcApi;

pub struct RpcServer {
    addr: SocketAddr,
    api: RpcApi,
    middleware: MaybeRpcMetricsMiddleware,
}

impl RpcServer {
    pub fn new(addr: SocketAddr, api: RpcApi) -> Self {
        Self {
            addr,
            api,
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
    pub async fn run(self) -> Result<(ServerHandle, SocketAddr), anyhow::Error> {
        let server = ServerBuilder::default()
            .set_logger(self.middleware)
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

        let context_v02 = (&self.api).into();

        let mut module_v01 = v01::RpcModuleWrapper::new(RpcModule::new(self.api));
        v01::register_all_methods(&mut module_v01)?;
        let module_v01: Methods = module_v01.into_inner().into();

        let mut _module_v02 = RpcModule::new(context_v02);
        v02::register_all_methods(&mut _module_v02)?;
        let _module_v02: Methods = _module_v02.into();

        // FIXME
        // Ok(server
        //     .start_with_paths([
        //         (vec!["/", "/rpc/v0.1"], module_v01),
        //         (vec!["/rpc/v0.2"], module_v02),
        //     ])
        //     .map(|handle| (handle, local_addr))?)

        Ok(server
            .start(module_v01)
            .map(|handle| (handle, local_addr))?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        core::{
            ClassHash, ContractAddress, ContractAddressSalt, EntryPoint, EventData, EventKey,
            GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
            StarknetBlockTimestamp, StarknetTransactionHash, StarknetTransactionIndex,
            StorageAddress, TransactionVersion,
        },
        rpc::RpcServer,
        sequencer::reply::{
            state_update::StorageDiff,
            transaction::{
                execution_resources::{BuiltinInstanceCounter, EmptyBuiltinInstanceCounter},
                EntryPointType, Event, ExecutionResources, InvokeTransaction, InvokeTransactionV0,
                Receipt,
            },
        },
        starkhash, starkhash_bytes,
        state::{state_tree::GlobalStateTree, PendingData},
        storage::{
            CanonicalBlocksTable, ContractCodeTable, ContractsTable, StarknetBlock,
            StarknetBlocksTable, StarknetTransactionsTable, Storage,
        },
    };

    use jsonrpsee::server::ServerHandle;
    use stark_hash::StarkHash;
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };
    use web3::types::H256;

    /// Starts the HTTP-RPC server.
    pub async fn run_server(
        addr: SocketAddr,
        api: super::v01::api::RpcApi,
    ) -> Result<(ServerHandle, SocketAddr), anyhow::Error> {
        RpcServer::new(addr, api).run().await
    }

    lazy_static::lazy_static! {
        pub static ref LOCALHOST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    }

    // Local test helper
    pub fn setup_storage() -> Storage {
        use crate::sequencer::reply::transaction::Transaction;
        use crate::{
            core::{ContractNonce, StorageValue},
            state::{update_contract_state, CompressedContract},
        };
        use web3::types::H128;

        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let db_txn = connection.transaction().unwrap();

        let contract0_addr = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 0"));
        let contract1_addr = ContractAddress::new_or_panic(starkhash_bytes!(b"contract 1"));

        let class0_hash = ClassHash(starkhash_bytes!(b"class 0 hash"));
        let class1_hash = ClassHash(starkhash_bytes!(b"class 1 hash"));

        let contract0_update = vec![];

        let storage_addr = StorageAddress::new_or_panic(starkhash_bytes!(b"storage addr 0"));
        let contract1_update0 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 0")),
        }];
        let contract1_update1 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 1")),
        }];
        let contract1_update2 = vec![StorageDiff {
            key: storage_addr,
            value: StorageValue(starkhash_bytes!(b"storage value 2")),
        }];

        // We need to set the magic bytes for zstd compression to simulate a compressed
        // contract definition, as this is asserted for internally
        let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
        let contract_definition =
            include_bytes!("../fixtures/contract_definition.json.zst").to_vec();
        let contract0_code = CompressedContract {
            abi: zstd_magic.clone(),
            bytecode: zstd_magic,
            definition: contract_definition,
            hash: class0_hash,
        };
        let mut contract1_code = contract0_code.clone();
        contract1_code.hash = class1_hash;

        ContractCodeTable::insert_compressed(&db_txn, &contract0_code).unwrap();
        ContractCodeTable::insert_compressed(&db_txn, &contract1_code).unwrap();

        ContractsTable::upsert(&db_txn, contract0_addr, class0_hash).unwrap();
        ContractsTable::upsert(&db_txn, contract1_addr, class1_hash).unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, GlobalRoot(StarkHash::ZERO)).unwrap();
        let contract_state_hash = update_contract_state(
            contract0_addr,
            &contract0_update,
            Some(ContractNonce(starkhash!("01"))),
            &global_tree,
            &db_txn,
        )
        .unwrap();
        global_tree
            .set(contract0_addr, contract_state_hash)
            .unwrap();
        let global_root0 = global_tree.apply().unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, global_root0).unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update0,
            None,
            &global_tree,
            &db_txn,
        )
        .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update1,
            None,
            &global_tree,
            &db_txn,
        )
        .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let global_root1 = global_tree.apply().unwrap();

        let mut global_tree = GlobalStateTree::load(&db_txn, global_root1).unwrap();
        let contract_state_hash = update_contract_state(
            contract1_addr,
            &contract1_update2,
            Some(ContractNonce(starkhash!("10"))),
            &global_tree,
            &db_txn,
        )
        .unwrap();
        global_tree
            .set(contract1_addr, contract_state_hash)
            .unwrap();
        let global_root2 = global_tree.apply().unwrap();

        let genesis_hash = StarknetBlockHash(starkhash_bytes!(b"genesis"));
        let block0 = StarknetBlock {
            number: StarknetBlockNumber::GENESIS,
            hash: genesis_hash,
            root: global_root0,
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(StarkHash::ZERO),
        };
        let block1_hash = StarknetBlockHash(starkhash_bytes!(b"block 1"));
        let block1 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(1),
            hash: block1_hash,
            root: global_root1,
            timestamp: StarknetBlockTimestamp::new_or_panic(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(starkhash_bytes!(&[1u8])),
        };
        let latest_hash = StarknetBlockHash(starkhash_bytes!(b"latest"));
        let block2 = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(2),
            hash: latest_hash,
            root: global_root2,
            timestamp: StarknetBlockTimestamp::new_or_panic(2),
            gas_price: GasPrice::from(2),
            sequencer_address: SequencerAddress(starkhash_bytes!(&[2u8])),
        };
        StarknetBlocksTable::insert(&db_txn, &block0, None).unwrap();
        StarknetBlocksTable::insert(&db_txn, &block1, None).unwrap();
        StarknetBlocksTable::insert(&db_txn, &block2, None).unwrap();

        CanonicalBlocksTable::insert(&db_txn, block0.number, block0.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block1.number, block1.hash).unwrap();
        CanonicalBlocksTable::insert(&db_txn, block2.number, block2.hash).unwrap();

        ContractCodeTable::update_declared_on_if_null(&db_txn, class0_hash, block1.hash).unwrap();

        let txn0_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 0"));
        // TODO introduce other types of transactions too
        let txn0 = InvokeTransactionV0 {
            calldata: vec![],
            contract_address: contract0_addr,
            entry_point_type: Some(EntryPointType::External),
            entry_point_selector: EntryPoint(StarkHash::ZERO),
            max_fee: crate::core::Fee(H128::zero()),
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
        let txn1_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 1"));
        let txn2_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 2"));
        let txn3_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 3"));
        let txn4_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 4 "));
        let txn5_hash = StarknetTransactionHash(starkhash_bytes!(b"txn 5"));
        let mut txn1 = txn0.clone();
        let mut txn2 = txn0.clone();
        let mut txn3 = txn0.clone();
        let mut txn4 = txn0.clone();
        txn1.transaction_hash = txn1_hash;
        txn1.contract_address = contract1_addr;
        txn2.transaction_hash = txn2_hash;
        txn2.contract_address = contract1_addr;
        txn3.transaction_hash = txn3_hash;
        txn3.contract_address = contract1_addr;
        txn4.transaction_hash = txn4_hash;

        txn4.contract_address = ContractAddress::new_or_panic(StarkHash::ZERO);
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
            data: vec![EventData(starkhash_bytes!(b"event 0 data"))],
            from_address: ContractAddress::new_or_panic(starkhash_bytes!(b"event 0 from addr")),
            keys: vec![EventKey(starkhash_bytes!(b"event 0 key"))],
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
        use crate::core::StorageValue;
        use crate::sequencer::reply::transaction::DeployTransaction;
        use crate::sequencer::reply::transaction::Transaction;

        let storage2 = storage.clone();
        let latest = tokio::task::spawn_blocking(move || {
            let mut db = storage2.connection().unwrap();
            let tx = db.transaction().unwrap();

            use crate::storage::StarknetBlocksBlockId;
            StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
                .unwrap()
                .expect("Storage should contain a latest block")
        })
        .await
        .unwrap();

        let transactions: Vec<Transaction> = vec![
            InvokeTransaction::V0(InvokeTransactionV0 {
                calldata: vec![],
                contract_address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract addr 0"
                )),
                entry_point_selector: EntryPoint(starkhash_bytes!(b"entry point 0")),
                entry_point_type: Some(EntryPointType::External),
                max_fee: crate::rpc::v01::types::request::Call::DEFAULT_MAX_FEE,
                signature: vec![],
                transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 0")),
            })
            .into(),
            DeployTransaction {
                contract_address: ContractAddress::new_or_panic(starkhash!("01122355")),
                contract_address_salt: ContractAddressSalt(starkhash_bytes!(b"salty")),
                class_hash: ClassHash(starkhash_bytes!(b"pending class hash 1")),
                constructor_calldata: vec![],
                transaction_hash: StarknetTransactionHash(starkhash_bytes!(b"pending tx hash 1")),
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
                        from_address: ContractAddress::new_or_panic(starkhash!("abcddddddd")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(starkhash!("abcddddddd")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key"))],
                    },
                    Event {
                        data: vec![],
                        from_address: ContractAddress::new_or_panic(starkhash!("abcaaaaaaa")),
                        keys: vec![EventKey(starkhash_bytes!(b"pending key 2"))],
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

        let block = crate::sequencer::reply::PendingBlock {
            gas_price: GasPrice::from_be_slice(b"gas price").unwrap(),
            parent_hash: latest.hash,
            sequencer_address: SequencerAddress(starkhash_bytes!(b"pending sequencer address")),
            status: crate::sequencer::reply::Status::Pending,
            timestamp: StarknetBlockTimestamp::new_or_panic(1234567),
            transaction_receipts,
            transactions,
            starknet_version: Some("pending version".to_owned()),
        };

        use crate::sequencer::reply as seq_reply;
        let deployed_contracts = vec![
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract 0 address"
                )),
                class_hash: ClassHash(starkhash_bytes!(b"pending contract 0 hash")),
            },
            seq_reply::state_update::DeployedContract {
                address: ContractAddress::new_or_panic(starkhash_bytes!(
                    b"pending contract 1 address"
                )),
                class_hash: ClassHash(starkhash_bytes!(b"pending contract 1 hash")),
            },
        ];
        let storage_diffs = [(
            deployed_contracts[1].address,
            vec![
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 0")),
                    value: StorageValue(starkhash_bytes!(b"pending storage value 0")),
                },
                seq_reply::state_update::StorageDiff {
                    key: StorageAddress::new_or_panic(starkhash_bytes!(b"pending storage key 1")),
                    value: StorageValue(starkhash_bytes!(b"pending storage value 1")),
                },
            ],
        )]
        .into_iter()
        .collect();

        let state_diff = crate::sequencer::reply::state_update::StateDiff {
            storage_diffs,
            deployed_contracts,
            declared_contracts: Vec::new(),
            nonces: std::collections::HashMap::new(),
        };

        // The class definitions must be inserted into the database.
        let deployed_contracts = state_diff.deployed_contracts.clone();
        let deploy_storage = storage.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = deploy_storage.connection().unwrap();
            let tx = db.transaction().unwrap();
            let compressed_definition = include_bytes!("../fixtures/contract_definition.json.zst");
            for deployed in deployed_contracts {
                // The abi, bytecode, definition are expected to be zstd compressed, and are
                // checked for the magic bytes.
                let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
                let contract = crate::state::CompressedContract {
                    abi: zstd_magic.clone(),
                    bytecode: zstd_magic.clone(),
                    definition: compressed_definition.to_vec(),
                    hash: deployed.class_hash,
                };
                ContractCodeTable::insert_compressed(&tx, &contract).unwrap();
            }
            tx.commit().unwrap();
        })
        .await
        .unwrap();

        // Use a roll-back transaction to calculate pending state root.
        // This must not be committed as we don't want to inject the diff
        // into storage, but do require database IO to determine the root.
        //
        // Load from latest block in storage's root.
        let state_diff2 = state_diff.clone();
        let pending_root = tokio::task::spawn_blocking(move || {
            let mut db = storage.connection().unwrap();
            let tmp_tx = db.transaction().unwrap();
            let mut global_tree = GlobalStateTree::load(&tmp_tx, latest.root).unwrap();
            for deployed in state_diff2.deployed_contracts {
                ContractsTable::upsert(&tmp_tx, deployed.address, deployed.class_hash).unwrap();
            }
            for (contract_address, storage_diffs) in state_diff2.storage_diffs {
                use crate::state::update_contract_state;
                let state_hash = update_contract_state(
                    contract_address,
                    &storage_diffs,
                    None,
                    &global_tree,
                    &tmp_tx,
                )
                .unwrap();
                global_tree.set(contract_address, state_hash).unwrap();
            }
            let pending_root = global_tree.apply().unwrap();
            tmp_tx.rollback().unwrap();
            pending_root
        })
        .await
        .unwrap();

        let state_update = crate::sequencer::reply::StateUpdate {
            // This must be `None` for a pending state update.
            block_hash: None,
            new_root: pending_root,
            old_root: latest.root,
            state_diff,
        };

        let pending_data = PendingData::default();
        pending_data
            .set(Arc::new(block), Arc::new(state_update))
            .await;
        pending_data
    }
}
